import streamlit as st
import graphviz
import os
import time
import google.generativeai as genai
import json
import re
import pandas as pd
from google.api_core import exceptions as google_exceptions

# モジュール群のインポート
from logic import CausalInferenceEngine, Alarm, simulate_cascade_failure

# Multi-tenant registry
from registry import (
    list_tenants,
    list_networks,
    get_paths,
    load_topology,
    topology_mtime,
)
from network_ops import run_diagnostic_simulation, generate_remediation_commands, predict_initial_symptoms, generate_fake_log_by_ai
from verifier import verify_log_content, format_verification_report
from inference_engine import LogicalRCA

# 🆕 アラーム生成ロジック（app.pyから抽出）
try:
    from alarm_generator import generate_alarms_for_scenario
    ALARM_GENERATOR_AVAILABLE = True
except ImportError:
    ALARM_GENERATOR_AVAILABLE = False
    print("⚠️ alarm_generator.py not found, using legacy alarm generation logic")

# --- ページ設定 ---
st.set_page_config(page_title="AIOps Incident Cockpit", page_icon="⚡", layout="wide")

# =====================================================
# 影響度定義（統一基準）
# =====================================================

class ImpactLevel:
    """
    影響度の統一定義（5段階）
    
    Level 1 (100%): サービス完全停止 - 全サービスが利用不可
    Level 2 (90%):  クリティカル - 単一障害だが影響甚大
    Level 3 (70-80%): サービス継続（要注意） - 冗長性喪失、サイレント障害疑い
    Level 4 (40-60%): 下流影響 - 上流障害の症状
    Level 5 (10-30%): 低優先度 - 監視継続
    """
    COMPLETE_OUTAGE = 100  # サービス完全停止
    CRITICAL = 90          # クリティカル単一障害
    DEGRADED_HIGH = 80     # 冗長性喪失（高）
    DEGRADED_MID = 70      # 冗長性喪失（中）
    DOWNSTREAM = 50        # 下流影響
    LOW_PRIORITY = 20      # 低優先度

# シナリオごとの影響度マッピング
SCENARIO_IMPACT_MAP = {
    # === Level 1: サービス完全停止 (100%) ===
    "WAN全回線断": ImpactLevel.COMPLETE_OUTAGE,
    "[WAN] 電源障害：両系": ImpactLevel.COMPLETE_OUTAGE,
    "[L2SW] 電源障害：両系": ImpactLevel.COMPLETE_OUTAGE,
    
    # === Level 2: クリティカル (90%) ===
    "[Core] 両系故障": ImpactLevel.CRITICAL,
    
    # === Level 3: サービス継続（要注意） (70-80%) ===
    # 冗長性が効いているが要注意
    "[FW] 電源障害：両系": ImpactLevel.DEGRADED_MID,  # HA片系故障→サービス継続
    "[FW] 電源障害：片系": ImpactLevel.DEGRADED_MID,
    "FW片系障害": ImpactLevel.DEGRADED_MID,
    "[WAN] 電源障害：片系": ImpactLevel.DEGRADED_MID,
    "[L2SW] 電源障害：片系": ImpactLevel.DEGRADED_MID,
    "L2SWサイレント障害": ImpactLevel.DEGRADED_HIGH,
    "[WAN] BGPルートフラッピング": ImpactLevel.DEGRADED_HIGH,
    
    # FAN・メモリは警告レベル
    "[WAN] FAN故障": ImpactLevel.DEGRADED_MID,
    "[FW] FAN故障": ImpactLevel.DEGRADED_MID,
    "[L2SW] FAN故障": ImpactLevel.DEGRADED_MID,
    "[WAN] メモリリーク": ImpactLevel.DEGRADED_MID,
    "[FW] メモリリーク": ImpactLevel.DEGRADED_MID,
    "[L2SW] メモリリーク": ImpactLevel.DEGRADED_MID,
    
    # 複合障害
    "[WAN] 複合障害：電源＆FAN": ImpactLevel.DEGRADED_HIGH,
    "[Complex] 同時多発：FW & AP": ImpactLevel.DEGRADED_HIGH,
    
    # === Level 4: 下流影響 (40-60%) ===
    # （動的に判定）
    
    # === Level 5: 低優先度 (10-30%) ===
    "正常稼働": 0,
}

def _get_scenario_impact_level(selected_scenario: str) -> int:
    """
    シナリオから影響度レベルを取得（0-100）
    
    Returns:
        影響度（0-100）。未定義の場合は70（デフォルト）
    """
    # 完全一致を優先
    if selected_scenario in SCENARIO_IMPACT_MAP:
        return SCENARIO_IMPACT_MAP[selected_scenario]
    
    # 部分一致チェック
    for key, value in SCENARIO_IMPACT_MAP.items():
        if key in selected_scenario:
            return value
    
    # デフォルト（中程度の影響度）
    return ImpactLevel.DEGRADED_MID

# =====================================================
# Multi-tenant helpers (All Companies View)
# =====================================================
def display_company(tenant_id: str) -> str:
    """表示名（A -> A社）"""
    if tenant_id.endswith("社"):
        return tenant_id
    return f"{tenant_id}社"

def _node_type(node) -> str:
    try:
        return str(getattr(node, "type", "UNKNOWN"))
    except Exception:
        return "UNKNOWN"

def _node_layer(node) -> int:
    try:
        return int(getattr(node, "layer", 999))
    except Exception:
        return 999

def _find_target_node_id(topology: dict, node_type: str | None = None, layer: int | None = None, keyword: str | None = None) -> str | None:
    """トポロジから対象ノードIDを1つ選ぶ"""
    for node_id, node in topology.items():
        if node_type and _node_type(node) != node_type:
            continue
        if layer is not None and _node_layer(node) != layer:
            continue
        if keyword and keyword not in str(node_id):
            continue
        return node_id
    return None

def _make_alarms(topology: dict, selected_scenario: str):
    """
    シナリオ文字列とトポロジ機器をマッチさせてアラームを生成
    
    🆕 改修ポイント：
    alarm_generator.py が利用可能なら委譲、なければレガシーロジック
    """
    # alarm_generator.py が利用可能なら委譲
    if ALARM_GENERATOR_AVAILABLE:
        return generate_alarms_for_scenario(topology, selected_scenario)
    
    # フォールバック: レガシーロジック
    return _make_alarms_legacy(topology, selected_scenario)


def _make_alarms_legacy(topology: dict, selected_scenario: str):
    """レガシーアラーム生成ロジック（後方互換性）"""
    alarms = []
    
    # 正常稼働・スキップ系
    if "---" in selected_scenario or "正常" in selected_scenario:
        return []
    
    # Live実機診断
    if "Live" in selected_scenario or "[Live]" in selected_scenario:
        return []
    
    # 1. WAN全回線断
    if "WAN全回線断" in selected_scenario:
        target = find_target_node_id(topology, node_type="ROUTER")
        if target:
            return simulate_cascade_failure(target, topology)
        return []
    
    # 2. FW片系障害
    if "FW片系障害" in selected_scenario:
        target = find_target_node_id(topology, node_type="FIREWALL")
        if target:
            return [Alarm(target, "Heartbeat Loss", "WARNING")]
        return []
    
    # 3. L2SWサイレント障害
    if "L2SWサイレント障害" in selected_scenario:
        target = find_target_node_id(topology, node_type="SWITCH", layer=4, keyword="L2")
        if not target:
            target = find_target_node_id(topology, keyword="L2_SW")
        if not target:
            target = find_target_node_id(topology, node_type="SWITCH")
        
        if target and target in topology:
            # 直下の子ノードを探す
            children = [
                nid for nid, n in topology.items()
                if getattr(n, "parent_id", None) == target or 
                   (isinstance(n, dict) and n.get("parent_id") == target)
            ]
            
            # 子が見つからない場合はAPを探す
            if not children:
                children = [
                    nid for nid, n in topology.items()
                    if (_node_type(n).upper() in ("ACCESS_POINT", "AP"))
                ]
            
            if children:
                return [Alarm(child, "Connection Lost", "CRITICAL") for child in children[:4]]
            
            return [Alarm(target, "Silent Degradation Suspected", "WARNING")]
        
        return []
    
    # 17. 複合障害
    if "複合障害" in selected_scenario:
        target = find_target_node_id(topology, node_type="ROUTER")
        if target:
            return [
                Alarm(target, "Power Supply 1 Failed", "CRITICAL"),
                Alarm(target, "Fan Fail", "WARNING")
            ]
        return []
    
    # 18. 同時多発
    if "同時多発" in selected_scenario:
        fw = find_target_node_id(topology, node_type="FIREWALL")
        ap = find_target_node_id(topology, node_type="ACCESS_POINT")
        if fw:
            alarms.append(Alarm(fw, "Heartbeat Loss", "WARNING"))
        if ap:
            alarms.append(Alarm(ap, "Connection Lost", "CRITICAL"))
        return alarms
    
    # デバイスタイプを判定
    target_device_id = None
    
    if "[WAN]" in selected_scenario:
        target_device_id = find_target_node_id(topology, node_type="ROUTER")
    elif "[FW]" in selected_scenario:
        target_device_id = find_target_node_id(topology, node_type="FIREWALL")
    elif "[L2SW]" in selected_scenario:
        target_device_id = find_target_node_id(topology, node_type="SWITCH", layer=4)
    
    if not target_device_id:
        return []
    
    # 電源障害：片系
    if "電源障害：片系" in selected_scenario:
        return [Alarm(target_device_id, "Power Supply 1 Failed", "WARNING")]
    
    # 電源障害：両系
    if "電源障害：両系" in selected_scenario:
        if "FW" in str(target_device_id):
            # FWはHA構成：Primary側が両系電源喪失でダウン → Secondaryが引き継ぎ
            # サービスは継続するが冗長性喪失（WARNING）
            return [Alarm(target_device_id, "HA Failover: Primary Down (PSU Dual Loss)", "WARNING")]
        # FW以外は両系電源喪失でカスケード障害
        return simulate_cascade_failure(target_device_id, topology, "Power Supply: Dual Loss (Device Down)")
    
    # BGPルートフラッピング
    if "BGP" in selected_scenario:
        return [Alarm(target_device_id, "BGP Flapping", "WARNING")]
    
    # FAN故障
    if "FAN" in selected_scenario:
        return [Alarm(target_device_id, "Fan Fail", "WARNING")]
    
    # メモリリーク
    if "メモリ" in selected_scenario:
        return [Alarm(target_device_id, "Memory High", "WARNING")]
    
    return []

def _status_from_alarms(selected_scenario: str, alarms) -> str:
    """
    全社一覧の状態（停止/要対応/注意/正常）を判定する
    
    【改善】影響度マッピングを使用して正確に判定
    """
    if not alarms:
        return "正常"
    
    # シナリオベースの影響度を取得
    impact_level = _get_scenario_impact_level(selected_scenario)
    
    # 影響度に基づいて状態を判定
    if impact_level >= ImpactLevel.COMPLETE_OUTAGE:
        return "停止"
    elif impact_level >= ImpactLevel.CRITICAL:
        return "要対応"
    elif impact_level >= ImpactLevel.DEGRADED_MID:
        # 冗長性喪失は「要対応」または「注意」
        # CRITICALメッセージがあれば「要対応」
        severities = [str(getattr(a, "severity", "")).upper() for a in alarms]
        if any(s == "CRITICAL" for s in severities):
            return "要対応"
        return "注意"
    elif impact_level >= ImpactLevel.DOWNSTREAM:
        return "注意"
    else:
        return "正常"

def _status_from_alarm_count(n: int) -> str:
    # 互換用（旧ロジック）
    if n >= 20:
        return "停止"
    if n >= 3:
        return "要対応"
    if n >= 1:
        return "注意"
    return "正常"

def _status_sort_key(status: str) -> int:
    # 左ほど優先度が高い（停止 → 要対応 → 注意 → 正常）
    order = {"停止": 0, "要対応": 1, "注意": 2, "正常": 3}
    return order.get(status, 99)

def _make_status_badge(status: str) -> str:
    icon = {"停止": "🔴", "要対応": "🟠", "注意": "🟡", "正常": "🟢"}.get(status, "⚪")
    return f"{icon} {status}"

def _get_impact_display(cand: dict, scope_status: str) -> str:
    """
    影響度を適切に表示（状態 + 数値の併記）
    サイレント障害の症状ノードは「下流影響」として区別
    """
    prob_pct = cand['prob'] * 100
    
    if scope_status == "停止":
        return 100  # プログレスバー用の数値
    
    return prob_pct

def _get_impact_label(cand: dict, scope_status: str) -> str:
    """
    影響度のラベル（アイコン + 状態）を返す
    
    新しい影響度定義に準拠：
    - 100%: サービス停止
    - 90%: CRITICAL
    - 70-80%: WARNING
    - 40-60%: 下流影響
    - 30%以下: 低優先度
    """
    prob = cand['prob']
    prob_pct = prob * 100
    
    if scope_status == "停止" or prob_pct >= ImpactLevel.COMPLETE_OUTAGE:
        return "🔴 サービス停止"
    
    # サイレント障害の症状ノード判定
    is_downstream_symptom = (
        "Connection Lost" in cand.get('label', '') and 
        prob < 0.6
    )
    
    if is_downstream_symptom:
        return "⚪ 下流影響"
    elif prob_pct >= ImpactLevel.CRITICAL:
        return "🔴 CRITICAL"
    elif prob_pct >= ImpactLevel.DEGRADED_MID:
        return "🟡 WARNING"
    elif prob_pct >= ImpactLevel.DOWNSTREAM:
        return "⚪ 下流影響"
    else:
        return "⚪ 低優先度"

def _safe_dataframe_select(view_df, key: str, height: int):
    """行クリック選択（対応版）"""
    try:
        st.dataframe(
            view_df,
            use_container_width=True,
            hide_index=True,
            height=height,
            selection_mode="single-row",
            on_select="rerun",
            key=key,
        )
        sel = st.session_state.get(key)
        if sel and hasattr(sel, "selection") and getattr(sel.selection, "rows", None):
            return sel.selection.rows[0]
        return None
    except TypeError:
        st.dataframe(view_df, use_container_width=True, hide_index=True, height=height)
        return None

def _collect_all_scopes():
    scopes = []
    for t in list_tenants():
        for n in list_networks(t):
            scopes.append((t, n))
    return scopes

def _build_company_rows(selected_scenario: str):
    """全社の状態を作る"""
    maint_flags = st.session_state.get("maint_flags", {}) or {}

    # 前回状態（デルタ計算用）
    prev = st.session_state.get("prev_company_snapshot", {}) or {}

    rows = []
    for tenant_id, network_id in _collect_all_scopes():
        paths = get_paths(tenant_id, network_id)
        topo = load_topology(paths.topology_path)

        alarms = _make_alarms(topo, selected_scenario)
        alarm_count = len(alarms)

        status = _status_from_alarms(selected_scenario, alarms)
        is_maint = bool(maint_flags.get(tenant_id, False))

        key = f"{tenant_id}/{network_id}"
        prev_count = prev.get(key, {}).get("alarm_count")
        delta = None if prev_count is None else (alarm_count - prev_count)

        rows.append({
            "tenant": tenant_id,
            "network": network_id,
            "company_network": f"{display_company(tenant_id)} / {network_id}",
            "status": status,
            "alarm_count": alarm_count,
            "delta": delta,
            "maintenance": is_maint,
        })

    # snapshot更新
    st.session_state.prev_company_snapshot = {
        f'{r["tenant"]}/{r["network"]}': {"alarm_count": r["alarm_count"]} for r in rows
    }

    return rows

def _render_all_companies_board(selected_scenario: str, df_height: int = 220):
    """
    UX改善版: ハイブリッド型全社ダッシュボード
    - KPIメトリクス + カスタム配色ツリーマップ
    - 説得力のあるデータグリッド型トリアージリスト
    """
    rows = _build_company_rows(selected_scenario)
    
    # 集計
    df_rows = pd.DataFrame(rows)
    count_stop = len(df_rows[df_rows['status'] == '停止'])
    count_action = len(df_rows[df_rows['status'] == '要対応'])
    count_warn = len(df_rows[df_rows['status'] == '注意'])
    count_normal = len(df_rows[df_rows['status'] == '正常'])

    st.subheader("🏢 全社状態ボード")

    # 1. KPI メトリクス (状況を数値で即座に把握)
    # -------------------------------------------------------
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("🔴 停止 (最優先)", f"{count_stop}社", delta=None, help="即時対応が必要です")
    kpi2.metric("🟠 要対応", f"{count_action}社", help="冗長性喪失など")
    kpi3.metric("🟡 注意", f"{count_warn}社", help="監視強化推奨")
    kpi4.metric("🟢 正常稼働", f"{count_normal}社")
    
    st.divider()

    # 2. 視覚的ツリーマップ (ノイズを消し、異常を目立たせる)
    # -------------------------------------------------------
    try:
        import plotly.express as px
        
        # 配色定義: 正常は目立たない色(グレー/薄緑)にし、異常を原色にする
        color_map = {
            "停止": "#DC2626",    # Vivid Red
            "要対応": "#F97316",  # Orange
            "注意": "#EAB308",    # Yellow
            "正常": "#F3F4F6"     # Very Light Grey (ノイズ低減)
        }
        
        # ツリーマップ用データ加工
        tree_data = []
        for r in rows:
            # 正常の面積を少し小さく評価して、異常を目立たせる重みづけ
            weight = r['alarm_count'] + (10 if r['status'] == '停止' else 1)
            tree_data.append({
                "Label": r["company_network"],
                "Status": r["status"],
                "Weight": weight, 
                "Alarms": r["alarm_count"],
                "Tenant": r["tenant"],
                "Network": r["network"]
            })
        
        df_tree = pd.DataFrame(tree_data)
        
        if not df_tree.empty:
            fig = px.treemap(
                df_tree,
                path=['Status', 'Label'],
                values='Weight',
                color='Status',
                color_discrete_map=color_map,
                hover_data={'Alarms': True, 'Weight': False, 'Status': False},
                custom_data=['Tenant', 'Network']
            )
            
            fig.update_layout(
                margin=dict(t=0, b=0, l=0, r=0),
                height=250,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(family="Inter, sans-serif", size=14)
            )
            # クリックイベントはStreamlitでは完全には取れないため、視覚化に徹する
            st.plotly_chart(fig, use_container_width=True)
            
    except ImportError:
        st.error("Plotly package is required for the dashboard.")

    # 3. トリアージ・グリッド (説得力のあるリスト表示)
    # -------------------------------------------------------
    st.markdown("### 🚨 自動トリアージ・リスト")

    # データフレーム構築用ヘルパー
    def make_display_df(target_rows):
        d = []
        for r in target_rows:
            # 深刻度を数値化してバー表示用にする
            severity_score = 100 if r['status'] == '停止' else (70 if r['status'] == '要対応' else 30)
            if r['status'] == '正常': severity_score = 0
            
            d.append({
                "Status": r['status'],
                "Company": r['company_network'],
                "Severity": severity_score,
                "Alarms": r['alarm_count'],
                "Update": "Just now", # 本来はtimestamp
                "Action": "詳細確認",
                "raw_tenant": r['tenant'],
                "raw_network": r['network']
            })
        return pd.DataFrame(d)

    # --- Priority High (停止・要対応) ---
    high_priority_rows = [r for r in rows if r['status'] in ['停止', '要対応']]
    
    if high_priority_rows:
        df_high = make_display_df(high_priority_rows)
        
        st.caption(f"直ちに対応が必要なシステム ({len(high_priority_rows)}件)")
        
        event = st.dataframe(
            df_high,
            column_order=["Status", "Company", "Severity", "Alarms", "Update"],
            column_config={
                "Status": st.column_config.TextColumn("状態", width="small"),
                "Company": st.column_config.TextColumn("対象システム", width="medium"),
                "Severity": st.column_config.ProgressColumn(
                    "深刻度", 
                    format="%d%%", 
                    min_value=0, 
                    max_value=100,
                    width="medium"
                ),
                "Alarms": st.column_config.NumberColumn("アラーム数", format="%d件"),
                "raw_tenant": None, # 非表示
                "raw_network": None # 非表示
            },
            use_container_width=True,
            hide_index=True,
            selection_mode="single-row",
            on_select="rerun",
            key="grid_high"
        )
        
        # 選択処理
        if len(event.selection.rows) > 0:
            selected_idx = event.selection.rows[0]
            sel_row = df_high.iloc[selected_idx]
            st.session_state.selected_scope = {
                "tenant": sel_row['raw_tenant'], 
                "network": sel_row['raw_network']
            }
            st.rerun()
    else:
        st.info("🎉 現在、緊急対応が必要なインシデントはありません。")

    # --- Watch List (注意) ---
    warn_rows = [r for r in rows if r['status'] == '注意']
    if warn_rows:
        with st.expander(f"⚠️ Watch List ({len(warn_rows)}件) - 傾向監視", expanded=False):
            df_warn = make_display_df(warn_rows)
            event_w = st.dataframe(
                df_warn,
                column_order=["Status", "Company", "Severity", "Alarms"],
                column_config={
                    "Status": st.column_config.TextColumn("状態"),
                    "Severity": st.column_config.ProgressColumn("負荷レベル", format="%d", max_value=100),
                    "raw_tenant": None, "raw_network": None
                },
                use_container_width=True,
                hide_index=True,
                selection_mode="single-row",
                on_select="rerun",
                key="grid_warn"
            )
             # 選択処理
            if len(event_w.selection.rows) > 0:
                selected_idx = event_w.selection.rows[0]
                sel_row = df_warn.iloc[selected_idx]
                st.session_state.selected_scope = {
                    "tenant": sel_row['raw_tenant'], 
                    "network": sel_row['raw_network']
                }
                st.rerun()

    # --- Normal (正常) ---
    # 正常は邪魔にならないよう極小化
    if count_normal > 0:
        with st.expander(f"✅ 正常稼働システム ({count_normal}件)", expanded=False):
            st.caption("以下のシステムは正常に稼働しています。")
            # シンプルなチップ表示
            normal_labels = [r['company_network'] for r in rows if r['status'] == '正常']
            st.write(", ".join(normal_labels))

# ==========================================
def find_target_node_id(topology, node_type=None, layer=None, keyword=None):
    """トポロジーから条件に合うノードIDを検索"""
    for node_id, node in topology.items():
        if node_type and node.type != node_type: continue
        if layer and node.layer != layer: continue
        if keyword:
            hit = False
            if keyword in node_id: hit = True
            for v in node.metadata.values():
                if isinstance(v, str) and keyword in v: hit = True
            if not hit: continue
        return node_id
    return None

def load_config_by_id(device_id):
    """configsフォルダから設定ファイルを読み込む"""
    possible_paths = [f"configs/{device_id}.txt", f"{device_id}.txt"]
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                pass
    return "Config file not found."

# --- Config sanitization & summary (pre-LLM) ---

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})(/\d{1,2})?\b")
_ENC_PW_RE = re.compile(r"(encrypted-password\s+)([\"']?)[^\"';\n]+([\"']?)", re.IGNORECASE)

def sanitize_config_text(raw_text: str) -> str:
    """Sanitize sensitive tokens BEFORE any AI prompt usage"""
    if not raw_text:
        return raw_text
    text = raw_text

    # Redact encrypted-password
    def _pw_sub(m):
        return f"{m.group(1)}\"***REDACTED***\""
    text = _ENC_PW_RE.sub(_pw_sub, text)

    # Mask IPv4 addresses (last octet)
    def _ip_sub(m):
        return f"{m.group(1)}.xxx{m.group(3) or ''}"
    text = _IPV4_RE.sub(_ip_sub, text)

    return text

def build_config_summary(sanitized_text: str) -> dict:
    """Best-effort extractor for operator-friendly summary"""
    summary = {
        "os_version": None,
        "host_name": None,
        "interfaces": [],
        "zones": [],
    }
    if not sanitized_text:
        return summary

    m = re.search(r"\bversion\s+([^;\n]+)", sanitized_text)
    if m:
        summary["os_version"] = m.group(1).strip()

    m = re.search(r"\bhost-name\s+([^;\s\n]+)", sanitized_text)
    if m:
        summary["host_name"] = m.group(1).strip()

    # Interface + address
    for im in re.finditer(r"\b(ge-\d+/\d+/\d+)\b[\s\S]{0,220}?\baddress\s+([^;\s\n]+)", sanitized_text):
        if_name = im.group(1)
        addr = im.group(2)
        summary["interfaces"].append({"name": if_name, "address": addr})

    # Zones
    for zm in re.finditer(r"security-zone\s+([^\s\{\n]+)", sanitized_text):
        z = zm.group(1).strip()
        if z not in summary["zones"]:
            summary["zones"].append(z)

    return summary

def load_config_sanitized(device_id: str) -> dict:
    """Load config and return a sanitized dict with summary + excerpt"""
    raw = load_config_by_id(device_id)
    sanitized = sanitize_config_text(raw)
    summary = build_config_summary(sanitized)

    excerpt = sanitized[:1500] if isinstance(sanitized, str) else ""
    return {
        "device_id": device_id,
        "summary": summary,
        "excerpt": excerpt,
        "available": (raw != "Config file not found."),
    }


def generate_content_with_retry(model, prompt, stream=True, retries=3):
    """503エラー対策のリトライ付き生成関数"""
    for i in range(retries):
        try:
            return model.generate_content(prompt, stream=stream)
        except google_exceptions.ServiceUnavailable:
            if i == retries - 1: raise
            time.sleep(2 * (i + 1))
    return None

def render_topology(alarms, root_cause_candidates):
    """トポロジー図の描画 (AI判定結果を反映)"""
    graph = graphviz.Digraph()
    graph.attr(rankdir='TB')
    graph.attr('node', shape='box', style='rounded,filled', fontname='Helvetica')
    
    alarm_map = {a.device_id: a for a in alarms}
    alarmed_ids = set(alarm_map.keys())
    
    root_cause_ids = {c['id'] for c in root_cause_candidates if c['prob'] > 0.6}
    
    # AI判定結果のマッピング
    node_status_map = {c['id']: c['type'] for c in root_cause_candidates}
    
    for node_id, node in TOPOLOGY.items():
        color = "#e8f5e9"
        penwidth = "1"
        fontcolor = "black"
        label = f"{node_id}\n({node.type})"
        
        red_type = node.metadata.get("redundancy_type")
        if red_type: label += f"\n[{red_type} Redundancy]"
        vendor = node.metadata.get("vendor")
        if vendor: label += f"\n[{vendor}]"

        status_type = node_status_map.get(node_id, "Normal")
        
        if "Silent" in status_type:
            color = "#fff3e0"
            penwidth = "4"
            label += "\n[サイレント疑い]"
        elif "Hardware/Physical" in status_type or "Critical" in status_type:
            color = "#ffcdd2" 
            penwidth = "3"
            label += "\n[ROOT CAUSE]"
        elif "Network/Unreachable" in status_type or "Network/Secondary" in status_type:
            color = "#cfd8dc" 
            fontcolor = "#546e7a"
            label += "\n[Unreachable]"
        elif node_id in alarmed_ids:
            color = "#fff9c4" 
        
        graph.node(node_id, label=label, fillcolor=color, color='black', penwidth=penwidth, fontcolor=fontcolor)
    
    for node_id, node in TOPOLOGY.items():
        if node.parent_id:
            graph.edge(node.parent_id, node_id)
            parent_node = TOPOLOGY.get(node.parent_id)
            if parent_node and parent_node.redundancy_group:
                partners = [n.id for n in TOPOLOGY.values() 
                           if n.redundancy_group == parent_node.redundancy_group and n.id != parent_node.id]
                for partner_id in partners:
                    graph.edge(partner_id, node_id)
    return graph

# --- UI構築 ---

api_key = None
if "GOOGLE_API_KEY" in st.secrets:
    api_key = st.secrets["GOOGLE_API_KEY"]
else:
    api_key = os.environ.get("GOOGLE_API_KEY")

# --- サイドバー ---
with st.sidebar:
    st.header("⚡ Scenario Controller")
    SCENARIO_MAP = {
        "基本・広域障害": ["正常稼働", "1. WAN全回線断", "2. FW片系障害", "3. L2SWサイレント障害"],
        "WAN Router": ["4. [WAN] 電源障害：片系", "5. [WAN] 電源障害：両系", "6. [WAN] BGPルートフラッピング", "7. [WAN] FAN故障", "8. [WAN] メモリリーク"],
        "Firewall (Juniper)": ["9. [FW] 電源障害：片系", "10. [FW] 電源障害：両系", "11. [FW] FAN故障", "12. [FW] メモリリーク"],
        "L2 Switch": ["13. [L2SW] 電源障害：片系", "14. [L2SW] 電源障害：両系", "15. [L2SW] FAN故障", "16. [L2SW] メモリリーク"],
        "複合・その他": ["17. [WAN] 複合障害：電源＆FAN", "18. [Complex] 同時多発：FW & AP", "99. [Live] Cisco実機診断"]
    }
    selected_category = st.selectbox("対象カテゴリ:", list(SCENARIO_MAP.keys()))
    selected_scenario = st.radio("発生シナリオ:", SCENARIO_MAP[selected_category])


    # Maintenance（最小版：手動フラグ）
    if 'maint_flags' not in st.session_state:
        st.session_state.maint_flags = {}
    with st.expander('🛠️ Maintenance（最小版：手動フラグ）', expanded=False):
        st.caption('将来は計画停止情報の外部連携に置換予定。いまは手動でグレーアウト対象（会社）を指定します。')
        ts = []
        try:
            ts = list_tenants()
        except Exception:
            ts = ['A','B']
        selected = st.multiselect('Maintenance 中の会社', options=ts, default=[t for t in ts if st.session_state.maint_flags.get(t, False)], format_func=display_company)
        st.session_state.maint_flags = {t: (t in selected) for t in ts}

    st.markdown("---")
    if api_key: st.success("API Connected")
    else:
        st.warning("API Key Missing")
        user_key = st.text_input("Google API Key", type="password")
        if user_key: api_key = user_key

# --- セッション管理 ---
if "current_scenario" not in st.session_state:
    st.session_state.current_scenario = "正常稼働"


# -----------------------------
# All Companies View (top)
# -----------------------------
DF_HEIGHT_5ROWS = 260
if "selected_scope" not in st.session_state:
    st.session_state.selected_scope = None

# 上段の全社状態ボード（クリックで下段切替）
_render_all_companies_board(selected_scenario, df_height=DF_HEIGHT_5ROWS)
st.markdown("---")

# 選択スコープ（状態ボードの行クリックで切替）
_scope = st.session_state.get("selected_scope")
if _scope and isinstance(_scope, dict) and _scope.get("tenant") and _scope.get("network"):
    ACTIVE_TENANT = _scope["tenant"]
    ACTIVE_NETWORK = _scope["network"]
else:
    # 初期表示（未選択）の場合は、利用可能な先頭スコープを選ぶ
    try:
        _ts = list_tenants()
        _t0 = _ts[0] if _ts else "A"
        _ns = list_networks(_t0)
        _n0 = _ns[0] if _ns else "default"
    except Exception:
        _t0, _n0 = "A", "default"
    ACTIVE_TENANT, ACTIVE_NETWORK = _t0, _n0
    st.session_state.selected_scope = {"tenant": _t0, "network": _n0}

# テナントごとのトポロジー読み込み
_paths = get_paths(ACTIVE_TENANT, ACTIVE_NETWORK)
TOPOLOGY = load_topology(_paths.topology_path)

# 変数初期化
for key in ["live_result", "messages", "chat_session", "trigger_analysis", "verification_result", "generated_report", "verification_log", "last_report_cand_id", "logic_engine"]:
    if key not in st.session_state:
        st.session_state[key] = None if key != "messages" and key != "trigger_analysis" else ([] if key == "messages" else False)

# エンジン初期化
try:
    topo_mtime = os.path.getmtime(_paths.topology_path)
except Exception:
    topo_mtime = 0.0
engine_sig = f"{ACTIVE_TENANT}/{ACTIVE_NETWORK}:{topo_mtime}"

if st.session_state.get("logic_engine_sig") != engine_sig:
    st.session_state.logic_engine = LogicalRCA(TOPOLOGY)
    st.session_state.logic_engine_sig = engine_sig

# シナリオ切り替え時のリセット
if st.session_state.current_scenario != selected_scenario:
    st.session_state.current_scenario = selected_scenario
    st.session_state.messages = []      
    st.session_state.chat_session = None 
    st.session_state.live_result = None 
    st.session_state.trigger_analysis = False
    st.session_state.verification_result = None
    st.session_state.generated_report = None
    st.session_state.verification_log = None 
    st.session_state.last_report_cand_id = None
    if "remediation_plan" in st.session_state: del st.session_state.remediation_plan
    st.rerun()

# ==========================================
# メインロジック
# ==========================================

# 1. アラーム生成ロジック（🆕 alarm_generator.pyに委譲）
alarms = _make_alarms(TOPOLOGY, selected_scenario)

target_device_id = None
root_severity = "CRITICAL"
is_live_mode = False

if "Live" in selected_scenario or "[Live]" in selected_scenario:
    is_live_mode = True

# 2. 推論エンジンによる分析
engine = st.session_state.logic_engine
engine.SILENT_MIN_CHILDREN = getattr(engine, "SILENT_MIN_CHILDREN", 2) or 2
engine.SILENT_RATIO = 0.5
if "サイレント" in selected_scenario:
    engine.SILENT_RATIO = 0.3
analysis_results = engine.analyze(alarms)

# 【重要】シナリオベースの影響度でオーバーライド
# 推論エンジンの prob 値よりもシナリオの定義を優先
scenario_impact = _get_scenario_impact_level(selected_scenario)

# 根本原因候補（最上位）にシナリオ影響度を適用
if analysis_results and scenario_impact > 0:
    # 最も prob が高い候補（根本原因）の影響度を調整
    top_candidate = analysis_results[0] if analysis_results else None
    if top_candidate and top_candidate.get('prob', 0) > 0.5:
        # シナリオ定義の影響度を100分率に変換して適用
        top_candidate['prob'] = scenario_impact / 100.0
        
        # サイレント障害の場合、影響度は固定（80%）
        if "サイレント" in selected_scenario or "Silent" in top_candidate.get('type', ''):
            top_candidate['prob'] = ImpactLevel.DEGRADED_HIGH / 100.0

scope_status = _status_from_alarms(selected_scenario, alarms)


# 3. コックピット表示
selected_incident_candidate = None

st.markdown("### 🛡️ AIOps インシデント・コックピット")
col1, col2, col3 = st.columns(3)
with col1: st.metric("📉 ノイズ削減率", "98.5%", "高効率稼働中")

# 抑制されたアラーム数を計算
total_alarms = len(alarms)
downstream_count = len([c for c in analysis_results if "Unreachable" in c.get('type', '')])
suppressed_count = total_alarms * 15 + downstream_count

with col2: st.metric("📨 抑制アラーム数", f"{suppressed_count}件", "ノイズ削減")
with col3: st.metric("🚨 要対応インシデント", f"{len([c for c in analysis_results if c['prob'] > 0.6])}件", "対処が必要")
st.markdown("---")

# アラーム分類
root_cause_candidates = []
downstream_devices = []

for cand in analysis_results:
    if "Network/Unreachable" in cand.get('type', '') or "Network/Secondary" in cand.get('type', ''):
        downstream_devices.append(cand)
    else:
        root_cause_candidates.append(cand)

# 影響範囲サマリー表示
if root_cause_candidates and downstream_devices:
    root_id = root_cause_candidates[0]['id']
    impact_count = len(downstream_devices)
    st.info(f"📍 **根本原因**: {root_id} → 影響範囲: 配下 {impact_count} 機器")

df_data = []
for rank, cand in enumerate(root_cause_candidates, 1):
    status = "⚪ 監視中"
    action = "👁️ 静観"

    is_silent = ("SilentFailure" in str(cand.get("type","")) or "Silent" in str(cand.get("type","")) or "サイレント" in str(cand.get("type","")))
    if is_silent:
        status = "🟣 サイレント疑い (上位設備)"
        action = "🔍 上位SW/配下影響を確認"
    else:
        if cand['prob'] > 0.8:
            status = "🔴 危険 (根本原因)"
            action = "🚀 自動修復が可能"
        elif cand['prob'] > 0.6:
            status = "🟡 警告 (被疑箇所)"
            action = "🔍 詳細調査を推奨"

    if "Network/Unreachable" in cand['type'] or "Network/Secondary" in cand['type']:
        status = "⚫ 応答なし (上位障害)"
        action = "⛔ 対応不要 (上位復旧待ち)"

    candidate_text = f"デバイス: {cand['id']} / 原因: {cand['label']}"
    if cand.get('verification_log'):
        candidate_text += " [🔍 Active Probe: 応答なし]"

    df_data.append({
        "順位": rank,
        "ステータス": status,
        "根本原因候補": candidate_text,
        "影響度": _get_impact_display(cand, scope_status),
        "状態": _get_impact_label(cand, scope_status),
        "推奨アクション": action,
        "ID": cand['id'],
        "Type": cand['type']
    })

df = pd.DataFrame(df_data)
st.info("💡 ヒント: インシデントの行をクリックすると、右側に詳細分析と復旧プランが表示されます。")

event = st.dataframe(
    df,
    column_order=["順位", "ステータス", "根本原因候補", "影響度", "状態", "推奨アクション"],
    column_config={
        "影響度": st.column_config.ProgressColumn(
            "影響度",
            help="サービス影響度（0-100%）",
            format="%d%%",
            min_value=0,
            max_value=100
        ),
        "状態": st.column_config.TextColumn(
            "状態",
            help="根本原因/症状/監視対象の分類",
            width="medium"
        )
    },
    use_container_width=True,
    hide_index=True,
    selection_mode="single-row",
    on_select="rerun"
)

# 下流機器の展開表示
if downstream_devices:
    with st.expander(f"▼ 影響を受けている機器 ({len(downstream_devices)}台) - 上流復旧待ち", expanded=False):
        st.caption("これらの機器は上流障害の影響を受けているため、根本原因の復旧後に自動的に回復します。")
        
        downstream_df_data = []
        for idx, d_cand in enumerate(downstream_devices, 1):
            downstream_df_data.append({
                "No": idx,
                "デバイス": d_cand['id'],
                "状態": "⚫ 応答なし",
                "影響度": "－",  # N/Aではなく「－」を使用
                "備考": "上流復旧待ち"
            })
        
        downstream_df = pd.DataFrame(downstream_df_data)
        st.dataframe(
            downstream_df,
            use_container_width=True,
            hide_index=True,
            height=min(len(downstream_devices) * 35 + 38, 300)  # 最大300px
        )

if len(event.selection.rows) > 0:
    idx = event.selection.rows[0]
    sel_row = df.iloc[idx]
    for res in root_cause_candidates:
        if res['id'] == sel_row['ID'] and res['type'] == sel_row['Type']:
            selected_incident_candidate = res
            break
else:
    selected_incident_candidate = root_cause_candidates[0] if root_cause_candidates else None


# 4. 画面分割
col_map, col_chat = st.columns([1.2, 1])

# === 左カラム: トポロジーと診断 ===
with col_map:
    st.subheader("🌐 Network Topology")
    
    current_root_node = None
    current_severity = "WARNING"
    
    if selected_incident_candidate and selected_incident_candidate["prob"] > 0.6:
        current_root_node = TOPOLOGY.get(selected_incident_candidate["id"])
        if "Hardware/Physical" in selected_incident_candidate["type"] or "Critical" in selected_incident_candidate["type"] or "Silent" in selected_incident_candidate["type"]:
            current_severity = "CRITICAL"
        else:
            current_severity = "WARNING"

    elif target_device_id:
        current_root_node = TOPOLOGY.get(target_device_id)
        current_severity = root_severity

    st.graphviz_chart(render_topology(alarms, analysis_results), use_container_width=True)

    st.markdown("---")
    st.subheader("🛠️ Auto-Diagnostics")
    
    if st.button("🚀 診断実行 (Run Diagnostics)", type="primary"):
        if not api_key:
            st.error("API Key Required")
        else:
            with st.status("Agent Operating...", expanded=True) as status:
                st.write("🔌 Connecting to device...")
                target_node_obj = TOPOLOGY.get(target_device_id) if target_device_id else None
                
                res = run_diagnostic_simulation(selected_scenario, target_node_obj, api_key)
                st.session_state.live_result = res
                
                if res["status"] == "SUCCESS":
                    st.write("✅ Log Acquired & Sanitized.")
                    status.update(label="Diagnostics Complete!", state="complete", expanded=False)
                    log_content = res.get('sanitized_log', "")
                    verification = verify_log_content(log_content)
                    st.session_state.verification_result = verification
                    st.session_state.trigger_analysis = True
                elif res["status"] == "SKIPPED":
                    status.update(label="No Action Required", state="complete")
                else:
                    st.write("❌ Connection Failed.")
                    status.update(label="Diagnostics Failed", state="error")
            st.rerun()

    if st.session_state.live_result:
        res = st.session_state.live_result
        if res["status"] == "SUCCESS":
            st.markdown("#### 📄 Diagnostic Results")
            with st.container(border=True):
                if selected_incident_candidate and selected_incident_candidate.get("verification_log"):
                    st.caption("🤖 Active Probe / Verification Log")
                    st.code(selected_incident_candidate["verification_log"], language="text")
                    st.divider()

                if st.session_state.verification_result:
                    v = st.session_state.verification_result
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Ping Status", v.get('ping_status'))
                    c2.metric("Interface", v.get('interface_status'))
                    c3.metric("Hardware", v.get('hardware_status'))
                
                st.divider()
                st.caption("🔒 Raw Logs (Sanitized)")
                st.code(res["sanitized_log"], language="text")
        elif res["status"] == "ERROR":
            st.error(f"診断エラー: {res.get('error')}")

# === 右カラム: 分析レポート ===
with col_chat:
    st.subheader("📝 AI Analyst Report")
    
    if selected_incident_candidate:
        cand = selected_incident_candidate
        
        # --- A. 状況報告 (Situation Report) ---
        if "generated_report" not in st.session_state or st.session_state.generated_report is None:
            st.info(f"インシデント選択中: **{cand['id']}** ({cand['label']})")
            
            if api_key and selected_scenario != "正常稼働":
                if st.button("📝 詳細レポートを作成 (Generate Report)"):
                    
                    report_container = st.empty()
                    cfg = load_config_sanitized(cand['id'])
                    
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel("gemini-1.5-flash")
                    
                    verification_context = cand.get("verification_log", "特になし")
                    
                    prompt = f"""
                    あなたはネットワーク運用監視のプロフェッショナルです。
                    以下の障害インシデントについて、顧客向けの「詳細な状況報告レポート」を作成してください。
                    
                    【入力情報】
                    - 発生シナリオ: {selected_scenario}
                    - 根本原因候補: {cand['id']} ({cand['label']})
                    - 影響度スコア: {_get_impact_display(cand, scope_status):.0f}%
                    - 役割: {_get_impact_label(cand, scope_status)}
                    
                    【★重要: AIによる能動的診断結果 (Reasoning)】
                    システムはアラームだけでなく、以下の能動的な確認を行いました。この内容を「対応」や「特定根拠」に含めてください。
                    {verification_context}

                    - 対象機器Config（秘匿化済み・要点）:
                    OS: {cfg['summary'].get('os_version')}
                    Host: {cfg['summary'].get('host_name')}
                    Zones: {', '.join(cfg['summary'].get('zones') or [])}
                    IFs: {', '.join([f"{i['name']}={i['address']}" for i in (cfg['summary'].get('interfaces') or [])])}

                    - 対象機器Config（秘匿化済み・抜粋）:
                    {cfg['excerpt']}

                    【重要: 出力形式】
                    1. HTMLタグ(brなど)は絶対に使用しないでください。改行はMarkdownの標準的な空行（エンター2回）で行ってください。
                    2. 見出し（###）の前後には必ず空行を入れてください。
                    
                    構成:
                    ### 状況報告：{cand['id']}
                    
                    **1. 障害概要**
                    (概要記述)
                    
                    **2. 影響**
                    (影響記述)
                    
                    **3. 詳細情報**
                    (機器情報など)
                    
                    **4. 対応と特定根拠**
                    (★ここに能動的診断の結果を反映して記述)
                    
                    **5. 今後の対応**
                    (今後)
                    """
                    
                    try:
                        response = generate_content_with_retry(model, prompt, stream=True)
                        full_text = ""
                        for chunk in response:
                            if chunk.candidates[0].finish_reason == 1: 
                                pass 
                            elif chunk.candidates[0].finish_reason == 3: 
                                full_text = "⚠️ コンテンツが安全フィルターによりブロックされました。別のシナリオを試してください。"
                                break
                            else:
                                full_text += chunk.text
                                report_container.markdown(full_text)
                        
                        if not full_text: full_text = "レポート生成に失敗しました（空の応答）。"
                        st.session_state.generated_report = full_text
                        st.session_state.last_report_cand_id = cand['id']
                        
                    except Exception as e:
                        err_msg = f"Report Generation Error: {str(e)}"
                        st.session_state.generated_report = err_msg
                        st.error("現在、AIモデルが混雑しています (503 Error)。時間を置いて再度お試しください。")
        else:
            st.markdown(st.session_state.generated_report)
            if st.button("🔄 レポート再作成"):
                st.session_state.generated_report = None
                st.rerun()

    # --- B. 自動修復 & チャット ---
    st.markdown("---")
    st.subheader("🤖 Remediation & Chat")

    if selected_incident_candidate and selected_incident_candidate["prob"] > 0.6:
        impact_label = _get_impact_label(selected_incident_candidate, scope_status)
        impact_score = _get_impact_display(selected_incident_candidate, scope_status)
        st.markdown(f"""
        <div style="background-color:#e8f5e9;padding:10px;border-radius:5px;border:1px solid #4caf50;color:#2e7d32;margin-bottom:10px;">
            <strong>✅ AI Analysis Completed</strong><br>
            特定された原因 <b>{selected_incident_candidate['id']}</b> に対する復旧手順が利用可能です。<br>
            (影響度: {impact_label} <span style="font-size:1.2em;font-weight:bold;">{impact_score:.0f}%</span>)
        </div>
        """, unsafe_allow_html=True)

        if "remediation_plan" not in st.session_state:
            if st.button("✨ 修復プランを作成 (Generate Fix)"):
                 if not api_key: st.error("API Key Required")
                 else:
                    with st.spinner("Generating plan..."):
                        t_node = TOPOLOGY.get(selected_incident_candidate["id"])
                        plan_md = generate_remediation_commands(
                            selected_scenario, 
                            f"Identified Root Cause: {selected_incident_candidate['label']}", 
                            t_node, api_key
                        )
                        st.session_state.remediation_plan = plan_md
                        st.rerun()
        
        if "remediation_plan" in st.session_state:
            with st.container(border=True):
                st.info("AI Generated Recovery Procedure")
                st.markdown(st.session_state.remediation_plan)
            
            col_exec1, col_exec2 = st.columns(2)
            
            with col_exec1:
                if st.button("🚀 修復実行 (Execute)", type="primary"):
                    if not api_key:
                        st.error("API Key Required")
                    else:
                        with st.status("Autonomic Remediation in progress...", expanded=True) as status:
                            st.write("⚙️ Applying Configuration...")
                            time.sleep(1.5) 
                            
                            st.write("🔎 Running Verification Commands...")
                            target_node_obj = TOPOLOGY.get(selected_incident_candidate["id"])
                            verification_log = generate_fake_log_by_ai("正常稼働", target_node_obj, api_key)
                            st.session_state.verification_log = verification_log
                            
                            st.write("✅ Verification Completed.")
                            status.update(label="Process Finished", state="complete", expanded=False)
                        
                        st.success("Remediation Process Finished.")

            with col_exec2:
                 if st.button("キャンセル"):
                    del st.session_state.remediation_plan
                    st.session_state.verification_log = None
                    st.rerun()
            
            if st.session_state.get("verification_log"):
                st.markdown("#### 🔎 Post-Fix Verification Logs")
                st.code(st.session_state.verification_log, language="text")
                
                is_success = "up" in st.session_state.verification_log.lower() or "ok" in st.session_state.verification_log.lower()
                
                if is_success:
                    st.balloons()
                    st.success("✅ System Recovered Successfully!")
                else:
                    st.warning("⚠️ Verification indicates potential issues. Please check manually.")

                if st.button("デモを終了してリセット"):
                    del st.session_state.remediation_plan
                    st.session_state.verification_log = None
                    st.session_state.current_scenario = "正常稼働"
                    st.rerun()
    else:
        if selected_incident_candidate:
            impact_label = _get_impact_label(selected_incident_candidate, scope_status)
            impact_score = _get_impact_display(selected_incident_candidate, scope_status)
            score_display = f"{impact_label} {impact_score:.0f}%"
            
            st.warning(f"""
            ⚠️ **自動修復はロックされています**
            現在選択されているインシデントの影響度は **{score_display}** です。
            誤操作防止のため、スコアが 60% 以上の時のみ自動修復ボタンが有効化されます。
            """)

    # チャット (常時表示)
    with st.expander("💬 Chat with AI Agent", expanded=False):
        if st.session_state.chat_session is None and api_key and selected_scenario != "正常稼働":
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            st.session_state.chat_session = model.start_chat(history=[])

        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]): st.markdown(msg["content"])

        if prompt := st.chat_input("Ask details..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"): st.markdown(prompt)
            if st.session_state.chat_session:
                with st.chat_message("assistant"):
                    with st.spinner("Thinking..."):
                        res_container = st.empty()
                        response = generate_content_with_retry(st.session_state.chat_session.model, prompt, stream=True)
                        if response:
                            full_response = ""
                            for chunk in response:
                                full_response += chunk.text
                                res_container.markdown(full_response)
                            st.session_state.messages.append({"role": "assistant", "content": full_response})
                        else:
                            st.error("AIからの応答がありませんでした。")

# ベイズ更新トリガー (診断後)
if st.session_state.trigger_analysis and st.session_state.live_result:
    if st.session_state.verification_result:
        pass
    st.session_state.trigger_analysis = False
    st.rerun()
