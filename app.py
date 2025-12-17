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
from alarm_generator import generate_alarms_for_scenario

# --- ページ設定 ---
st.set_page_config(page_title="AIOps Incident Cockpit", page_icon="⚡", layout="wide")

# ==========================================
# 関数定義
# ==========================================
# Multi-tenant helpers (All Companies View)
# ==========================================
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
    150行のif-elif地獄を alarm_generator.py に委譲
    """
    # alarm_generator.py に委譲
    return generate_alarms_for_scenario(topology, selected_scenario)

def _status_from_alarms(selected_scenario: str, alarms) -> str:
    """全社一覧の状態（停止/要対応/注意/正常）を判定する"""
    if not alarms:
        return "正常"

    # シナリオ起因で停止が明確なもの（優先）
    if ("WAN全回線断" in selected_scenario) or ("電源障害：両系" in selected_scenario):
        return "停止"

    severities = [str(getattr(a, "severity", "")).upper() for a in alarms]
    messages = [str(getattr(a, "message", "")) for a in alarms]

    # CRITICAL が含まれるなら少なくとも要対応。Device Down系なら停止。
    if any(s == "CRITICAL" for s in severities):
        if any(("Device Down" in m) or ("Dual Loss" in m) or ("Unreachable" in m) for m in messages):
            return "停止"
        return "要対応"

    # WARNING/INFO のみ：件数で注意/要対応を分ける
    n = len(alarms)
    if n < 3:
        return "注意"
    if n < 10:
        return "要対応"
    return "停止"

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
    """上段: 全社状態ボード（停止/要対応/注意/正常）"""
    st.subheader("🏢 全社一覧（状態ボード）")
    st.caption("左ほど優先度が高い（停止 → 要対応 → 注意 → 正常）。クリック操作は通常は必要としない状態ボードです。")

    rows = _build_company_rows(selected_scenario)

    # Bucketごとに並べる
    buckets = ["停止", "要対応", "注意", "正常"]
    cols = st.columns(4, gap="large")

    # サマリ（上の小カード）
    counts = {b: sum(1 for r in rows if r["status"] == b) for b in buckets}
    for c, b in zip(cols, buckets):
        with c:
            st.markdown(f"### {_make_status_badge(b)}  **{counts[b]}**")

    st.markdown("")

    # 各列の中身（スクロール可能な表）
    for c, b in zip(cols, buckets):
        with c:
            items = [r for r in rows if r["status"] == b]
            items.sort(key=lambda r: (-r["alarm_count"], r["company_network"]))

            if not items:
                st.caption("（該当なし）")
                continue

            # 表示列
            view_rows = []
            for r in items:
                d = r["delta"]
                delta_str = "" if d is None else (f"+{d}" if d > 0 else str(d))
                maint = "🛠️" if r["maintenance"] else ""
                view_rows.append({
                    "会社/ネットワーク": r["company_network"],
                    "Maintenance": maint,
                    "Δ": delta_str,
                    "Alarms": r["alarm_count"],
                })

            view_df = pd.DataFrame(view_rows)

            selected_idx = _safe_dataframe_select(view_df, key=f"bucket_{b}", height=df_height)
            if selected_idx is not None and 0 <= selected_idx < len(items):
                sel = items[selected_idx]
                st.session_state.selected_scope = {"tenant": sel["tenant"], "network": sel["network"]}

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
scope_status = _status_from_alarms(selected_scenario, alarms)


# 3. コックピット表示
selected_incident_candidate = None

st.markdown("### 🛡️ AIOps インシデント・コックピット")
col1, col2, col3 = st.columns(3)
with col1: st.metric("📉 ノイズ削減率", "98.5%", "高効率稼働中")
with col2: st.metric("📨 処理アラーム数", f"{len(alarms) * 15 if alarms else 0}件", "抑制済")
with col3: st.metric("🚨 要対応インシデント", f"{len([c for c in analysis_results if c['prob'] > 0.6])}件", "対処が必要")
st.markdown("---")

df_data = []
for rank, cand in enumerate(analysis_results, 1):
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
        "リスクスコア": (None if scope_status == "停止" else cand['prob']),
        "推奨アクション": action,
        "ID": cand['id'],
        "Type": cand['type']
    })

df = pd.DataFrame(df_data)
st.info("💡 ヒント: インシデントの行をクリックすると、右側に詳細分析と復旧プランが表示されます。")

event = st.dataframe(
    df,
    column_order=["順位", "ステータス", "根本原因候補", "リスクスコア", "推奨アクション"],
    column_config=(
        {
            "リスクスコア": st.column_config.TextColumn("リスクスコア", help="停止中は評価対象外", width="small")
        }
        if scope_status == "停止"
        else {
            "リスクスコア": st.column_config.ProgressColumn("リスクスコア (0-1.0)", format="%.2f", min_value=0, max_value=1),
        }
    ),
    use_container_width=True,
    hide_index=True,
    selection_mode="single-row",
    on_select="rerun"
)

if len(event.selection.rows) > 0:
    idx = event.selection.rows[0]
    sel_row = df.iloc[idx]
    for res in analysis_results:
        if res['id'] == sel_row['ID'] and res['type'] == sel_row['Type']:
            selected_incident_candidate = res
            break
else:
    selected_incident_candidate = analysis_results[0] if analysis_results else None


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
                    - リスクスコア: {"N/A（停止中のため評価対象外）" if scope_status=="停止" else f"{cand['prob']*100:.0f}"}
                    
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
        st.markdown(f"""
        <div style="background-color:#e8f5e9;padding:10px;border-radius:5px;border:1px solid #4caf50;color:#2e7d32;margin-bottom:10px;">
            <strong>✅ AI Analysis Completed</strong><br>
            特定された原因 <b>{selected_incident_candidate['id']}</b> に対する復旧手順が利用可能です。<br>
            (リスクスコア: <span style="font-size:1.2em;font-weight:bold;">{selected_incident_candidate['prob']*100:.0f}</span>)
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
            score = (None if scope_status == "停止" else selected_incident_candidate['prob'] * 100)
            st.warning(f"""
            ⚠️ **自動修復はロックされています**
            現在選択されているインシデントのリスクスコアは **{('N/A（停止中のため評価対象外）' if score is None else f'{score:.0f}')}** です。
            誤操作防止のため、スコアが 60 以上の時のみ自動修復ボタンが有効化されます。
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
