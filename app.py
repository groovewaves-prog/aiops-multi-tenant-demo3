import streamlit as st
import graphviz
import os
import time
import google.generativeai as genai
import json
import re
import pandas as pd
from google.api_core import exceptions as google_exceptions
try:
    import plotly.graph_objects as go
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("⚠️ Plotly not installed. Some visualizations will be limited.")
from datetime import datetime, timedelta
import math

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

# 🆕 アラーム生成ロジック
try:
    from alarm_generator import generate_alarms_for_scenario
    ALARM_GENERATOR_AVAILABLE = True
except ImportError:
    ALARM_GENERATOR_AVAILABLE = False
    print("⚠️ alarm_generator.py not found, using legacy alarm generation logic")

# --- ページ設定 ---
st.set_page_config(page_title="AIOps Incident Cockpit", page_icon="⚡", layout="wide")

# =====================================================
# 影響度定義（統一基準）- FW片系障害を「要対応」に修正
# =====================================================

class ImpactLevel:
    COMPLETE_OUTAGE = 100  # サービス完全停止
    CRITICAL = 90          # クリティカル単一障害
    DEGRADED_HIGH = 80     # 冗長性喪失（高）- ハザーダス状態
    DEGRADED_MID = 70      # 冗長性喪失（中）
    DOWNSTREAM = 50        # 下流影響
    LOW_PRIORITY = 20      # 低優先度

# FW片系障害を DEGRADED_HIGH に変更（ハザーダス状態として認識）
SCENARIO_IMPACT_MAP = {
    "WAN全回線断": ImpactLevel.COMPLETE_OUTAGE,
    "[WAN] 電源障害：両系": ImpactLevel.COMPLETE_OUTAGE,
    "[L2SW] 電源障害：両系": ImpactLevel.COMPLETE_OUTAGE,
    "[Core] 両系故障": ImpactLevel.CRITICAL,
    "[FW] 電源障害：両系": ImpactLevel.CRITICAL,  # FW両系は CRITICAL
    "[FW] 電源障害：片系": ImpactLevel.DEGRADED_HIGH,  # FW片系は HIGH（要対応）
    "FW片系障害": ImpactLevel.DEGRADED_HIGH,  # FW片系は HIGH（要対応）
    "[WAN] 電源障害：片系": ImpactLevel.DEGRADED_MID,
    "[L2SW] 電源障害：片系": ImpactLevel.DEGRADED_MID,
    "L2SWサイレント障害": ImpactLevel.DEGRADED_HIGH,
    "[WAN] BGPルートフラッピング": ImpactLevel.DEGRADED_HIGH,
    "[WAN] FAN故障": ImpactLevel.DEGRADED_MID,
    "[FW] FAN故障": ImpactLevel.DEGRADED_MID,
    "[L2SW] FAN故障": ImpactLevel.DEGRADED_MID,
    "[WAN] メモリリーク": ImpactLevel.DEGRADED_MID,
    "[FW] メモリリーク": ImpactLevel.DEGRADED_MID,
    "[L2SW] メモリリーク": ImpactLevel.DEGRADED_MID,
    "[WAN] 複合障害：電源＆FAN": ImpactLevel.DEGRADED_HIGH,
    "[Complex] 同時多発：FW & AP": ImpactLevel.DEGRADED_HIGH,
    "正常稼働": 0,
}

def _get_scenario_impact_level(selected_scenario: str) -> int:
    if selected_scenario in SCENARIO_IMPACT_MAP:
        return SCENARIO_IMPACT_MAP[selected_scenario]
    for key, value in SCENARIO_IMPACT_MAP.items():
        if key in selected_scenario:
            return value
    return ImpactLevel.DEGRADED_MID

# =====================================================
# Multi-tenant helpers
# =====================================================
def display_company(tenant_id: str) -> str:
    if tenant_id.endswith("社"):
        return tenant_id
    return f"{tenant_id}社"

def _node_type(node) -> str:
    try: return str(getattr(node, "type", "UNKNOWN"))
    except Exception: return "UNKNOWN"

def _node_layer(node) -> int:
    try: return int(getattr(node, "layer", 999))
    except Exception: return 999

def _find_target_node_id(topology: dict, node_type: str | None = None, layer: int | None = None, keyword: str | None = None) -> str | None:
    for node_id, node in topology.items():
        if node_type and _node_type(node) != node_type: continue
        if layer is not None and _node_layer(node) != layer: continue
        if keyword and keyword not in str(node_id): continue
        return node_id
    return None

def _make_alarms(topology: dict, selected_scenario: str):
    if ALARM_GENERATOR_AVAILABLE:
        return generate_alarms_for_scenario(topology, selected_scenario)
    return _make_alarms_legacy(topology, selected_scenario)

def _make_alarms_legacy(topology: dict, selected_scenario: str):
    if "---" in selected_scenario or "正常" in selected_scenario: return []
    if "Live" in selected_scenario or "[Live]" in selected_scenario: return []
    
    alarms = []
    target_device_id = None
    
    # FW片系障害の処理
    if "FW片系障害" in selected_scenario:
        fid = _find_target_node_id(topology, node_type="FIREWALL")
        if fid:
            return [Alarm(fid, "Heartbeat Loss", "WARNING"), 
                    Alarm(fid, "HA State: Degraded", "WARNING")]
    
    if "[WAN]" in selected_scenario or "WAN" in selected_scenario:
        target_device_id = _find_target_node_id(topology, node_type="ROUTER")
    elif "[FW]" in selected_scenario or "FW" in selected_scenario:
        target_device_id = _find_target_node_id(topology, node_type="FIREWALL")
    elif "[L2SW]" in selected_scenario or "L2SW" in selected_scenario:
        target_device_id = _find_target_node_id(topology, node_type="SWITCH", layer=4)
    
    if target_device_id:
        if "電源" in selected_scenario:
            if "片系" in selected_scenario:
                alarms.append(Alarm(target_device_id, "Power Supply 1 Failed", "WARNING"))
            else:
                alarms.append(Alarm(target_device_id, "Power Supply: Dual Loss", "CRITICAL"))
        elif "FAN" in selected_scenario:
            alarms.append(Alarm(target_device_id, "Fan Fail", "WARNING"))
        elif "メモリ" in selected_scenario:
            alarms.append(Alarm(target_device_id, "Memory High", "WARNING"))
        elif "BGP" in selected_scenario:
            alarms.append(Alarm(target_device_id, "BGP Flapping", "WARNING"))
            
    return alarms

def _status_from_alarms(selected_scenario: str, alarms) -> str:
    """改良版：影響度ベースでステータスを決定"""
    if not alarms: return "正常"
    
    impact_level = _get_scenario_impact_level(selected_scenario)
    
    # 完全停止
    if impact_level >= ImpactLevel.COMPLETE_OUTAGE: 
        return "停止"
    
    # クリティカル、または高影響度の冗長性喪失
    elif impact_level >= ImpactLevel.DEGRADED_HIGH:  # 80以上は「要対応」
        return "要対応"
    
    # 中程度の冗長性喪失
    elif impact_level >= ImpactLevel.DEGRADED_MID:
        severities = [str(getattr(a, "severity", "")).upper() for a in alarms]
        # CRITICALアラームがある場合は「要対応」に格上げ
        if any(s == "CRITICAL" for s in severities): 
            return "要対応"
        return "注意"
    
    # 下流影響
    elif impact_level >= ImpactLevel.DOWNSTREAM: 
        return "注意"
    
    else: 
        return "正常"

def _build_company_rows(selected_scenario: str):
    maint_flags = st.session_state.get("maint_flags", {}) or {}
    prev = st.session_state.get("prev_company_snapshot", {}) or {}
    rows = []
    
    all_scopes = []
    try:
        for t in list_tenants():
            for n in list_networks(t):
                all_scopes.append((t, n))
    except:
        all_scopes = [("A", "default"), ("B", "default")]

    for tenant_id, network_id in all_scopes:
        try:
            paths = get_paths(tenant_id, network_id)
            topo = load_topology(paths.topology_path)
        except:
            topo = {}

        alarms = _make_alarms(topo, selected_scenario)
        alarm_count = len(alarms)
        status = _status_from_alarms(selected_scenario, alarms)
        is_maint = bool(maint_flags.get(tenant_id, False))

        key = f"{tenant_id}/{network_id}"
        prev_count = prev.get(key, {}).get("alarm_count")
        delta = None if prev_count is None else (alarm_count - prev_count)

        # MTTR計算（モック）
        if status in ["停止", "要対応"]:
            mttr = f"{30 + alarm_count * 5}分"
        else:
            mttr = "-"

        rows.append({
            "tenant": tenant_id,
            "network": network_id,
            "company_network": f"{display_company(tenant_id)} / {network_id}",
            "status": status,
            "alarm_count": alarm_count,
            "delta": delta,
            "maintenance": is_maint,
            "mttr": mttr,
            "priority": 1 if status == "停止" else (2 if status == "要対応" else 3),
        })

    st.session_state.prev_company_snapshot = {
        f'{r["tenant"]}/{r["network"]}': {"alarm_count": r["alarm_count"]} for r in rows
    }
    return rows

# =====================================================
# 改良版プロフェッショナルダッシュボード
# =====================================================
def _render_all_companies_board(selected_scenario: str, df_height: int = 220):
    """
    完全改良版: ダイナミックビジュアルとプロフェッショナルUI
    """
    rows = _build_company_rows(selected_scenario)
    
    # 集計
    df_rows = pd.DataFrame(rows)
    count_stop = len(df_rows[df_rows['status'] == '停止'])
    count_action = len(df_rows[df_rows['status'] == '要対応'])
    count_warn = len(df_rows[df_rows['status'] == '注意'])
    count_normal = len(df_rows[df_rows['status'] == '正常'])
    
    # アラーム数の集計（エラー修正用）
    alarm_counts = [r['alarm_count'] for r in rows]
    total_alarms = sum(alarm_counts)
    max_alarms = max(alarm_counts) if alarm_counts else 0

    st.subheader("🏢 全社状態ボード")

    # 1. KPI メトリクス
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("🔴 障害発生", f"{count_stop}社", help="サービス停止レベル")
    kpi2.metric("🟠 要対応", f"{count_action}社", help="冗長性喪失・ハザーダス状態")
    kpi3.metric("🟡 注意", f"{count_warn}社", help="軽微なアラート")
    kpi4.metric("🟢 正常", f"{count_normal}社", help="アラートなし")
    
    st.divider()

    # タブ切り替え
    tab1, tab2, tab3 = st.tabs(["🔥 インタラクティブ・ヒートマップ", "📊 トリアージ・コマンドセンター", "📈 トレンド分析"])
    
    with tab1:
        # 2. 改良版Plotlyヒートマップ
        st.markdown("### 🔥 全社ステータス・ヒートマップ")
        st.caption("円の大きさ = アラーム件数 | 色 = ステータス | クリックで詳細表示")
        
        if not PLOTLY_AVAILABLE:
            st.warning("⚠️ Plotlyがインストールされていません。フルバージョンを表示するには: `pip install plotly`")
            # 簡易版表示
            cols_per_row = 4
            for i in range(0, len(rows), cols_per_row):
                cols = st.columns(cols_per_row)
                for j, col in enumerate(cols):
                    if i + j < len(rows):
                        r = rows[i + j]
                        with col:
                            color = {"停止": "🔴", "要対応": "🟠", "注意": "🟡", "正常": "🟢"}[r['status']]
                            if st.button(
                                f"{color} {r['company_network']}\n{r['alarm_count']}件",
                                key=f"heat_{r['tenant']}_{r['network']}",
                                use_container_width=True
                            ):
                                st.session_state.selected_scope = {"tenant": r['tenant'], "network": r['network']}
                                st.rerun()
        else:
            # Plotlyバブルチャート（改良版）
            data_for_plot = []
            
            # 全体の健全性スコアを計算
            total_critical = sum(1 for r in rows if r['status'] == '停止')
            total_warning = sum(1 for r in rows if r['status'] == '要対応')
            overall_health = 100 - (total_critical * 30 + total_warning * 15)  # 健全性スコア
            
            for r in rows:
                # ステータスに基づく色の値（健全性を反映）
                if r['status'] == "停止":
                    color_value = 100
                elif r['status'] == "要対応":
                    color_value = 70 + (r['alarm_count'] / max(max_alarms, 1)) * 10
                elif r['status'] == "注意":
                    color_value = 30 + (r['alarm_count'] / max(max_alarms, 1)) * 20
                else:
                    color_value = 5
                
                data_for_plot.append({
                    "会社": r['company_network'],
                    "アラーム数": r['alarm_count'],
                    "ステータス": r['status'],
                    "色値": color_value,
                    "tenant": r['tenant'],
                    "network": r['network'],
                    "表示テキスト": f"{r['company_network']}<br>{r['alarm_count']}件",
                    "メンテナンス": "🛠️" if r['maintenance'] else ""
                })
            
            df_plot = pd.DataFrame(data_for_plot)
            
            # 全体健全性インジケーター
            health_color = '#4caf50' if overall_health > 80 else '#ffc107' if overall_health > 50 else '#f44336'
            st.markdown(f"""
            <div style="text-align: center; margin-bottom: 10px;">
                <span style="font-size: 14px; color: #666;">全体健全性</span>
                <div style="
                    display: inline-block;
                    margin-left: 10px;
                    background: linear-gradient(to right, #e0e0e0, #f5f5f5);
                    border-radius: 20px;
                    width: 200px;
                    height: 8px;
                    position: relative;
                ">
                    <div style="
                        width: {overall_health}%;
                        height: 100%;
                        background: {health_color};
                        border-radius: 20px;
                    "></div>
                </div>
                <span style="
                    margin-left: 10px;
                    font-weight: bold;
                    color: {health_color};
                ">{overall_health:.0f}%</span>
            </div>
            """, unsafe_allow_html=True)
            
            # バブルチャートの作成（改良版：密集配置と動的サイズ）
            if len(df_plot) > 0:
                # グリッド配置の計算（よりコンパクトに）
                n_companies = len(df_plot)
                
                # 会社数に応じて最適な列数を決定
                if n_companies <= 4:
                    cols = n_companies
                elif n_companies <= 8:
                    cols = 4
                elif n_companies <= 15:
                    cols = 5
                elif n_companies <= 24:
                    cols = 6
                else:
                    cols = 8  # 大量の会社がある場合
                
                rows_needed = math.ceil(n_companies / cols)
                
                # X, Y座標の生成（密集配置、間隔を動的に調整）
                spacing = 1.0 if n_companies <= 10 else 0.8  # 会社が多い場合は間隔を狭める
                x_coords = []
                y_coords = []
                for i in range(n_companies):
                    # ジグザグ配置で視認性向上
                    row = i // cols
                    col = i % cols
                    # 偶数行は少しずらす
                    x_offset = 0.2 if row % 2 == 1 else 0
                    x = col * spacing + x_offset
                    y = row * spacing
                    x_coords.append(x)
                    y_coords.append(y)
                
                df_plot['x'] = x_coords
                df_plot['y'] = y_coords
                
                # バブルサイズの計算（より明確な差をつける）
                # アラーム数に応じて3段階のサイズ設定
                sizes = []
                for alarm_count in df_plot['アラーム数']:
                    if alarm_count == 0:
                        size = 25  # 最小サイズ
                    elif alarm_count <= 5:
                        size = 35 + alarm_count * 5  # 小〜中サイズ
                    elif alarm_count <= 15:
                        size = 60 + (alarm_count - 5) * 3  # 中〜大サイズ
                    else:
                        size = min(100, 90 + (alarm_count - 15) * 1)  # 最大サイズ（上限設定）
                    sizes.append(size)
                df_plot['size'] = sizes
                
                fig = go.Figure()
                
                # 各ステータスごとにトレースを追加（凡例のため）
                for status in ["停止", "要対応", "注意", "正常"]:
                    df_status = df_plot[df_plot['ステータス'] == status]
                    if len(df_status) > 0:
                        fig.add_trace(go.Scatter(
                            x=df_status['x'],
                            y=df_status['y'],
                            mode='markers+text',
                            name=status,
                            text=df_status['会社'],
                            textposition="middle center",
                            marker=dict(
                                size=df_status['size'],
                                color=df_status['色値'],
                                colorscale=[
                                    [0, '#2e7d32'],      # 濃い緑（健全）
                                    [0.3, '#66bb6a'],    # 緑
                                    [0.5, '#fdd835'],    # 黄
                                    [0.7, '#ff9800'],    # オレンジ
                                    [0.85, '#f44336'],   # 赤
                                    [1, '#b71c1c']       # 濃い赤（危機的）
                                ],
                                line=dict(width=2, color='white'),
                                showscale=False,
                                opacity=0.9  # 少し透明感を持たせる
                            ),
                            customdata=df_status[['tenant', 'network', 'アラーム数']],
                            hovertemplate='<b>%{text}</b><br>アラーム: %{customdata[2]}件<extra></extra>'
                        ))
                
                fig.update_layout(
                    showlegend=True,
                    height=min(600, 200 + rows_needed * 80),  # 行数に応じて高さを調整
                    xaxis=dict(
                        showgrid=False, 
                        zeroline=False, 
                        visible=False, 
                        range=[-0.5, cols * spacing + 0.5]
                    ),
                    yaxis=dict(
                        showgrid=False, 
                        zeroline=False, 
                        visible=False, 
                        range=[-0.5, rows_needed * spacing + 0.5],
                        autorange='reversed'  # 上から下に配置
                    ),
                    plot_bgcolor='rgba(248,248,248,0.5)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    margin=dict(t=20, b=20, l=20, r=20),
                    hovermode='closest',
                    clickmode='event+select',
                    legend=dict(
                        orientation="h",
                        yanchor="top",
                        y=-0.1,
                        xanchor="center",
                        x=0.5
                    )
                )
                
                # インタラクティブ表示
                selected_points = st.plotly_chart(
                    fig,
                    use_container_width=True,
                    on_select="rerun",
                    selection_mode=['points']
                )
                
                # 選択処理
                if selected_points and hasattr(selected_points, 'selection'):
                    if hasattr(selected_points.selection, 'point_indices'):
                        indices = selected_points.selection.point_indices
                        if indices and len(indices) > 0:
                            idx = indices[0]
                            if 0 <= idx < len(df_plot):
                                selected = df_plot.iloc[idx]
                                st.session_state.selected_scope = {
                                    "tenant": selected['tenant'],
                                    "network": selected['network']
                                }
                                st.rerun()
    
    with tab2:
        # 3. トリアージ・コマンドセンター（改良版）
        st.markdown("### 🚨 トリアージ・コマンドセンター")
        st.caption("優先度順の対応指示とアクション管理")
        
        # フィルタリング（エラー修正版）
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            filter_status = st.multiselect(
                "ステータス",
                ["停止", "要対応", "注意", "正常"],
                default=["停止", "要対応"],
                key="filter_status"
            )
        with col2:
            # スライダーエラーの確実な修正
            if max_alarms > 0:
                # min_valueとmax_valueが同じ値にならないように確保
                if max_alarms == 1:
                    # 1件の場合は選択肢を広げる
                    filter_alarm = st.slider(
                        "アラーム数",
                        min_value=0,
                        max_value=2,
                        value=(0, 2),
                        key="filter_alarm"
                    )
                else:
                    filter_alarm = st.slider(
                        "アラーム数",
                        min_value=0,
                        max_value=max_alarms,
                        value=(0, max_alarms),
                        key="filter_alarm"
                    )
            else:
                # アラームがない場合はスライダーを表示しない
                filter_alarm = (0, 1)
                st.info("アラームなし")
        with col3:
            show_maint = st.checkbox("メンテナンス中を含む", value=True)
        with col4:
            sort_by = st.selectbox(
                "ソート",
                ["優先度順", "アラーム数順", "会社名順"],
                key="sort_by"
            )
        
        # フィルタ適用
        filtered_rows = [
            r for r in rows 
            if r['status'] in filter_status 
            and filter_alarm[0] <= r['alarm_count'] <= filter_alarm[1]
            and (show_maint or not r['maintenance'])
        ]
        
        # ソート
        if sort_by == "優先度順":
            filtered_rows.sort(key=lambda x: (x['priority'], -x['alarm_count']))
        elif sort_by == "アラーム数順":
            filtered_rows.sort(key=lambda x: -x['alarm_count'])
        else:
            filtered_rows.sort(key=lambda x: x['company_network'])
        
        if filtered_rows:
            # 改良版トリアージリスト
            for idx, r in enumerate(filtered_rows):
                with st.container():
                    cols = st.columns([0.5, 3, 1.5, 1.5, 1, 1])
                    
                    # ステータスアイコン
                    with cols[0]:
                        icon = {"停止": "🔴", "要対応": "🟠", "注意": "🟡", "正常": "🟢"}[r['status']]
                        st.markdown(f"### {icon}")
                    
                    # 会社情報
                    with cols[1]:
                        st.markdown(f"**{r['company_network']}**")
                        if r['maintenance']:
                            st.caption("🛠️ メンテナンス中")
                    
                    # 深刻度（改良版：コンパクトで動的なプログレスバー）
                    with cols[2]:
                        # アラーム数とステータスに基づく深刻度計算
                        if r['status'] == "停止":
                            severity = 100
                            bar_color = '#d32f2f'  # 濃い赤
                            text_color = '#ffffff'
                        elif r['status'] == "要対応":
                            # アラーム数に応じて70-95%の範囲で変動
                            severity = min(95, 70 + r['alarm_count'] * 2)
                            bar_color = '#f57c00'  # オレンジ
                            text_color = '#ffffff'
                        elif r['status'] == "注意":
                            # アラーム数に応じて30-60%の範囲で変動
                            severity = min(60, 30 + r['alarm_count'] * 3)
                            bar_color = '#fbc02d'  # 黄色
                            text_color = '#000000'
                        else:
                            severity = max(5, r['alarm_count'] * 2)  # 正常でも少し表示
                            bar_color = '#66bb6a'  # 緑
                            text_color = '#ffffff'
                        
                        # コンパクトなプログレスバー（高さを抑える）
                        st.markdown(f"""
                        <div style="margin: 0; padding: 0;">
                            <div style="
                                background: linear-gradient(to right, #e8e8e8 0%, #f5f5f5 100%);
                                border-radius: 8px;
                                overflow: hidden;
                                height: 24px;
                                position: relative;
                                box-shadow: inset 0 1px 3px rgba(0,0,0,0.2);
                            ">
                                <div style="
                                    width: {severity}%;
                                    height: 100%;
                                    background: {bar_color};
                                    background: linear-gradient(90deg, 
                                        {bar_color} 0%, 
                                        {bar_color}dd {severity}%, 
                                        {bar_color}88 100%);
                                    display: flex;
                                    align-items: center;
                                    justify-content: center;
                                    position: relative;
                                    transition: width 0.3s ease;
                                    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                                ">
                                    <span style="
                                        color: {text_color};
                                        font-weight: bold;
                                        font-size: 12px;
                                        text-shadow: 0 1px 2px rgba(0,0,0,0.3);
                                        position: absolute;
                                    ">{severity}%</span>
                                </div>
                            </div>
                            <div style="
                                font-size: 10px;
                                color: #666;
                                margin-top: 2px;
                                display: flex;
                                justify-content: space-between;
                            ">
                                <span>深刻度</span>
                                <span>{r['alarm_count']}件</span>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # MTTR
                    with cols[3]:
                        st.metric("推定MTTR", r['mttr'], label_visibility="collapsed")
                        st.caption("復旧時間")
                    
                    # アクションボタン
                    with cols[4]:
                        if st.button("📋", key=f"detail_{r['tenant']}_{r['network']}", help="詳細を表示"):
                            st.session_state.selected_scope = {
                                "tenant": r['tenant'],
                                "network": r['network']
                            }
                            st.rerun()
                    
                    with cols[5]:
                        if r['status'] in ["停止", "要対応"]:
                            if st.button("🚀", key=f"action_{r['tenant']}_{r['network']}", 
                                       type="primary", help="自動対応を開始"):
                                st.session_state.selected_scope = {
                                    "tenant": r['tenant'],
                                    "network": r['network']
                                }
                                st.session_state.auto_remediate = True
                                st.rerun()
                    
                    st.divider()
        else:
            st.info("フィルタ条件に該当するシステムはありません。")
    
    with tab3:
        # 4. トレンド分析
        st.markdown("### 📈 24時間トレンド")
        
        # 統計情報は常に表示
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info(f"**本日の総アラーム数**: {total_alarms}件")
        with col2:
            avg_mttr = "45分"  # モック
            st.info(f"**平均MTTR**: {avg_mttr}")
        with col3:
            resolution_rate = "92%"  # モック
            st.info(f"**自動解決率**: {resolution_rate}")
        
        if PLOTLY_AVAILABLE:
            # モックデータ生成
            hours = list(range(24))
            current_hour = datetime.now().hour
            
            trend_data = []
            for h in hours:
                base = 5 + abs(h - 12) * 2  # 昼間に多い傾向
                if h == current_hour:
                    stop = count_stop
                    action = count_action
                    warn = count_warn
                else:
                    import random
                    stop = max(0, base // 10 + random.randint(-1, 1))
                    action = base // 5 + random.randint(-2, 2)
                    warn = base // 3 + random.randint(-3, 3)
                
                trend_data.append({
                    "時刻": f"{h:02d}:00",
                    "停止": stop,
                    "要対応": action,
                    "注意": warn
                })
            
            df_trend = pd.DataFrame(trend_data)
            
            # Plotlyグラフ
            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                x=df_trend['時刻'], y=df_trend['停止'],
                mode='lines+markers', name='停止',
                line=dict(color='#ef5350', width=3),
                marker=dict(size=8),
                fill='tozeroy',
                fillcolor='rgba(239, 83, 80, 0.2)'
            ))
            fig_trend.add_trace(go.Scatter(
                x=df_trend['時刻'], y=df_trend['要対応'],
                mode='lines+markers', name='要対応',
                line=dict(color='#fb8c00', width=2),
                marker=dict(size=6),
                fill='tozeroy',
                fillcolor='rgba(251, 140, 0, 0.1)'
            ))
            fig_trend.add_trace(go.Scatter(
                x=df_trend['時刻'], y=df_trend['注意'],
                mode='lines+markers', name='注意',
                line=dict(color='#fbc02d', width=1),
                marker=dict(size=4)
            ))
            
            fig_trend.update_layout(
                height=300,
                hovermode='x unified',
                xaxis_title="時刻",
                yaxis_title="発生件数",
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=1, xanchor="right", x=1)
            )
            
            st.plotly_chart(fig_trend, use_container_width=True)
        else:
            st.info("📊 トレンドグラフを表示するには Plotly をインストールしてください。")
            st.code("pip install plotly", language="bash")

# =====================================================
# 以下、既存のヘルパー関数とメインロジック（変更なし）
# =====================================================

def _get_impact_display(cand: dict, scope_status: str) -> str:
    prob_pct = cand['prob'] * 100
    if scope_status == "停止": return 100
    return prob_pct

def _get_impact_label(cand: dict, scope_status: str) -> str:
    prob = cand['prob']
    prob_pct = prob * 100
    if scope_status == "停止" or prob_pct >= ImpactLevel.COMPLETE_OUTAGE: return "🔴 サービス停止"
    is_downstream_symptom = ("Connection Lost" in cand.get('label', '') and prob < 0.6)
    if is_downstream_symptom: return "⚪ 下流影響"
    elif prob_pct >= ImpactLevel.CRITICAL: return "🔴 CRITICAL"
    elif prob_pct >= ImpactLevel.DEGRADED_MID: return "🟡 WARNING"
    elif prob_pct >= ImpactLevel.DOWNSTREAM: return "⚪ 下流影響"
    else: return "⚪ 低優先度"

def find_target_node_id(topology, node_type=None, layer=None, keyword=None):
    return _find_target_node_id(topology, node_type, layer, keyword)

def load_config_by_id(device_id):
    possible_paths = [f"configs/{device_id}.txt", f"{device_id}.txt"]
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f: return f.read()
            except: pass
    return "Config file not found."

def sanitize_config_text(raw_text: str) -> str:
    if not raw_text: return raw_text
    text = raw_text
    text = re.sub(r"(encrypted-password\s+)([\"']?)[^\"';\n]+([\"']?)", r"\1\2***REDACTED***\3", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})(/\d{1,2})?\b", r"\1.xxx\3", text)
    return text

def build_config_summary(sanitized_text: str) -> dict:
    summary = {"os_version": None, "host_name": None, "interfaces": [], "zones": []}
    if not sanitized_text: return summary
    m = re.search(r"\bversion\s+([^;\n]+)", sanitized_text)
    if m: summary["os_version"] = m.group(1).strip()
    m = re.search(r"\bhost-name\s+([^;\s\n]+)", sanitized_text)
    if m: summary["host_name"] = m.group(1).strip()
    for im in re.finditer(r"\b(ge-\d+/\d+/\d+)\b[\s\S]{0,220}?\baddress\s+([^;\s\n]+)", sanitized_text):
        summary["interfaces"].append({"name": im.group(1), "address": im.group(2)})
    for zm in re.finditer(r"security-zone\s+([^\s\{\n]+)", sanitized_text):
        z = zm.group(1).strip()
        if z not in summary["zones"]: summary["zones"].append(z)
    return summary

def load_config_sanitized(device_id: str) -> dict:
    raw = load_config_by_id(device_id)
    sanitized = sanitize_config_text(raw)
    summary = build_config_summary(sanitized)
    excerpt = sanitized[:1500] if isinstance(sanitized, str) else ""
    return {"device_id": device_id, "summary": summary, "excerpt": excerpt, "available": (raw != "Config file not found.")}

def generate_content_with_retry(model, prompt, stream=True, retries=3):
    for i in range(retries):
        try:
            return model.generate_content(prompt, stream=stream)
        except google_exceptions.ServiceUnavailable:
            if i == retries - 1: raise
            time.sleep(2 * (i + 1))
    return None

def render_topology(alarms, root_cause_candidates):
    graph = graphviz.Digraph()
    graph.attr(rankdir='TB')
    graph.attr('node', shape='box', style='rounded,filled', fontname='Helvetica')
    
    alarm_map = {a.device_id: a for a in alarms}
    alarmed_ids = set(alarm_map.keys())
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
            color = "#fff3e0"; penwidth = "4"; label += "\n[サイレント疑い]"
        elif "Hardware/Physical" in status_type or "Critical" in status_type:
            color = "#ffcdd2"; penwidth = "3"; label += "\n[ROOT CAUSE]"
        elif "Network/Unreachable" in status_type or "Network/Secondary" in status_type:
            color = "#cfd8dc"; fontcolor = "#546e7a"; label += "\n[Unreachable]"
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

    if 'maint_flags' not in st.session_state: st.session_state.maint_flags = {}
    with st.expander('🛠️ Maintenance', expanded=False):
        ts = list_tenants() if list_tenants() else ['A','B']
        selected = st.multiselect('Maintenance 中の会社', options=ts, default=[t for t in ts if st.session_state.maint_flags.get(t, False)], format_func=display_company)
        st.session_state.maint_flags = {t: (t in selected) for t in ts}

    st.markdown("---")
    if api_key: st.success("API Connected")
    else:
        st.warning("API Key Missing")
        user_key = st.text_input("Google API Key", type="password")
        if user_key: api_key = user_key

# --- セッション管理 ---
if "current_scenario" not in st.session_state: st.session_state.current_scenario = "正常稼働"
if "selected_scope" not in st.session_state: st.session_state.selected_scope = None

# ======================================================================================
# 上段の全社状態ボード
# ======================================================================================
DF_HEIGHT_5ROWS = 260
_render_all_companies_board(selected_scenario, df_height=DF_HEIGHT_5ROWS)
st.markdown("---")

# ======================================================================================
# 下段：AIOps インシデント・コックピット（既存のまま）
# ======================================================================================
_scope = st.session_state.get("selected_scope")
if _scope and isinstance(_scope, dict) and _scope.get("tenant") and _scope.get("network"):
    ACTIVE_TENANT = _scope["tenant"]
    ACTIVE_NETWORK = _scope["network"]
else:
    try:
        _ts = list_tenants(); _t0 = _ts[0] if _ts else "A"
        _ns = list_networks(_t0); _n0 = _ns[0] if _ns else "default"
    except:
        _t0, _n0 = "A", "default"
    ACTIVE_TENANT, ACTIVE_NETWORK = _t0, _n0
    st.session_state.selected_scope = {"tenant": _t0, "network": _n0}

_paths = get_paths(ACTIVE_TENANT, ACTIVE_NETWORK)
TOPOLOGY = load_topology(_paths.topology_path)

for key in ["live_result", "messages", "chat_session", "trigger_analysis", "verification_result", "generated_report", "verification_log", "last_report_cand_id", "logic_engine"]:
    if key not in st.session_state:
        st.session_state[key] = None if key != "messages" and key != "trigger_analysis" else ([] if key == "messages" else False)

try:
    topo_mtime = os.path.getmtime(_paths.topology_path)
except: topo_mtime = 0.0
engine_sig = f"{ACTIVE_TENANT}/{ACTIVE_NETWORK}:{topo_mtime}"

if st.session_state.get("logic_engine_sig") != engine_sig:
    st.session_state.logic_engine = LogicalRCA(TOPOLOGY)
    st.session_state.logic_engine_sig = engine_sig

if st.session_state.current_scenario != selected_scenario:
    st.session_state.current_scenario = selected_scenario
    st.session_state.messages = []; st.session_state.chat_session = None; st.session_state.live_result = None
    st.session_state.trigger_analysis = False; st.session_state.verification_result = None
    st.session_state.generated_report = None; st.session_state.verification_log = None
    if "remediation_plan" in st.session_state: del st.session_state.remediation_plan
    st.rerun()

alarms = _make_alarms(TOPOLOGY, selected_scenario)
target_device_id = None
root_severity = "CRITICAL"

engine = st.session_state.logic_engine
engine.SILENT_RATIO = 0.3 if "サイレント" in selected_scenario else 0.5
analysis_results = engine.analyze(alarms)

scenario_impact = _get_scenario_impact_level(selected_scenario)
if analysis_results and scenario_impact > 0:
    top_candidate = analysis_results[0]
    if top_candidate.get('prob', 0) > 0.5:
        top_candidate['prob'] = scenario_impact / 100.0
        if "サイレント" in selected_scenario or "Silent" in top_candidate.get('type', ''):
            top_candidate['prob'] = ImpactLevel.DEGRADED_HIGH / 100.0

scope_status = _status_from_alarms(selected_scenario, alarms)
selected_incident_candidate = None

st.markdown(f"### 🛡️ AIOps インシデント・コックピット : **{display_company(ACTIVE_TENANT)}** / {ACTIVE_NETWORK}")
col1, col2, col3 = st.columns(3)
with col1: st.metric("📉 ノイズ削減率", "98.5%", "高効率稼働中")
total_alarms = len(alarms)
downstream_count = len([c for c in analysis_results if "Unreachable" in c.get('type', '')])
suppressed_count = total_alarms * 15 + downstream_count
with col2: st.metric("📨 抑制アラーム数", f"{suppressed_count}件", "ノイズ削減")
with col3: st.metric("🚨 要対応インシデント", f"{len([c for c in analysis_results if c['prob'] > 0.6])}件", "対処が必要")
st.markdown("---")

# 以下、既存のコックピット表示ロジック続き
root_cause_candidates = []
downstream_devices = []
for cand in analysis_results:
    if "Network/Unreachable" in cand.get('type', '') or "Network/Secondary" in cand.get('type', ''):
        downstream_devices.append(cand)
    else:
        root_cause_candidates.append(cand)

if root_cause_candidates and downstream_devices:
    st.info(f"📍 **根本原因**: {root_cause_candidates[0]['id']} → 影響範囲: 配下 {len(downstream_devices)} 機器")

df_data = []
for rank, cand in enumerate(root_cause_candidates, 1):
    status = "⚪ 監視中"; action = "👁️ 静観"
    is_silent = ("Silent" in str(cand.get("type","")) or "サイレント" in str(cand.get("type","")))
    if is_silent:
        status = "🟣 サイレント疑い (上位設備)"; action = "🔍 上位SW/配下影響を確認"
    else:
        if cand['prob'] > 0.8: status = "🔴 危険 (根本原因)"; action = "🚀 自動修復が可能"
        elif cand['prob'] > 0.6: status = "🟡 警告 (被疑箇所)"; action = "🔍 詳細調査を推奨"
    if "Network/Unreachable" in cand['type']: status = "⚫ 応答なし (上位障害)"; action = "⛔ 対応不要"

    candidate_text = f"デバイス: {cand['id']} / 原因: {cand['label']}"
    if cand.get('verification_log'): candidate_text += " [🔍 Active Probe: 応答なし]"
    df_data.append({
        "順位": rank, "ステータス": status, "根本原因候補": candidate_text,
        "影響度": _get_impact_display(cand, scope_status), "状態": _get_impact_label(cand, scope_status),
        "推奨アクション": action, "ID": cand['id'], "Type": cand['type']
    })

df = pd.DataFrame(df_data)
st.info("💡 ヒント: インシデントの行をクリックすると、右側に詳細分析と復旧プランが表示されます。")

event = st.dataframe(
    df,
    column_order=["順位", "ステータス", "根本原因候補", "影響度", "状態", "推奨アクション"],
    column_config={
        "影響度": st.column_config.ProgressColumn("影響度", format="%d%%", min_value=0, max_value=100),
        "状態": st.column_config.TextColumn("状態", width="medium")
    },
    use_container_width=True, hide_index=True, selection_mode="single-row", on_select="rerun"
)

if downstream_devices:
    with st.expander(f"▼ 影響を受けている機器 ({len(downstream_devices)}台) - 上流復旧待ち", expanded=False):
        dd_df = pd.DataFrame([{"No": i+1, "デバイス": d['id'], "状態": "⚫ 応答なし", "備考": "上流復旧待ち"} for i, d in enumerate(downstream_devices)])
        st.dataframe(dd_df, use_container_width=True, hide_index=True)

if event.selection and len(event.selection.rows) > 0:
    sel_row = df.iloc[event.selection.rows[0]]
    for res in root_cause_candidates:
        if res['id'] == sel_row['ID'] and res['type'] == sel_row['Type']:
            selected_incident_candidate = res; break
else:
    selected_incident_candidate = root_cause_candidates[0] if root_cause_candidates else None

# 画面分割
col_map, col_chat = st.columns([1.2, 1])

with col_map:
    st.subheader("🌐 Network Topology")
    st.graphviz_chart(render_topology(alarms, analysis_results), use_container_width=True)
    st.markdown("---")
    st.subheader("🛠️ Auto-Diagnostics")
    
    if st.button("🚀 診断実行 (Run Diagnostics)", type="primary"):
        if not api_key: st.error("API Key Required")
        else:
            with st.status("Agent Operating...", expanded=True) as status:
                target_node_obj = TOPOLOGY.get(selected_incident_candidate['id']) if selected_incident_candidate else None
                res = run_diagnostic_simulation(selected_scenario, target_node_obj, api_key)
                st.session_state.live_result = res
                if res["status"] == "SUCCESS":
                    st.write("✅ Log Acquired & Sanitized.")
                    status.update(label="Diagnostics Complete!", state="complete", expanded=False)
                    st.session_state.verification_result = verify_log_content(res.get('sanitized_log', ""))
                    st.session_state.trigger_analysis = True
                else:
                    status.update(label="Diagnostics Failed", state="error")
            st.rerun()

    if st.session_state.live_result:
        res = st.session_state.live_result
        if res["status"] == "SUCCESS":
            st.markdown("#### 📄 Diagnostic Results")
            with st.container(border=True):
                if st.session_state.verification_result:
                    v = st.session_state.verification_result
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Ping", v.get('ping_status')); c2.metric("IF", v.get('interface_status')); c3.metric("HW", v.get('hardware_status'))
                st.divider()
                st.caption("🔒 Raw Logs (Sanitized)"); st.code(res["sanitized_log"], language="text")

with col_chat:
    st.subheader("📝 AI Analyst Report")
    
    if selected_incident_candidate:
        cand = selected_incident_candidate
        if "generated_report" not in st.session_state or st.session_state.generated_report is None:
            if api_key and selected_scenario != "正常稼働":
                if st.button("📝 詳細レポートを作成 (Generate Report)"):
                    report_container = st.empty()
                    cfg = load_config_sanitized(cand['id'])
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel("gemma-3-12b-it")
                    
                    prompt = f"""
                    あなたはネットワーク運用監視のプロフェッショナルです。
                    以下の障害インシデントについて、顧客向けの「詳細な状況報告レポート」を作成してください。
                    
                    【入力情報】
                    - 発生シナリオ: {selected_scenario}
                    - 根本原因候補: {cand['id']} ({cand['label']})
                    - 影響度スコア: {_get_impact_display(cand, scope_status):.0f}%
                    
                    【重要: 出力形式】
                    HTMLタグは使用せず、Markdownを使用してください。
                    """
                    try:
                        response = generate_content_with_retry(model, prompt, stream=True)
                        full_text = ""
                        for chunk in response:
                            full_text += chunk.text
                            report_container.markdown(full_text)
                        st.session_state.generated_report = full_text
                    except Exception as e:
                        st.error(f"Report Generation Error: {str(e)}")
        else:
            st.markdown(st.session_state.generated_report)
            if st.button("🔄 レポート再作成"):
                st.session_state.generated_report = None; st.rerun()

    st.markdown("---")
    st.subheader("🤖 Remediation & Chat")
    
    # 自動修復フラグチェック
    if st.session_state.get("auto_remediate"):
        st.session_state.auto_remediate = False
        if selected_incident_candidate and selected_incident_candidate["prob"] > 0.6:
            st.session_state.remediation_plan = "Auto-generating..."
    
    if selected_incident_candidate and selected_incident_candidate["prob"] > 0.6:
        if "remediation_plan" not in st.session_state:
            if st.button("✨ 修復プランを作成 (Generate Fix)"):
                 if not api_key: st.error("API Key Required")
                 else:
                    with st.spinner("Generating plan..."):
                        t_node = TOPOLOGY.get(selected_incident_candidate["id"])
                        plan_md = generate_remediation_commands(selected_scenario, f"Root Cause: {selected_incident_candidate['label']}", t_node, api_key)
                        st.session_state.remediation_plan = plan_md
                        st.rerun()
        
        if "remediation_plan" in st.session_state:
            if st.session_state.remediation_plan == "Auto-generating...":
                with st.spinner("自動修復プランを生成中..."):
                    t_node = TOPOLOGY.get(selected_incident_candidate["id"])
                    plan_md = generate_remediation_commands(selected_scenario, f"Root Cause: {selected_incident_candidate['label']}", t_node, api_key)
                    st.session_state.remediation_plan = plan_md
                    st.rerun()
            else:
                with st.container(border=True):
                    st.info("AI Generated Recovery Procedure")
                    st.markdown(st.session_state.remediation_plan)
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("🚀 修復実行 (Execute)", type="primary"):
                        st.success("Remediation Executed.")
                with c2:
                    if st.button("キャンセル"):
                        del st.session_state.remediation_plan; st.rerun()

    with st.expander("💬 Chat with AI Agent", expanded=False):
        if st.session_state.chat_session is None and api_key and selected_scenario != "正常稼働":
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemma-3-12b-it")
            st.session_state.chat_session = model.start_chat(history=[])
        
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"]): st.markdown(msg["content"])

        if prompt := st.chat_input("Ask details..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"): st.markdown(prompt)
            if st.session_state.chat_session:
                with st.chat_message("assistant"):
                    with st.spinner("Thinking..."):
                        res_container = st.empty(); full_response = ""
                        response = generate_content_with_retry(st.session_state.chat_session.model, prompt, stream=True)
                        if response:
                            for chunk in response: full_response += chunk.text; res_container.markdown(full_response)
                            st.session_state.messages.append({"role": "assistant", "content": full_response})

if st.session_state.trigger_analysis and st.session_state.live_result:
    st.session_state.trigger_analysis = False
    st.rerun()
