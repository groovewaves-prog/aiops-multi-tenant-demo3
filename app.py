import streamlit as st
import graphviz
import os
import google.generativeai as genai

from data import TOPOLOGY
from logic import CausalInferenceEngine, Alarm, simulate_cascade_failure
from network_ops import run_diagnostic_simulation

# --- ページ設定 ---
st.set_page_config(page_title="Antigravity Live", page_icon="⚡", layout="wide")

# --- 関数: トポロジー図の生成 ---
def render_topology(alarms, root_cause_node):
    graph = graphviz.Digraph()
    graph.attr(rankdir='TB')
    graph.attr('node', shape='box', style='rounded,filled', fontname='Helvetica')
    
    alarmed_ids = {a.device_id for a in alarms}
    
    # ノード描画
    for node_id, node in TOPOLOGY.items():
        color = "#e8f5e9" # Default Green
        penwidth = "1"
        fontcolor = "black"
        label = f"{node_id}\n({node.type})"
        
        if root_cause_node and node_id == root_cause_node.id:
            color = "#ffcdd2" # Root Cause Red
            penwidth = "3"
            label += "\n[ROOT CAUSE]"
        elif node_id in alarmed_ids:
            color = "#fff9c4" # Alarm Yellow
        
        graph.node(node_id, label=label, fillcolor=color, color='black', penwidth=penwidth, fontcolor=fontcolor)
    
    # エッジ描画
    for node_id, node in TOPOLOGY.items():
        if node.parent_id:
            graph.edge(node.parent_id, node_id)
            
            # 親がHAグループの場合
            parent_node = TOPOLOGY.get(node.parent_id)
            if parent_node and parent_node.redundancy_group:
                partners = [n.id for n in TOPOLOGY.values() 
                           if n.redundancy_group == parent_node.redundancy_group and n.id != parent_node.id]
                for partner_id in partners:
                    graph.edge(partner_id, node_id)
    return graph

# --- 関数: Config自動読み込み (修正箇所) ---
def load_config_by_id(device_id):
    path = f"configs/{device_id}.txt"
    if os.path.exists(path):
        try:
            # tryブロック内は必ず改行してインデントする
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return None
    return None

# --- UI構築 ---
st.title("⚡ Antigravity AI Agent (Live Demo)")

api_key = None
if "GOOGLE_API_KEY" in st.secrets:
    api_key = st.secrets["GOOGLE_API_KEY"]
else:
    api_key = os.environ.get("GOOGLE_API_KEY")

with st.sidebar:
    st.header("⚡ 運用モード選択")
    
    selected_scenario = st.radio(
        "シナリオ:", 
        (
            "正常稼働", 
            "1. WAN全回線断", 
            "2. FW片系障害", 
            "3. L2SWサイレント障害",
            "4. BGPルートフラッピング",
            "5. FAN故障",
            "6. 電源故障",
            "7. メモリリーク",
            "8. [Live] Cisco実機診断"
        )
    )
    
    st.markdown("---")
    if api_key:
        st.success("API Connected")
    else:
        st.warning("API Key Missing")
        user_key = st.text_input("Google API Key", type="password")
        if user_key: api_key = user_key

# セッション状態管理
if "current_scenario" not in st.session_state:
    st.session_state.current_scenario = "正常稼働"
    st.session_state.messages = []
    st.session_state.chat_session = None 
    st.session_state.live_result = None
    st.session_state.trigger_analysis = False

if st.session_state.current_scenario != selected_scenario:
    st.session_state.current_scenario = selected_scenario
    st.session_state.messages = []
    st.session_state.chat_session = None
    st.session_state.live_result = None
    st.session_state.trigger_analysis = False
    st.rerun()

# --- アラーム生成 (シミュレーション) ---
alarms = []

if selected_scenario == "1. WAN全回線断":
    alarms = simulate_cascade_failure("WAN_ROUTER_01", TOPOLOGY)
elif selected_scenario == "2. FW片系障害":
    alarms = [Alarm("FW_01_PRIMARY", "Heartbeat Loss", "WARNING")]
elif selected_scenario == "3. L2SWサイレント障害":
    alarms = [Alarm("AP_01", "Connection Lost", "CRITICAL"), Alarm("AP_02", "Connection Lost", "CRITICAL")]
elif selected_scenario in ["4. BGPルートフラッピング", "7. メモリリーク"]:
    alarms = [Alarm("WAN_ROUTER_01", "Syslog Pattern Match", "WARNING")]
elif selected_scenario in ["5. FAN故障", "6. 電源故障"]:
    alarms = [Alarm("WAN_ROUTER_01", "Environment Alert", "CRITICAL")]

root_cause = None
inference_result = None
reason = ""

if alarms:
    engine = CausalInferenceEngine(TOPOLOGY)
    res = engine.analyze_alarms(alarms)
    root_cause = res.root_cause_node
    reason = res.root_cause_reason

# --- メイン画面 ---
col1, col2 = st.columns([1, 1])

# 左カラム
with col1:
    st.subheader("Network Status")
    st.graphviz_chart(render_topology(alarms, root_cause), use_container_width=True)
    
    if root_cause:
        st.markdown(f'<div style="color:#d32f2f;background:#fdecea;padding:10px;border-radius:5px;">🚨 緊急アラート：{root_cause.id} ダウン</div>', unsafe_allow_html=True)
        st.caption(f"理由: {reason}")
    
    is_live_mode = ("[Live]" in selected_scenario)
    
    if is_live_mode or root_cause:
        st.markdown("---")
        st.info("🛠 **自律調査エージェント**")
        
        if st.button("🚀 診断実行 (Auto-Diagnostic)", type="primary"):
            if not api_key:
                st.error("API Key Required")
            else:
