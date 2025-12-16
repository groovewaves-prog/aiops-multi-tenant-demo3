# -*- coding: utf-8 -*-
"""
Antigravity Autonomous Agent
Multi-tenant AIOps Demo
- All Companies View at TOP
- Single-tenant Incident Cockpit below

NOTE:
- logic.py exports simulate_cascade_failure, but find_target_node_id is defined here
  (it existed in the original app.py in this repo).
"""

from pathlib import Path
import streamlit as st

from registry import (
    list_tenants,
    list_networks,
    get_paths,
    load_topology,
    topology_mtime,
)
from inference_engine import LogicalRCA
from logic import simulate_cascade_failure


# =====================
# Page Config
# =====================
st.set_page_config(page_title="Antigravity Autonomous Agent", layout="wide")


# =====================
# Topology helper (kept local: existed in original app.py)
# =====================
def find_target_node_id(topology, node_type=None, layer=None, keyword=None):
    """トポロジーから条件に合うノードIDを検索"""
    for node_id, node in topology.items():
        if node_type and node.type != node_type:
            continue
        if layer and node.layer != layer:
            continue
        if keyword:
            hit = False
            if keyword in node_id:
                hit = True
            for v in node.metadata.values():
                if isinstance(v, str) and keyword in v:
                    hit = True
            if not hit:
                continue
        return node_id
    return None


# =====================
# Scope helpers
# =====================
def _reset_for_scope_change():
    for k in ["logic_engine", "last_alarm_count", "cached_root_cause"]:
        if k in st.session_state:
            del st.session_state[k]


def _get_scope():
    tenants = list_tenants()
    if "tenant_id" not in st.session_state:
        st.session_state.tenant_id = tenants[0]

    tenant_id = st.sidebar.selectbox(
        "Tenant",
        tenants,
        index=tenants.index(st.session_state.tenant_id),
        key="tenant_id",
        on_change=_reset_for_scope_change,
    )

    networks = list_networks(tenant_id)
    if "network_id" not in st.session_state:
        st.session_state.network_id = networks[0]

    network_id = st.sidebar.selectbox(
        "Network",
        networks,
        index=networks.index(st.session_state.network_id),
        key="network_id",
        on_change=_reset_for_scope_change,
    )
    return tenant_id, network_id


@st.cache_data(show_spinner=False)
def _load_topology_cached(path: str, mtime: float):
    return load_topology(Path(path))


# =====================
# Sidebar: Scenario
# =====================
st.sidebar.markdown("### ⚡ Scenario Controller")
selected_scenario = st.sidebar.radio(
    "発生シナリオ",
    ["正常稼働", "WAN全回線断", "FW片系障害", "L2SWサイレント障害"],
)


# =====================
# Title
# =====================
st.title("⚡ Antigravity Autonomous Agent")


# ==========================================================
# All Companies View (TOP)
# ==========================================================
@st.cache_data(show_spinner=False)
def summarize_scope(tenant_id, network_id, scenario, mtime):
    paths = get_paths(tenant_id, network_id)
    topology = load_topology(paths.topology_path)
    alarms = []

    if scenario == "WAN全回線断":
        nid = find_target_node_id(topology, node_type="ROUTER")
        if nid:
            alarms = simulate_cascade_failure(nid, topology)
    elif scenario == "FW片系障害":
        nid = find_target_node_id(topology, node_type="FIREWALL")
        if nid:
            alarms = simulate_cascade_failure(nid, topology, "Power Supply: Single Loss")
    elif scenario == "L2SWサイレント障害":
        nid = find_target_node_id(topology, node_type="SWITCH", layer=4)
        if nid:
            alarms = simulate_cascade_failure(nid, topology, "Link Degraded")

    count = len(alarms)
    if count == 0:
        health = "Good"
    elif count < 5:
        health = "Watch"
    elif count < 15:
        health = "Degraded"
    else:
        health = "Down"

    suspected = None
    if alarms:
        try:
            rca = LogicalRCA(topology, config_dir=str(paths.config_dir))
            result = rca.run_rca(alarms)
            if result:
                suspected = result[0]
        except Exception:
            suspected = None

    return {
        "tenant": tenant_id,
        "network": network_id,
        "health": health,
        "alarms": count,
        "suspected": suspected,
    }


def render_all_companies_view(scenario):
    st.subheader("🏢 All Companies View")

    rows = []
    for t in list_tenants():
        for n in list_networks(t):
            p = get_paths(t, n)
            rows.append(
                summarize_scope(t, n, scenario, topology_mtime(p.topology_path))
            )

    rows.sort(key=lambda r: r["alarms"], reverse=True)

    for r in rows[:10]:
        c1, c2, c3, c4 = st.columns([2, 2, 2, 2])
        c1.write(f"**{r['tenant']} / {r['network']}**")
        c2.write(r["health"])
        c3.write(f"Alarms: {r['alarms']}")
        c4.write(f"Suspected: {r['suspected'] or '-'}")

    st.divider()


render_all_companies_view(selected_scenario)


# ==========================================================
# Incident Cockpit (Single Tenant)
# ==========================================================
tenant_id, network_id = _get_scope()
paths = get_paths(tenant_id, network_id)

topology = _load_topology_cached(
    str(paths.topology_path),
    topology_mtime(paths.topology_path),
)
config_dir = str(paths.config_dir)

st.header("🛡️ AIOps インシデント・コックピット")

alarms = []
if selected_scenario == "WAN全回線断":
    nid = find_target_node_id(topology, node_type="ROUTER")
    if nid:
        alarms = simulate_cascade_failure(nid, topology)
elif selected_scenario == "FW片系障害":
    nid = find_target_node_id(topology, node_type="FIREWALL")
    if nid:
        alarms = simulate_cascade_failure(nid, topology, "Power Supply: Single Loss")
elif selected_scenario == "L2SWサイレント障害":
    nid = find_target_node_id(topology, node_type="SWITCH", layer=4)
    if nid:
        alarms = simulate_cascade_failure(nid, topology, "Link Degraded")

st.metric("処理アラーム数", len(alarms))

if alarms:
    rca = LogicalRCA(topology, config_dir=config_dir)
    analysis_results = rca.run_rca(alarms)

    st.subheader("🔎 推定根本原因")
    for i, r in enumerate(analysis_results[:5], 1):
        st.write(f"{i}. {r}")
else:
    st.success("現在、アクティブなインシデントはありません。")
