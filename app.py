# -*- coding: utf-8 -*-
"""
app_cards_multitenant_v2_statusboard.py

目的:
- 既存の「AIOps インシデント・コックピット」のデザイン/構造を壊さずに、
  画面上部へ「全社一覧」を“信号機ボード型（Down/Degraded/Watch/Good の4列）”で追加する。
- tenants/ + registry.py を使ったマルチテナント集計に対応。
- HTML/CSS を使わず、Streamlit標準コンポーネントと絵文字で視認性を上げる。

使い方:
- このファイルを app.py にリネームして置き換えてください。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Optional

import streamlit as st

from inference_engine import LogicalRCA
from logic import simulate_cascade_failure

from registry import (
    list_tenants,
    list_networks,
    get_paths,
    load_topology,
    topology_mtime,
)


st.set_page_config(page_title="AIOps Incident Cockpit", layout="wide")


@dataclass(frozen=True)
class ScopePaths:
    topology_path: Path
    config_dir: Path


def _node_type(node: Any) -> str:
    if node is None:
        return "UNKNOWN"
    if isinstance(node, dict):
        return str(node.get("type", "UNKNOWN"))
    return str(getattr(node, "type", "UNKNOWN"))


def _node_layer(node: Any) -> int:
    if node is None:
        return 999
    if isinstance(node, dict):
        try:
            return int(node.get("layer", 999))
        except Exception:
            return 999
    return int(getattr(node, "layer", 999))


def find_target_node_id(
    topology: Dict[str, Any],
    node_type: Optional[str] = None,
    layer: Optional[int] = None,
) -> Optional[str]:
    for node_id, node in topology.items():
        if node_type and _node_type(node) != node_type:
            continue
        if layer is not None and _node_layer(node) != layer:
            continue
        return node_id
    return None


def _make_alarms(topology: Dict[str, Any], scenario: str):
    if scenario == "WAN全回線断":
        nid = find_target_node_id(topology, node_type="ROUTER")
        return simulate_cascade_failure(nid, topology) if nid else []
    if scenario == "FW片系障害":
        nid = find_target_node_id(topology, node_type="FIREWALL")
        return simulate_cascade_failure(nid, topology, "Power Supply: Single Loss") if nid else []
    if scenario == "L2SWサイレント障害":
        nid = find_target_node_id(topology, node_type="SWITCH", layer=4)
        return simulate_cascade_failure(nid, topology, "Link Degraded") if nid else []
    return []


def _health_from_alarm_count(n: int) -> str:
    if n == 0:
        return "Good"
    if n < 5:
        return "Watch"
    if n < 15:
        return "Degraded"
    return "Down"


def _health_badge(health: str) -> str:
    if health == "Down":
        return "🟥 Down"
    if health == "Degraded":
        return "🟧 Degraded"
    if health == "Watch":
        return "🟨 Watch"
    return "🟩 Good"


@st.cache_data(show_spinner=False)
def _summarize_one_scope(tenant_id: str, network_id: str, scenario: str, mtime: float) -> Dict[str, Any]:
    paths = get_paths(tenant_id, network_id)
    topology = load_topology(paths.topology_path)

    alarms = _make_alarms(topology, scenario)
    alarm_count = len(alarms)
    health = _health_from_alarm_count(alarm_count)

    suspected = None
    if alarms:
        try:
            rca = LogicalRCA(topology, config_dir=str(paths.config_dir))
            res = rca.analyze(alarms) or []
            if res and isinstance(res, list) and isinstance(res[0], dict):
                suspected = res[0].get("id")
        except Exception:
            suspected = None

    return {
        "tenant": tenant_id,
        "network": network_id,
        "health": health,
        "alarms": alarm_count,
        "suspected": suspected,
    }


def _collect_all_scopes(scenario: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for t in list_tenants():
        for n in list_networks(t):
            p = get_paths(t, n)
            rows.append(_summarize_one_scope(t, n, scenario, topology_mtime(p.topology_path)))
    return rows


def _render_status_board(rows: List[Dict[str, Any]]):
    st.subheader("🏢 全社一覧")
    st.caption("左ほど優先度が高い（Down → Degraded → Watch → Good）。クリック操作は不要の“俯瞰ボード”です。")

    buckets = {"Down": [], "Degraded": [], "Watch": [], "Good": []}
    for r in rows:
        buckets[r["health"]].append(r)

    col_down, col_degraded, col_watch, col_good = st.columns(4)

    def _render_bucket(col, health_key: str):
        items = buckets[health_key]
        items.sort(key=lambda x: x["alarms"], reverse=True)

        with col:
            st.markdown(f"### {_health_badge(health_key)}  **{len(items)}**")
            if not items:
                st.caption("（該当なし）")
                return

            max_show = 8
            for r in items[:max_show]:
                st.write(f"**{r['tenant']} / {r['network']}**")
                meta = f"Alarms: **{r['alarms']}**"
                if r.get("suspected"):
                    meta += f"  ·  Suspected: `{r['suspected']}`"
                st.caption(meta)
                st.divider()

            if len(items) > max_show:
                st.caption(f"…他 {len(items) - max_show} 件（表示は上位 {max_show} 件）")

    _render_bucket(col_down, "Down")
    _render_bucket(col_degraded, "Degraded")
    _render_bucket(col_watch, "Watch")
    _render_bucket(col_good, "Good")


# Sidebar
st.sidebar.markdown("### ⚡ Scenario Controller")
selected_scenario = st.sidebar.radio(
    "発生シナリオ",
    ["正常稼働", "WAN全回線断", "FW片系障害", "L2SWサイレント障害"],
)

tenants = list_tenants()
tenant_id = st.sidebar.selectbox("Tenant", tenants, index=0)

networks = list_networks(tenant_id)
network_id = st.sidebar.selectbox("Network", networks, index=0)

# Top: status board
all_rows = _collect_all_scopes(selected_scenario)
_render_status_board(all_rows)

st.markdown("---")

# Below: keep your original cockpit UI by pasting it here.
# (This file intentionally focuses on Step1 UI only.)
st.header("🛡️ AIOps インシデント・コックピット")
st.info("ここから下は、元の app.py のコックピット描画ブロックをそのまま貼り付けてください（Step1 の実装に集中しているため）。")
