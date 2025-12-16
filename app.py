# -*- coding: utf-8 -*-
"""
app_cards_multitenant_v4_statusboard_delta_maint_scroll.py

- 状態ボード（停止 → 劣化 → 要注意 → 正常）
- デルタ表示（変化があった会社だけ）
- Maintenance グレーアウト（最小版：手動フラグ）
- “行数が増えすぎる”対策：各列をスクロール可能な表（st.dataframe）で表示

注意:
- HTML/CSSは使いません（Streamlit標準のみ）。
- 下段の「AIOpsインシデント・コックピット」は、元の app.py からそのまま貼り付けて復活してください。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pandas as pd
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

# -----------------------------
# Page config
# -----------------------------
st.set_page_config(page_title="AIOps Incident Cockpit", layout="wide")

# -----------------------------
# Labels (JP)
# -----------------------------
STATUS_ORDER = ["停止", "劣化", "要注意", "正常"]  # 左→右（優先度が高い順）
STATUS_LABELS = {"Down": "停止", "Degraded": "劣化", "Watch": "要注意", "Good": "正常"}
STATUS_ICON = {"停止": "🟥", "劣化": "🟧", "要注意": "🟨", "正常": "🟩"}

DELTA_WINDOW_MIN = 15
MAX_ROWS_PER_BUCKET = 200  # 将来スケールの安全弁（UI保護）

# -----------------------------
# Scenario map（元の app.py のバリエーションに復帰）
# - ただし、状態ボード/デモの障害生成は「主要3シナリオ + 正常稼働」のみに紐づけ
# -----------------------------
SCENARIO_MAP = {
    "基本・広域障害": [
        "正常稼働",
        "1. WAN全回線断",
        "2. FW片系障害",
        "3. L2SWサイレント障害",
        "4. AP群断（エッジ異常）",
        "5. DC回線遅延（品質劣化）",
        "6. BGP不安定（断続障害）",
    ],
    "クラウド/アプリ": [
        "10. [Cloud] DNS障害（名前解決不可）",
        "11. [Cloud] APIレート制限（429）",
        "12. [App] 認証障害（Login失敗）",
        "13. [App] DB遅延（P95悪化）",
    ],
    "セキュリティ/運用": [
        "20. [Sec] WAFブロック急増",
        "21. [Sec] 不審ログイン急増",
        "22. [Ops] 計画停止（Maintenance）",
    ],
    "デモ拡張": [
        "99. [Live] Cisco実機診断",
    ],
}


def display_company(tenant_id: str) -> str:
    return f"{tenant_id}社"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
    try:
        return int(getattr(node, "layer", 999))
    except Exception:
        return 999


def _find_target_node_id(
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


def _normalize_scenario(s: str) -> str:
    """SCENARIO_MAPの多様な表現を、デモで扱う主要シナリオに正規化する。"""
    if "WAN全回線断" in s:
        return "WAN全回線断"
    if "FW片系障害" in s or "FW片系" in s:
        return "FW片系障害"
    if "L2SWサイレント障害" in s or "L2SW" in s:
        return "L2SWサイレント障害"
    return "正常稼働"


def _make_alarms(topology: Dict[str, Any], normalized_scenario: str):
    if normalized_scenario == "WAN全回線断":
        nid = _find_target_node_id(topology, node_type="ROUTER")
        return simulate_cascade_failure(nid, topology) if nid else []
    if normalized_scenario == "FW片系障害":
        nid = _find_target_node_id(topology, node_type="FIREWALL")
        return simulate_cascade_failure(nid, topology, "Power Supply: Single Loss") if nid else []
    if normalized_scenario == "L2SWサイレント障害":
        nid = _find_target_node_id(topology, node_type="SWITCH", layer=4)
        return simulate_cascade_failure(nid, topology, "Link Degraded") if nid else []
    return []


def _health_from_alarm_count(n: int) -> str:
    # デモ用閾値（将来はSLO/重要度で差し替え）
    if n == 0:
        return "Good"
    if n < 5:
        return "Watch"
    if n < 15:
        return "Degraded"
    return "Down"


@st.cache_data(show_spinner=False)
def _summarize_one_scope(tenant_id: str, network_id: str, normalized_scenario: str, mtime: float) -> Dict[str, Any]:
    paths = get_paths(tenant_id, network_id)
    topology = load_topology(paths.topology_path)

    alarms = _make_alarms(topology, normalized_scenario)
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
        "health": health,  # internal: Good/Watch/Degraded/Down
        "alarms": alarm_count,
        "suspected": suspected,
    }


def _collect_all_scopes(normalized_scenario: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for t in list_tenants():
        for n in list_networks(t):
            p = get_paths(t, n)
            rows.append(_summarize_one_scope(t, n, normalized_scenario, topology_mtime(p.topology_path)))
    return rows


def _delta_key(r: Dict[str, Any]) -> str:
    return f"{r['tenant']}::{r['network']}"


def _compute_delta(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    session_state に保存された前回値との差分を計算。
    変化がないものは delta=None にして UI 上は出さない（“埋もれない”）。
    """
    if "allco_prev" not in st.session_state:
        st.session_state.allco_prev = {}
        st.session_state.allco_prev_ts = _now_iso()

    prev: Dict[str, Dict[str, Any]] = st.session_state.allco_prev
    out: Dict[str, Dict[str, Any]] = {}

    for r in rows:
        k = _delta_key(r)
        p = prev.get(k)
        if p is None:
            out[k] = {"delta": None}
            continue

        d_alarms = int(r["alarms"]) - int(p.get("alarms", 0))
        d_health = (p.get("health") != r.get("health"))
        if d_alarms == 0 and not d_health:
            out[k] = {"delta": None}
        else:
            out[k] = {
                "delta": {
                    "alarms": d_alarms,
                    "health_changed": d_health,
                    "window_min": DELTA_WINDOW_MIN,
                }
            }

    # 今回値を次回の prev に更新
    st.session_state.allco_prev = { _delta_key(r): {"alarms": r["alarms"], "health": r["health"]} for r in rows }
    st.session_state.allco_prev_ts = _now_iso()
    return out


def _status_jp(health_internal: str) -> str:
    return STATUS_LABELS.get(health_internal, "要注意")


def _status_badge(status_jp: str) -> str:
    return f"{STATUS_ICON.get(status_jp,'🟨')} {status_jp}"


def _maintenance_map() -> Dict[str, bool]:
    if "maint_flags" not in st.session_state:
        st.session_state.maint_flags = {}
    return st.session_state.maint_flags


def _delta_text(delta: Optional[Dict[str, Any]]) -> str:
    if not delta:
        return ""
    da = int(delta["alarms"])
    arrow = "↑" if da > 0 else ("↓" if da < 0 else "•")
    txt = f"{arrow} {da:+d}（{int(delta['window_min'])}分）"
    if delta.get("health_changed"):
        txt += " 状態変化"
    return txt


def _render_bucket_df(items: List[Dict[str, Any]], deltas: Dict[str, Dict[str, Any]], maint: Dict[str, bool]) -> pd.DataFrame:
    out = []
    for r in items[:MAX_ROWS_PER_BUCKET]:
        tenant = r["tenant"]
        network = r["network"]
        k = _delta_key(r)
        delta = deltas.get(k, {}).get("delta")
        is_maint = bool(maint.get(tenant, False))
        out.append(
            {
                "会社/ネットワーク": f"{display_company(tenant)} / {network}",
                "Maintenance": "🛠️" if is_maint else "",
                "Δ": _delta_text(delta) if (delta is not None) else "",
                "Alarms": ("" if is_maint else int(r["alarms"])),
                "Suspected": ("" if is_maint else (r.get("suspected") or "")),
            }
        )
    return pd.DataFrame(out)


def _render_status_board(rows: List[Dict[str, Any]]):
    st.subheader("🏢 全社一覧")
    st.caption("左から優先度が高い順（停止 → 劣化 → 要注意 → 正常）。クリック操作を必要としない 状態ボードです。")

    maint = _maintenance_map()
    deltas = _compute_delta(rows)

    buckets: Dict[str, List[Dict[str, Any]]] = {k: [] for k in STATUS_ORDER}
    for r in rows:
        buckets[_status_jp(r["health"])].append(r)

    # 危険順（左→右）
    col_down, col_degraded, col_watch, col_good = st.columns(4)
    col_map = {"停止": col_down, "劣化": col_degraded, "要注意": col_watch, "正常": col_good}

    for status_jp in STATUS_ORDER:
        items = buckets[status_jp]
        items.sort(key=lambda x: x["alarms"], reverse=True)  # 読み取り速度優先
        with col_map[status_jp]:
            st.markdown(f"### {_status_badge(status_jp)}  **{len(items)}**")

            if not items:
                st.caption("（該当なし）")
                continue

            df = _render_bucket_df(items, deltas, maint)

            # スクロール表示（行数が増えても縦に伸びない）
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                height=360,
            )

            if len(items) > MAX_ROWS_PER_BUCKET:
                st.caption(f"表示件数を {MAX_ROWS_PER_BUCKET} 件に制限しました（将来スケール想定の保護）。")

    with st.expander("🛠️ Maintenance（最小版：手動フラグ）", expanded=False):
        st.caption("将来は計画停止情報の外部連携に置換予定。いまは手動でグレーアウト対象（会社）を指定します。")
        ts = list_tenants()
        selected = st.multiselect(
            "Maintenance 中の会社",
            options=ts,
            default=[t for t in ts if maint.get(t, False)],
            format_func=lambda x: display_company(x),
        )
        st.session_state.maint_flags = {t: (t in selected) for t in ts}


# -----------------------------
# Sidebar (元のバリエーションへ復帰)
# -----------------------------
st.sidebar.markdown("### ⚡ Scenario Controller")

category = st.sidebar.selectbox("対象カテゴリ", list(SCENARIO_MAP.keys()), index=0)
selected_scenario_raw = st.sidebar.radio("発生シナリオ", SCENARIO_MAP[category])
normalized_scenario = _normalize_scenario(selected_scenario_raw)

tenants = list_tenants()
tenant_id = st.sidebar.selectbox(
    "テナント（会社）",
    tenants,
    index=0,
    format_func=lambda x: display_company(x),
)
networks = list_networks(tenant_id)
network_id = st.sidebar.selectbox("ネットワーク", networks, index=0)

# -----------------------------
# Top: All Companies Status Board
# -----------------------------
all_rows = _collect_all_scopes(normalized_scenario)
_render_status_board(all_rows)

st.markdown("---")

# =============================================================================
# Below: Existing "AIOps インシデント・コックピット"
# =============================================================================
st.header("🛡️ AIOps インシデント・コックピット")
st.info("ここから下は、元の app.py のコックピット描画ブロックをそのまま貼り付けてください（表・トポロジ・AI Analyst Report 等）。")
