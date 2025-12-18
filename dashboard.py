import json
from typing import List, Dict, Any
import streamlit as st

# ==========================================================
# Dashboard 表示ロジック（v3）
# ==========================================================
# 追加要件:
# - inference_engine 側で付与される以下を「詳細」欄にそのまま表示
#     - analyst_report (str)
#     - auto_investigation (list[str])
# ==========================================================

# ----------------------------
# Auto-remediation policy
# ----------------------------
AUTO_REMEDIATION_ALLOWED_IMPACT_TYPES = {
    # 安全に“提案/自動修復”として表示してよい候補（運用で調整）
    "Hardware/Redundancy",
    "Hardware/Degraded",
    "Software/Resource",
}

AUTO_REMEDIATION_BLOCKED_IMPACT_TYPES = {
    # 明確な停止・物理断・サービス断は承認制に寄せる
    "Hardware/Physical",
    "Hardware/Critical_Multi_Fail",
    "Network/Unreachable",
    "Network/SilentFailure",  # サイレント障害は調査が必要
    "OUTAGE",
    "DeviceDown",
    "AI_ERROR",
    "UNKNOWN",
}


def normalize_tier(item: Dict[str, Any]) -> int:
    try:
        t = int(item.get("tier", 3))
        return t if t >= 1 else 3
    except Exception:
        return 3


def sort_key(item: Dict[str, Any]):
    # tier が小さいほど優先、prob が高いほど上
    return (normalize_tier(item), -(float(item.get("prob", 0.0) or 0.0)))


def should_show_auto_remediation(item: Dict[str, Any]) -> bool:
    impact_type = str(item.get("type") or item.get("impact_type") or "UNKNOWN")

    if impact_type in AUTO_REMEDIATION_BLOCKED_IMPACT_TYPES:
        return False
    if impact_type in AUTO_REMEDIATION_ALLOWED_IMPACT_TYPES:
        return True

    # それ以外は安全側に倒す
    return False


def classify_display_status(item: Dict[str, Any]) -> Dict[str, str]:
    # prob を優先して UI の色/文言を決める（tier は優先度表示に使用）
    prob = float(item.get("prob", 0.0) or 0.0)
    impact_type = str(item.get("type") or "UNKNOWN")

    # サイレント障害は黄色扱い（要調査）
    if impact_type == "Network/SilentFailure":
        return {"severity": "🟡 警告 (被疑箇所)", "color": "YELLOW"}

    if prob >= 0.85:
        return {"severity": "🔴 危険 (根本原因)", "color": "RED"}
    if prob >= 0.5:
        return {"severity": "🟡 警告 (被疑箇所)", "color": "YELLOW"}
    return {"severity": "⚪ 監視中", "color": "GRAY"}


def render_details(item: Dict[str, Any]):
    """1件分の詳細欄。LLMの能動調査結果をそのまま表示する。"""
    analyst_report = item.get("analyst_report")
    auto_investigation = item.get("auto_investigation")

    has_any = bool(analyst_report) or bool(auto_investigation)
    title = "🔎 詳細" if has_any else "🔎 詳細（追加情報なし）"

    with st.expander(title, expanded=False):
        if analyst_report:
            st.markdown("**AI Analyst Report**")
            # “そのまま表示” の意図を優先して、整形は最小限にする
            st.code(str(analyst_report), language="text")

        if auto_investigation:
            st.markdown("**推奨・能動調査（提案）**")
            if isinstance(auto_investigation, list):
                for step in auto_investigation:
                    st.markdown(f"- {step}")
            else:
                st.write(auto_investigation)

        # 解析結果の生JSONも必要なら確認できるようにする（運用に便利）
        with st.expander("🧾 Raw JSON", expanded=False):
            st.json(item)


def render_incident_table(results: List[Dict[str, Any]]):
    """
    AIOps インシデント・コックピット表示（tier で折りたたみ）
    """
    st.subheader("🧠 AIOps インシデント・コックピット")

    results = sorted(results, key=sort_key)

    # tier ごとにグルーピング
    tiers: Dict[int, List[Dict[str, Any]]] = {}
    for item in results:
        t = normalize_tier(item)
        tiers.setdefault(t, []).append(item)

    # tier の表示順（小さいほど上位）
    for tier in sorted(tiers.keys()):
        title = f"Tier {tier}（優先度 {'高' if tier == 1 else '中' if tier == 2 else '低'}）"
        expanded = True if tier == 1 else False

        with st.expander(title, expanded=expanded):
            items = tiers[tier]
            for idx, item in enumerate(items, start=1):
                ui = classify_display_status(item)
                auto_flag = "🚀 自動修復が可能" if should_show_auto_remediation(item) else "🧑 手動対応 / 承認が必要"

                st.markdown(
                    f"""**{idx}. {ui['severity']}**  
- デバイス: `{item.get('id')}`  
- 原因: `{item.get('label')}`  
- 確信度: `{item.get('prob')}`  
- 分類: `{item.get('type')}`  
- 理由: {item.get('reason')}  
- 対応: {auto_flag}
"""
                )

                # ここが追加：詳細欄（AI Analyst Report を表示）
                render_details(item)

                st.divider()


def main():
    st.set_page_config(page_title="AIOps Incident Cockpit", layout="wide")

    st.title("🛡️ AIOps インシデント・コックピット")
    st.caption("推論結果 JSON をアップロードして、優先度順に閲覧します（詳細欄に AI Analyst Report を表示）。")

    uploaded = st.file_uploader("解析結果JSONをアップロード", type=["json"])
    if uploaded is None:
        st.info("解析結果 JSON をアップロードすると表示されます。")
        return

    try:
        results = json.load(uploaded)
        if not isinstance(results, list):
            st.error("JSON は配列形式（list）である必要があります。")
            return
        render_incident_table(results)
    except Exception as e:
        st.error(f"JSON 読み込みエラー: {e}")


if __name__ == "__main__":
    main()
