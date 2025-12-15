import streamlit as st
import pandas as pd

def render_intelligent_alarm_viewer(bayes_engine, selected_scenario):
    """
    AIOps時代のインシデント管理ビューアー（日本語版）
    """
    st.markdown("### 🛡️ AIOps インシデント・コックピット")
    
    # 1. KPIメトリクス (AIOpsの効果を一目でわからせる演出)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="📉 ノイズ削減率", value="98.5%", delta="高効率稼働中")
    with col2:
        st.metric(label="📨 処理したアラーム総数", value="154件", delta="-153件 (抑制済)", delta_color="inverse")
    with col3:
        st.metric(label="🚨 要対応インシデント", value="1件", delta="対処が必要")

    st.markdown("---")
    
    # 2. ベイズ推論の結果（ランキング）を取得
    ranking = bayes_engine.get_ranking()
    top_cause = ranking[0]
    
    # 3. 表示用データの整形
    data = []
    for rank, candidate in enumerate(ranking[:4], 1): # 上位4つを表示
        prob = candidate["prob"]
        
        # 確信度に応じた日本語ステータス演出
        if prob > 0.8:
            status = "🔴 危険 (根本原因)"
            action = "🚀 自動修復が可能"
            impact = "大 (全サービス影響)"
            root_cause_text = f"デバイス: {candidate['id']}\n原因種別: {candidate['type']}"
        elif prob > 0.4:
            status = "🟡 警告 (被疑箇所)"
            action = "🔍 詳細調査を推奨"
            impact = "中 (性能低下)"
            root_cause_text = f"デバイス: {candidate['id']}\n原因種別: {candidate['type']}"
        else:
            status = "⚪ 監視中"
            action = "👁️ 静観"
            impact = "小"
            root_cause_text = f"デバイス: {candidate['id']}\n原因種別: {candidate['type']}"

        # リスト用の辞書作成
        data.append({
            "順位": rank,
            "確信度": prob, # 0.0 - 1.0 (プログレスバー用)
            "根本原因分析": root_cause_text,
            "AI診断": status,
            "影響範囲": impact,
            "推奨アクション": action
        })

    df = pd.DataFrame(data)

    # 4. Streamlit Dataframeによるリッチ表示
    st.dataframe(
        df,
        column_order=["順位", "AI診断", "根本原因分析", "確信度", "影響範囲", "推奨アクション"],
        column_config={
            "順位": st.column_config.NumberColumn(
                "#", format="%d", width="small"
            ),
            "AI診断": st.column_config.TextColumn(
                "ステータス", width="medium"
            ),
            "根本原因分析": st.column_config.TextColumn(
                "📌 根本原因候補 (Root Cause)", width="large", help="AIがログ分析から特定した原因候補"
            ),
            "確信度": st.column_config.ProgressColumn(
                "AI確信度スコア",
                format="%.1f",
                min_value=0,
                max_value=1,
                width="medium",
            ),
            "推奨アクション": st.column_config.TextColumn(
                "🤖 Next Action", width="medium"
            ),
            "影響範囲": st.column_config.TextColumn(
                "影響度", width="small"
            ),
        },
        use_container_width=True,
        hide_index=True,
        height=250 # 一覧性を確保
    )
    
    # トップの原因候補を返す（メインロジックでの連携用）
    return top_cause
