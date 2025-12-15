import pandas as pd
import os

class BayesianRCA:
    def __init__(self, topology_nodes=None):
        self.likelihood_matrix = None
        self.priors = {}
        self.candidates = []
        
        # データセットの確認と学習実行
        csv_path = "training_data.csv"
        
        # もしCSVがなければ、初回のみ自動生成する
        if not os.path.exists(csv_path):
            try:
                from mock_data_gen import generate_mock_data
                generate_mock_data()
            except ImportError:
                print("Warning: mock_data_gen.py not found.")
        
        if os.path.exists(csv_path):
            self.train(csv_path)
        else:
            print("Error: Training data missing.")

    def train(self, csv_path):
        """
        Learning Phase: 過去データから尤度 P(E|H) を学習する
        """
        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            print(f"Training failed: {e}")
            return

        # 証拠キーを作成 (例: "log::Interface Down")
        df["EvidenceKey"] = df["EvidenceType"] + "::" + df["EvidenceValue"]
        
        # 1. 事前確率 P(H) の計算
        root_counts = df["RootCause"].value_counts(normalize=True)
        self.priors = root_counts.to_dict()
        
        # 候補リストの初期化
        self.candidates = []
        for rc, prob in self.priors.items():
            parts = rc.split("::")
            self.candidates.append({
                "id": parts[0],
                "type": parts[1] if len(parts) > 1 else "Unknown",
                "key": rc,
                "prob": prob # 初期値は事前確率
            })

        # 2. 尤度行列 P(E|H) の計算 (Pandasのクロス集計)
        # 行: 証拠(Evidence), 列: 原因(RootCause)
        crosstab = pd.crosstab(df["EvidenceKey"], df["RootCause"])
        
        # ラプラススムージング (未知のデータが来ても確率0にしない処理)
        alpha = 1.0
        num_evidence_types = len(crosstab.index)
        root_cause_totals = df["RootCause"].value_counts()
        
        # ベイズの尤度計算式: (観測回数 + α) / (原因の総発生回数 + α * 証拠の種類数)
        self.likelihood_matrix = (crosstab + alpha).div(root_cause_totals + alpha * num_evidence_types, axis=1)
        
        # 参照用に転置 (行:原因, 列:証拠)
        self.likelihood_matrix = self.likelihood_matrix.T
        print("✅ Bayesian Model Trained successfully.")

    def update_probabilities(self, evidence_type, evidence_value):
        """
        Inference Phase: 新しい証拠に基づいて確率を更新 (Posterior Update)
        """
        if self.likelihood_matrix is None: return

        ev_key = f"{evidence_type}::{evidence_value}"
        
        # 学習データに存在しない未知の証拠はスキップ
        if ev_key not in self.likelihood_matrix.columns:
            return

        denom = 0.0
        
        for cand in self.candidates:
            h_key = cand["key"]
            
            # P(E|H): 学習した尤度を取得
            likelihood = self.likelihood_matrix.at[h_key, ev_key]
            
            # ベイズ更新: P(H|E) ∝ P(E|H) * P(H)
            cand["prob"] = likelihood * cand["prob"]
            denom += cand["prob"]

        # 正規化 (合計を1.0にする)
        if denom > 0:
            for cand in self.candidates:
                cand["prob"] /= denom

    def get_ranking(self):
        """確率の高い順にソートして返す（ダッシュボード表示用）"""
        return sorted(self.candidates, key=lambda x: x["prob"], reverse=True)
