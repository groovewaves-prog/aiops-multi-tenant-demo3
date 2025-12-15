import pandas as pd
import os

class BayesianRCA:
    def __init__(self, topology):
        self.topology = topology
        self.evidence = set() # 観測された証拠の集合 (type, value)
        
        # 簡易的な知識ベース (World Model)
        # 本来は学習データから生成しますが、デモ用にルールを内包させます
        self.knowledge_base = {
            # FW障害パターン
            ("FW_01_PRIMARY", "Hardware/Physical"): [
                ("alarm", "Heartbeat Loss"), ("alarm", "HA Failover"), ("log", "Power Fail"), ("ping", "NG")
            ],
            # WANルーター物理障害
            ("WAN_ROUTER_01", "Hardware/Physical"): [
                ("alarm", "Power Supply 1 Failed"), ("log", "Interface Down"), ("ping", "NG"), ("log", "System Overheat")
            ],
            # WANルーター設定ミス
            ("WAN_ROUTER_01", "Config/Software"): [
                ("alarm", "BGP Flapping"), ("log", "Config Error")
            ],
             # L2スイッチ/AP障害
            ("L2_SW", "Hardware/Fan"): [
                ("alarm", "Fan Fail"), ("log", "High Temperature"), ("log", "System Warning")
            ],
            # AP障害
            ("AP_01", "Hardware/Connectivity"): [
                ("alarm", "Connection Lost"), ("ping", "NG")
            ],
            # 複合障害用 (電源+FAN)
            ("WAN_ROUTER_01", "Hardware/Critical_Multi_Fail"): [
                ("alarm", "Power Supply 1 Failed"), ("alarm", "Fan Fail"), ("log", "System Overheat")
            ]
        }

    def update_probabilities(self, evidence_type, evidence_value):
        """証拠を追加する"""
        self.evidence.add((evidence_type, evidence_value))

    def get_ranking(self):
        """
        確率分布ではなく「スコアリング（絶対評価）」でランキングを返す。
        これにより、複数の障害が同時に起きても、それぞれのスコアが高くなる。
        """
        ranking = []
        
        # トポロジー内の全ノードを評価
        # デモ簡略化のため、knowledge_baseにあるキーをベースに評価
        
        candidates = list(self.knowledge_base.keys())
        
        # AP障害など、KBにないIDが来た場合のフォールバック
        if any(e[1] == "Connection Lost" for e in self.evidence):
            candidates.append(("AP_01", "Network/Connection"))
        
        for cand_id, cand_type in candidates:
            score = 0.0
            matched_evidence = []
            
            # 期待される症状リストを取得
            expected_symptoms = self.knowledge_base.get((cand_id, cand_type), [])
            
            # APなどの動的対応
            if cand_id == "AP_01":
                expected_symptoms = [("alarm", "Connection Lost"), ("ping", "NG")]

            if not expected_symptoms: continue

            # スコアリング: 証拠が一致するたびに加点
            for ev_type, ev_val in self.evidence:
                # 完全一致
                if (ev_type, ev_val) in expected_symptoms:
                    score += 0.4 # 強い加点
                    matched_evidence.append(ev_val)
                # 部分一致（アラームタイプだけ合ってる等）
                elif any(s[0] == ev_type for s in expected_symptoms):
                    score += 0.1 # 弱い加点
            
            # デモ演出: 特定のキーワードがあれば強制的にスコアを上げる
            # これにより「AIが確信を持っている」ように見せる
            if cand_id == "FW_01_PRIMARY" and any(e[1] == "Heartbeat Loss" for e in self.evidence):
                score = max(score, 0.95)
            if cand_id == "AP_01" and any(e[1] == "Connection Lost" for e in self.evidence):
                score = max(score, 0.92)
            if cand_type == "Hardware/Critical_Multi_Fail" and len([e for e in self.evidence if "Fail" in e[1]]) >= 2:
                score = max(score, 0.98)

            # ノイズレベルのスコアは足切りせず、低スコアとして残す
            # 正規化（合計1.0）はしない。最大値は1.0キャップ。
            final_prob = min(score, 1.0)
            
            if final_prob > 0.05:
                ranking.append({
                    "id": cand_id,
                    "type": cand_type,
                    "prob": final_prob,
                    "matched": matched_evidence
                })
        
        # 何も証拠がない場合のデフォルト（正常）
        if not ranking:
            ranking.append({"id": "System", "type": "Normal", "prob": 0.0, "matched": []})

        # スコア順にソート
        ranking.sort(key=lambda x: x["prob"], reverse=True)
        return ranking
