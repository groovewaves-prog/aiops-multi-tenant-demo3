import pandas as pd

class BayesianRCA:
    def __init__(self, topology):
        self.topology = topology
        self.evidence = set() # 観測された証拠 (type, value)
        
        # 知識ベース: 「この障害なら、このアラームが出るはず」という定義
        # ここでは「確率」ではなく「期待される症状のリスト」として扱います
        self.knowledge_base = {
            # --- FW関連 ---
            ("FW_01_PRIMARY", "Hardware/Physical"): [
                ("alarm", "Heartbeat Loss"), 
                ("alarm", "HA Failover"), 
                ("log", "Power Fail"), 
                ("ping", "NG")
            ],
            # --- WANルーター関連 ---
            ("WAN_ROUTER_01", "Hardware/Physical"): [
                ("alarm", "Power Supply 1 Failed"), 
                ("log", "Interface Down"), 
                ("ping", "NG"), 
                ("log", "System Overheat")
            ],
            ("WAN_ROUTER_01", "Config/Software"): [
                ("alarm", "BGP Flapping"), 
                ("log", "Config Error")
            ],
            ("WAN_ROUTER_01", "Hardware/Critical_Multi_Fail"): [
                ("alarm", "Power Supply 1 Failed"), 
                ("alarm", "Fan Fail"), 
                ("log", "System Overheat")
            ],
             # --- L2SW / AP関連 ---
            ("L2_SW", "Hardware/Fan"): [
                ("alarm", "Fan Fail"), 
                ("log", "High Temperature"), 
                ("log", "System Warning")
            ],
            ("AP_01", "Network/Connection"): [
                ("alarm", "Connection Lost"), 
                ("ping", "NG")
            ],
             # --- 外部要因 ---
            ("External_ISP", "Network"): [
                ("alarm", "BGP Flapping"), 
                ("ping", "NG")
            ]
        }

    def update_probabilities(self, evidence_type, evidence_value):
        """証拠を追加する"""
        self.evidence.add((evidence_type, evidence_value))

    def get_ranking(self):
        """
        【修正版ロジック】
        ベイズ確率(合計1.0)ではなく、「症状合致スコア(絶対評価)」で計算する。
        これにより、複合障害時でもスコアが分散せず、両方とも高スコアになる。
        """
        ranking = []
        
        # 評価対象の候補リストを作成
        candidates = list(self.knowledge_base.keys())
        
        # 動的に候補を追加（KBにないIDへの対応）
        # もし証拠の中に "Connection Lost" があれば、AP障害を候補に加える
        if any(e[1] == "Connection Lost" for e in self.evidence):
            if ("AP_01", "Network/Connection") not in candidates:
                candidates.append(("AP_01", "Network/Connection"))

        for cand_id, cand_type in candidates:
            # 1. 期待される症状を取得
            expected_symptoms = self.knowledge_base.get((cand_id, cand_type), [])
            
            # APなどの特別対応
            if cand_id == "AP_01":
                expected_symptoms = [("alarm", "Connection Lost"), ("ping", "NG")]

            if not expected_symptoms: continue

            # 2. スコアリング計算 (満点=1.0を目指す加点方式)
            score = 0.0
            match_count = 0
            
            for ev_type, ev_val in self.evidence:
                # A. 完全一致 (TypeもValueも同じ) -> 大きく加点
                if (ev_type, ev_val) in expected_symptoms:
                    score += 0.4 
                    match_count += 1
                # B. 部分一致 (Typeだけ同じ、あるいは似たアラーム) -> 少し加点
                elif any(s[0] == ev_type for s in expected_symptoms):
                    # アラーム内容が違っても、アラームが出ていること自体が重要なら加点
                    score += 0.05

            # 3. ブーストロジック（デモの演出用）
            # 特定のキーワード（決定的な証拠）がある場合は、スコアを跳ね上げる
            if cand_id == "FW_01_PRIMARY" and any(e[1] == "Heartbeat Loss" for e in self.evidence):
                score += 0.5
            if cand_id == "AP_01" and any(e[1] == "Connection Lost" for e in self.evidence):
                score += 0.5
            if cand_type == "Hardware/Critical_Multi_Fail" and len([e for e in self.evidence if "Fail" in e[1]]) >= 2:
                score += 0.6

            # 4. スコアの正規化（キャップ処理）
            # 確率ではないので、合計が1を超えても良いが、表示用には 1.0 (100%) を上限とする
            final_prob = min(score, 1.0)
            
            # ノイズ除去（スコアが低すぎるものはリストに出さない）
            if final_prob > 0.1:
                ranking.append({
                    "id": cand_id,
                    "type": cand_type,
                    "prob": final_prob,
                    "matched": match_count
                })
        
        # 候補がない場合
        if not ranking:
            ranking.append({"id": "System", "type": "Normal", "prob": 0.0, "matched": 0})

        # スコア順にソート
        ranking.sort(key=lambda x: x["prob"], reverse=True)
        return ranking
