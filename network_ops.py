"""
Google Antigravity AIOps Agent - Network Operations Module (Stub Version)
実機接続をシミュレーションし、サニタイズ機能を提供します。
"""
import re
import os
import time

def sanitize_output(text: str) -> str:
    """
    セキュリティ対策: 機密情報をマスクする
    """
    # Cisco Type 7 password mask
    text = re.sub(r'(password|secret) \d+ \S+', r'\1 <HIDDEN>', text)
    # SNMP communities
    text = re.sub(r'community \S+', 'community <HIDDEN>', text)
    # Global IP mask (簡易例: 203.0.113.x をマスク)
    text = re.sub(r'203\.0\.113\.\d+', '<Global-IP>', text)
    return text

def run_diagnostic_simulation(scenario_type):
    """
    SSH接続をシミュレーションするスタブ関数
    """
    # 接続している感を出すためのウェイト
    time.sleep(2.0)
    
    status = "SUCCESS"
    raw_output = ""
    error_msg = None

    # シナリオに応じた挙動の分岐
    if scenario_type == "1. WAN全回線断":
        # 完全に落ちている場合 -> SSH接続タイムアウトをシミュレーション
        status = "ERROR"
        error_msg = "Connection timed out (Host unreachable)"
        raw_output = "SSH Connection failed. Target is not responding to Ping/SSH."
        
    elif scenario_type == "4. [Live] Cisco実機診断":
        # ログが取れる場合 -> ファイルから読み込み
        log_path = "logs/sample_cisco_log.txt"
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                raw_output = f.read()
            # ダミーのコマンド実行履歴を付与
            raw_output = f"[Command] show run\n{raw_output}\n[Command] show ip int brief\nInterface GE1: UP/UP"
        else:
            # ファイルがない場合のフォールバック
            raw_output = "hostname WAN_ROUTER_01\npassword 7 999999\n(Dummy Log)"
            
    else:
        # その他のケース
        raw_output = "No diagnostic data available for this scenario."

    return {
        "status": status,
        "sanitized_log": sanitize_output(raw_output),
        "error": error_msg
    }
