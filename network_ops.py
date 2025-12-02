"""
Google Antigravity AIOps Agent - Network Operations Module (AI Generative Simulator)
シナリオに基づき、Google Gemini 2.0 Flash が動的に「擬似障害ログ」を生成します。
これにより、人間がテストデータを作成する手間をゼロにします。
"""
import re
import os
import time
import google.generativeai as genai

# 実機接続情報 (Liveモード用)
SANDBOX_DEVICE = {
    'device_type': 'cisco_nxos',
    'host': 'sandbox-nxos-1.cisco.com',
    'username': 'admin',
    'password': 'Admin_1234!',
    'port': 22,
    'global_delay_factor': 2,
    'banner_timeout': 30,
    'conn_timeout': 30,
}

def sanitize_output(text: str) -> str:
    """機密情報のマスク処理"""
    rules = [
        (r'(password|secret) \d+ \S+', r'\1 <HIDDEN_PASSWORD>'),
        (r'(encrypted password) \S+', r'\1 <HIDDEN_PASSWORD>'),
        (r'(snmp-server community) \S+', r'\1 <HIDDEN_COMMUNITY>'),
        (r'(username \S+ privilege \d+ secret \d+) \S+', r'\1 <HIDDEN_SECRET>'),
        (r'\b(?!(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.)\d{1,3}\.(?:\d{1,3}\.){2}\d{1,3}\b', '<MASKED_PUBLIC_IP>'),
        (r'([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}', '<MASKED_MAC>'),
    ]
    for pattern, replacement in rules:
        text = re.sub(pattern, replacement, text)
    return text

def generate_fake_log_by_ai(scenario_name, api_key):
    """
    【核心機能】シナリオ名から、それっぽい実機ログをAIに捏造させる
    """
    if not api_key:
        return "Error: API Key is required for Generative Simulation."

    genai.configure(api_key=api_key)
    # 高速なFlashモデルを使用
    model = genai.GenerativeModel("gemini-2.0-flash")

    prompt = f"""
    あなたはCiscoネットワーク機器のシミュレーター（CLI）です。
    以下の障害シナリオが発生している時の、エンジニアが調査で叩きそうなコマンドとその実行結果（ログ）を生成してください。

    **発生シナリオ**: {scenario_name}
    **対象機器**: Cisco IOS Router (WAN_ROUTER_01)

    【制約事項】
    1. 解説や説明文は一切不要です。CLIの生ログのみを出力してください。
    2. `show version`, `show logging`, `show environment` 関連など、その障害の特定に必要なコマンドを含めてください。
    3. ログの中には、障害を示唆するエラーメッセージ（%BGP-5-ADJCHANGE, %ENVMON-3-FAN_FAILED 等）を必ず含めてください。
    4. 嘘のパスワードやIPアドレスを含めて、リアリティを出してください（後でサニタイズ機能のテストに使います）。
    """

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"AI Generation Failed: {str(e)}"

def run_diagnostic_simulation(scenario_type, api_key=None):
    """
    診断シミュレーション実行関数
    """
    time.sleep(1.5) # 処理中演出
    
    status = "SUCCESS"
    raw_output = ""
    error_msg = None

    # --- 接続不能系（AIにログを書かせるまでもなくタイムアウト） ---
    if "全回線断" in scenario_type or "サイレント" in scenario_type:
        status = "ERROR"
        error_msg = "Connection timed out (Host unreachable)"
        raw_output = f"SSH connection to target failed.\nICMP Ping failed.\nScenario: {scenario_type}"

    # --- 実機接続モード ---
    elif "[Live]" in scenario_type:
        # (netmikoのインポートはここで行い、ライブラリがない場合のエラーを回避してもよい)
        from netmiko import ConnectHandler
        commands = ["terminal length 0", "show version", "show interface brief"]
        try:
            with ConnectHandler(**SANDBOX_DEVICE) as ssh:
                if not ssh.check_enable_mode(): ssh.enable()
                prompt = ssh.find_prompt()
                raw_output += f"Connected to: {prompt}\n"
                for cmd in commands:
                    output = ssh.send_command(cmd)
                    raw_output += f"\n{'='*30}\n[Command] {cmd}\n{output}\n"
        except Exception as e:
            status = "ERROR"
            error_msg = str(e)
            raw_output = f"Real Device Connection Failed: {error_msg}"

    # --- その他の障害（BGP, FAN, 電源, メモリなど） ---
    else:
        # ★ここでAIにログを捏造させる
        # FW片系障害なども含め、すべてAI生成に任せる
        if api_key:
            raw_output = generate_fake_log_by_ai(scenario_type, api_key)
        else:
            status = "ERROR"
            error_msg = "API Key Missing for Simulation"
            raw_output = "API Key required to generate fake logs."

    return {
        "status": status,
        "sanitized_log": sanitize_output(raw_output),
        "error": error_msg
    }
