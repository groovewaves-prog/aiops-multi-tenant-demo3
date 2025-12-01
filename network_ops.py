"""
Google Antigravity AIOps Agent - Network Operations Module
"""
import re
from netmiko import ConnectHandler

# Cisco DevNet Always-On Sandbox 情報
# 接続を安定させるためのオプションを追加
SANDBOX_DEVICE = {
    'device_type': 'cisco_ios',
    'host': 'sandbox-iosxe-recomm-1.cisco.com', # ホスト名をより安定している推奨サーバーに変更
    'username': 'developer',
    'password': 'C1sco12345',
    'port': 22,
    # 以下、接続安定化のための追加オプション
    'global_delay_factor': 2,       # 通信の待ち時間を通常の2倍に設定
    'conn_timeout': 20,             # 接続タイムアウトを20秒に延長
    'auth_timeout': 20,             # 認証タイムアウトを20秒に延長
    'banner_timeout': 20,           # バナー表示待ちを20秒に延長
}

def sanitize_output(text: str) -> str:
    # パスワードなどをマスク
    text = re.sub(r'(password|secret) \d+ \S+', r'\1 <HIDDEN>', text)
    text = re.sub(r'community \S+', 'community <HIDDEN>', text)
    return text

def run_diagnostic_commands():
    commands = [
        "show version | include Cisco IOS",
        "show ip interface brief",
        "show ip route summary",
    ]
    
    raw_output = ""
    status = "SUCCESS"
    error_msg = None

    try:
        # Netmikoで接続
        with ConnectHandler(**SANDBOX_DEVICE) as ssh:
            ssh.enable()
            for cmd in commands:
                # コマンド送信
                output = ssh.send_command(cmd)
                raw_output += f"\n[Command] {cmd}\n{output}\n"
                
    except Exception as e:
        status = "ERROR"
        error_msg = str(e)
        raw_output = f"SSH Connection Failed: {error_msg}"

    return {
        "status": status,
        "sanitized_log": sanitize_output(raw_output),
        "error": error_msg
    }
