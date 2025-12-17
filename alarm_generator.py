# -*- coding: utf-8 -*-
"""
アラーム生成モジュール
各シナリオに応じた適切なアラームを生成する
"""

from typing import List, Dict, Any
from logic import Alarm, simulate_cascade_failure

def generate_alarms_for_scenario(topology: Dict[str, Any], scenario: str) -> List[Alarm]:
    """
    シナリオに応じたアラームを生成する統一関数
    
    Args:
        topology: ネットワークトポロジー
        scenario: 選択されたシナリオ名
    
    Returns:
        生成されたアラームのリスト
    """
    
    # 正常稼働やLive診断の場合は空リスト
    if "正常" in scenario or "---" in scenario or "[Live]" in scenario:
        return []
    
    # シナリオ別のアラーム生成ロジック
    if "WAN全回線断" in scenario:
        return _generate_wan_outage_alarms(topology)
    
    elif "FW片系障害" in scenario:
        return _generate_fw_single_failure_alarms(topology)
    
    elif "L2SWサイレント障害" in scenario:
        return _generate_l2sw_silent_failure_alarms(topology)
    
    elif "複合障害" in scenario:
        return _generate_complex_failure_alarms(topology, scenario)
    
    elif "同時多発" in scenario:
        return _generate_simultaneous_alarms(topology)
    
    # デバイス特定のシナリオ
    else:
        return _generate_device_specific_alarms(topology, scenario)


def _find_node_by_type(topology: Dict, node_type: str, layer: int = None) -> str:
    """ノードタイプでデバイスを検索"""
    for node_id, node in topology.items():
        if hasattr(node, 'type') and str(node.type) == node_type:
            if layer is None or (hasattr(node, 'layer') and node.layer == layer):
                return node_id
    return None


def _generate_wan_outage_alarms(topology: Dict) -> List[Alarm]:
    """WAN全回線断のアラーム生成"""
    router_id = _find_node_by_type(topology, "ROUTER")
    if router_id:
        return simulate_cascade_failure(router_id, topology, "Power Supply: Dual Loss (Device Down)")
    return []


def _generate_fw_single_failure_alarms(topology: Dict) -> List[Alarm]:
    """FW片系障害のアラーム生成（ハザーダス状態を明確に）"""
    fw_id = _find_node_by_type(topology, "FIREWALL")
    if fw_id:
        return [
            Alarm(fw_id, "Heartbeat Loss", "WARNING"),
            Alarm(fw_id, "HA State: Degraded (Single Point of Failure)", "WARNING"),
            Alarm(fw_id, "Redundancy Lost - Immediate Action Required", "WARNING")
        ]
    return []


def _generate_l2sw_silent_failure_alarms(topology: Dict) -> List[Alarm]:
    """L2SWサイレント障害のアラーム生成"""
    l2sw_id = None
    
    # L2スイッチを探す（複数の命名パターンに対応）
    for pattern in ["L2_SW_01", "L2_SW_B01", "L2_SW"]:
        for node_id in topology:
            if pattern in node_id:
                l2sw_id = node_id
                break
        if l2sw_id:
            break
    
    # それでもない場合はSWITCHでlayer=4を探す
    if not l2sw_id:
        l2sw_id = _find_node_by_type(topology, "SWITCH", layer=4)
    
    if l2sw_id and l2sw_id in topology:
        # 配下のAPやデバイスのアラームを生成
        child_alarms = []
        for node_id, node in topology.items():
            if hasattr(node, 'parent_id') and node.parent_id == l2sw_id:
                child_alarms.append(Alarm(node_id, "Connection Lost", "CRITICAL"))
        
        # 配下が見つからない場合はAPを直接探す
        if not child_alarms:
            for node_id, node in topology.items():
                if hasattr(node, 'type') and "ACCESS_POINT" in str(node.type):
                    child_alarms.append(Alarm(node_id, "Connection Lost", "CRITICAL"))
                    if len(child_alarms) >= 4:  # 最大4台まで
                        break
        
        return child_alarms
    
    return []


def _generate_complex_failure_alarms(topology: Dict, scenario: str) -> List[Alarm]:
    """複合障害のアラーム生成"""
    router_id = _find_node_by_type(topology, "ROUTER")
    if router_id:
        return [
            Alarm(router_id, "Power Supply 1 Failed", "CRITICAL"),
            Alarm(router_id, "Fan Module Failed", "WARNING"),
            Alarm(router_id, "Temperature Critical", "WARNING")
        ]
    return []


def _generate_simultaneous_alarms(topology: Dict) -> List[Alarm]:
    """同時多発障害のアラーム生成"""
    alarms = []
    
    fw_id = _find_node_by_type(topology, "FIREWALL")
    if fw_id:
        alarms.append(Alarm(fw_id, "Heartbeat Loss", "WARNING"))
    
    ap_id = _find_node_by_type(topology, "ACCESS_POINT")
    if ap_id:
        alarms.append(Alarm(ap_id, "Connection Lost", "CRITICAL"))
    
    return alarms


def _generate_device_specific_alarms(topology: Dict, scenario: str) -> List[Alarm]:
    """デバイス固有のシナリオアラーム生成"""
    
    # ターゲットデバイスの特定
    target_id = None
    
    if "[WAN]" in scenario:
        target_id = _find_node_by_type(topology, "ROUTER")
    elif "[FW]" in scenario:
        target_id = _find_node_by_type(topology, "FIREWALL")
    elif "[L2SW]" in scenario:
        target_id = _find_node_by_type(topology, "SWITCH", layer=4)
        if not target_id:
            # L2_SW naming patternを試す
            for node_id in topology:
                if "L2_SW" in node_id:
                    target_id = node_id
                    break
    
    if not target_id:
        return []
    
    # 障害タイプ別のアラーム生成
    alarms = []
    
    if "電源障害：片系" in scenario:
        alarms = [
            Alarm(target_id, "Power Supply 1 Failed", "WARNING"),
            Alarm(target_id, "Redundancy Degraded", "WARNING")
        ]
        # FWの場合は追加のHA警告
        if "[FW]" in scenario:
            alarms.append(Alarm(target_id, "HA State: Degraded", "WARNING"))
    
    elif "電源障害：両系" in scenario:
        if "[FW]" in scenario:
            # FWは両系でも冗長があれば少し持ちこたえる可能性
            alarms = [
                Alarm(target_id, "Power Supply: Dual Loss", "CRITICAL"),
                Alarm(target_id, "Device Critical", "CRITICAL")
            ]
        else:
            # 他のデバイスはカスケード障害
            return simulate_cascade_failure(target_id, topology, "Power Supply: Dual Loss (Device Down)")
    
    elif "FAN故障" in scenario:
        alarms = [
            Alarm(target_id, "Fan Module Failed", "WARNING"),
            Alarm(target_id, "Temperature Rising", "WARNING")
        ]
    
    elif "メモリリーク" in scenario:
        alarms = [
            Alarm(target_id, "Memory High (85% utilized)", "WARNING"),
            Alarm(target_id, "Process: bgpd consuming excessive memory", "WARNING")
        ]
    
    elif "BGP" in scenario:
        alarms = [
            Alarm(target_id, "BGP Neighbor Down/Up Flapping", "WARNING"),
            Alarm(target_id, "Routing Table Unstable", "WARNING")
        ]
    
    return alarms
