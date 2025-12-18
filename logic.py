# -*- coding: utf-8 -*-
"""
Google Antigravity AIOps Agent - Logic Module (Optimized Final)
因果推論エンジンとアラーム処理を担当するモジュール
"""

import logging
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from data import TOPOLOGY, NetworkNode

# =====================================================
# ロギング設定
# =====================================================
logger = logging.getLogger(__name__)

# =====================================================
# データクラス定義
# =====================================================

@dataclass
class Alarm:
    """
    ネットワークアラームを表現するデータクラス
    """
    device_id: str
    message: str
    severity: str  # CRITICAL, WARNING, INFO
    timestamp: Optional[float] = None
    
    def __post_init__(self):
        """バリデーション"""
        valid_severities = {"CRITICAL", "WARNING", "INFO"}
        if self.severity not in valid_severities:
            logger.warning(
                f"Invalid severity '{self.severity}' for alarm {self.device_id}. "
                f"Valid values: {valid_severities}. Defaulting to 'WARNING'."
            )
            self.severity = "WARNING"
        
        if not self.device_id or not isinstance(self.device_id, str):
            raise ValueError(f"Invalid device_id: {self.device_id}")

@dataclass
class InferenceResult:
    """
    因果推論の結果を表現するデータクラス
    """
    root_cause_node: Optional[NetworkNode]
    root_cause_reason: str
    sop_key: str
    related_alarms: List[Alarm] = field(default_factory=list)
    severity: str = "CRITICAL"
    
    def __post_init__(self):
        """バリデーション"""
        valid_severities = {"CRITICAL", "WARNING", "INFO", "UNKNOWN"}
        if self.severity not in valid_severities:
            logger.warning(
                f"Invalid severity '{self.severity}' in InferenceResult. "
                f"Valid values: {valid_severities}. Defaulting to 'UNKNOWN'."
            )
            self.severity = "UNKNOWN"

# =====================================================
# 因果推論エンジン
# =====================================================

class CausalInferenceEngine:
    """
    ネットワークアラームの因果関係を推論するエンジン
    """
    
    def __init__(self, topology: Dict[str, NetworkNode]):
        if not topology:
            raise ValueError("Topology cannot be empty")
        
        self.topology = topology
        logger.info(f"CausalInferenceEngine initialized with {len(topology)} nodes")
    
    def analyze_alarms(self, alarms: List[Alarm]) -> InferenceResult:
        """
        アラームを分析して根本原因を推論
        """
        if not isinstance(alarms, list):
            logger.error(f"Invalid alarms type: {type(alarms)}")
            raise ValueError("Alarms must be a list")
        
        # 空のアラームリストの処理
        if not alarms:
            return InferenceResult(
                root_cause_node=None,
                root_cause_reason="アラームなし",
                sop_key="DEFAULT",
                related_alarms=[],
                severity="INFO"
            )
        
        # アラーム情報の整理
        alarmed_device_ids = {a.device_id for a in alarms}
        alarm_map = {a.device_id: a for a in alarms}
        
        # 階層順にソート（layer値が小さいほど上位層）
        sorted_alarms = sorted(
            alarms,
            key=lambda a: (
                self.topology[a.device_id].layer 
                if a.device_id in self.topology 
                else 999
            )
        )
        
        top_alarm = sorted_alarms[0]
        top_node = self.topology.get(top_alarm.device_id)
        
        # トポロジーに存在しないデバイス
        if not top_node:
            logger.warning(f"Unknown device in alarm: {top_alarm.device_id}")
            return InferenceResult(
                root_cause_node=None,
                root_cause_reason=f"不明なデバイス: {top_alarm.device_id}",
                sop_key="DEFAULT",
                related_alarms=alarms,
                severity="UNKNOWN"
            )
        
        # A. 冗長性ルール（HA構成の分析）
        if top_node.redundancy_group:
            return self._analyze_redundancy(top_node, alarmed_device_ids, alarms, alarm_map)
        
        # B. サイレント障害推論
        if top_node.parent_id:
            silent_res = self._check_silent_failure_for_parent(
                top_node.parent_id, 
                alarmed_device_ids
            )
            if silent_res:
                return silent_res
        
        # C. 単一機器障害
        root_severity = top_alarm.severity
        
        return InferenceResult(
            root_cause_node=top_node,
            root_cause_reason=(
                f"階層ルール: 最上位レイヤーのデバイス {top_node.id} でアラーム検知 "
                f"({top_alarm.message})"
            ),
            sop_key="HIERARCHY_FAILURE",
            related_alarms=alarms,
            severity=root_severity
        )
    
    def _analyze_redundancy(
        self, 
        node: NetworkNode, 
        alarmed_ids: Set[str], 
        alarms: List[Alarm], 
        alarm_map: Dict[str, Alarm]
    ) -> InferenceResult:
        """冗長性構成（HA）の分析"""
        group_members = [
            n for n in self.topology.values() 
            if n.redundancy_group == node.redundancy_group
        ]
        down_members = [n for n in group_members if n.id in alarmed_ids]
        
        # エラー詳細の構築
        error_details = []
        for m in down_members:
            if m.id in alarm_map:
                error_details.append(f"{m.id}: {alarm_map[m.id].message}")
        details_str = ", ".join(error_details)
        
        # 全停止判定
        if len(down_members) == len(group_members):
            return InferenceResult(
                root_cause_node=node,
                root_cause_reason=(
                    f"冗長性ルール: HAグループ {node.redundancy_group} 全停止。"
                    f"詳細: [{details_str}]"
                ),
                sop_key="HA_TOTAL_FAILURE",
                related_alarms=alarms,
                severity="CRITICAL"
            )
        else:
            # 片系障害判定
            return InferenceResult(
                root_cause_node=node,
                root_cause_reason=(
                    f"冗長性ルール: HAグループ {node.redundancy_group} 片系障害 (稼働継続)。"
                    f"検知内容: [{details_str}]"
                ),
                sop_key="HA_PARTIAL_FAILURE",
                related_alarms=alarms,
                severity="WARNING"
            )
    
    def _check_silent_failure_for_parent(
        self, 
        parent_id: str, 
        alarmed_ids: Set[str]
    ) -> Optional[InferenceResult]:
        """サイレント障害の検出"""
        parent_node = self.topology.get(parent_id)
        if not parent_node: return None
        
        children = [n for n in self.topology.values() if n.parent_id == parent_id]
        if not children: return None
        
        children_down = sum(1 for c in children if c.id in alarmed_ids)
        
        if children_down == len(children):
            return InferenceResult(
                root_cause_node=parent_node,
                root_cause_reason=(
                    f"サイレント障害推論: 親デバイス {parent_id} は沈黙していますが、"
                    f"配下の子デバイスが全滅しています。"
                ),
                sop_key="SILENT_FAILURE",
                related_alarms=[],
                severity="CRITICAL"
            )
        return None

# =====================================================
# ユーティリティ関数
# =====================================================

def simulate_cascade_failure(
    root_cause_id: str, 
    topology: Dict[str, NetworkNode], 
    custom_message: str = "Interface Down"
) -> List[Alarm]:
    """カスケード障害のシミュレーション"""
    if root_cause_id not in topology:
        raise ValueError(f"Device {root_cause_id} not found in topology")
    
    generated_alarms = []
    
    # 根本原因のアラーム生成
    root_alarm = Alarm(root_cause_id, custom_message, "CRITICAL")
    generated_alarms.append(root_alarm)
    
    # BFSで子デバイスを探索
    queue = [root_cause_id]
    processed = {root_cause_id}
    
    while queue:
        current_parent_id = queue.pop(0)
        children = [
            n for n in topology.values() 
            if n.parent_id == current_parent_id
        ]
        
        for child in children:
            if child.id not in processed:
                child_alarm = Alarm(child.id, "Unreachable", "WARNING")
                generated_alarms.append(child_alarm)
                queue.append(child.id)
                processed.add(child.id)
                
    return generated_alarms

# =====================================================
# バリデーション関数
# =====================================================

def validate_topology(topology: Dict[str, NetworkNode]) -> bool:
    """トポロジーの整合性をチェック"""
    if not topology: return False
    
    issues = []
    for node_id, node in topology.items():
        if node.id != node_id:
            issues.append(f"Node ID mismatch: {node_id}")
        if node.parent_id and node.parent_id not in topology:
            issues.append(f"Node {node_id} has invalid parent: {node.parent_id}")
            
    if issues:
        for i in issues: logger.warning(i)
        return False
    return True

# 初期化時にバリデーション実行
try:
    if TOPOLOGY: validate_topology(TOPOLOGY)
except Exception as e:
    logger.error(f"Topology validation error: {e}")
