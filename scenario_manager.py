# -*- coding: utf-8 -*-
"""
scenario_manager.py - シナリオ定義の統一管理モジュール

【設計思想】
- シナリオをデータとして扱う（コードではない）
- YAMLやJSONで外部化可能
- AI推論とルールベースの橋渡し
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import yaml
import json


# ========================================
# Enums: シナリオ属性の型安全性
# ========================================

class ImpactScope(Enum):
    """障害の影響範囲"""
    SINGLE = "single"              # 単一機器
    CASCADE = "cascade"            # カスケード（親→子全滅）
    MULTI = "multi"                # 同時多発（独立した複数機器）
    SILENT_UPSTREAM = "silent"     # サイレント障害（親は沈黙、子が症状）


class Severity(Enum):
    """深刻度"""
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class SimulationType(Enum):
    """診断シミュレーションのタイプ"""
    LIVE = "live"          # 実機接続
    AI_MOCK = "ai_mock"    # AI生成モック
    ERROR = "error"        # エラーシミュレーション
    SKIP = "skip"          # スキップ


# ========================================
# データクラス: シナリオ定義
# ========================================

@dataclass
class TargetHints:
    """対象機器の探索ヒント"""
    device_type: Optional[str] = None    # "ROUTER", "FIREWALL", "SWITCH", etc.
    layer: Optional[int] = None          # ネットワーク階層（1=Edge, 5=AP）
    keyword: Optional[str] = None        # デバイスID部分一致検索
    redundancy_group: Optional[str] = None


@dataclass
class ScenarioDefinition:
    """
    シナリオの完全な定義
    
    【使用例】
    scenario = ScenarioDefinition(
        id="wan_outage",
        name="WAN全回線断",
        description="Edge router physical link failure",
        impact_scope=ImpactScope.CASCADE,
        severity=Severity.CRITICAL,
        simulation_type=SimulationType.AI_MOCK,
        target_hints=TargetHints(device_type="ROUTER", layer=1)
    )
    """
    
    # 識別情報
    id: str                                 # 一意なID（英数字）
    name: str                               # 表示名（日本語OK）
    description: str                        # 詳細説明
    
    # 障害特性
    impact_scope: ImpactScope
    severity: Severity
    simulation_type: SimulationType = SimulationType.AI_MOCK
    
    # 対象機器
    target_hints: Optional[TargetHints] = None
    
    # AI推論のヒント
    symptoms: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    
    # メタデータ
    tags: List[str] = field(default_factory=list)
    related_sop: Optional[str] = None      # 関連する標準作業手順
    
    def __post_init__(self):
        """バリデーション"""
        if not self.id or not isinstance(self.id, str):
            raise ValueError(f"Invalid scenario id: {self.id}")
        
        if not self.name:
            raise ValueError("Scenario name is required")
    
    def matches(self, query: str) -> float:
        """
        クエリとのマッチ度を返す（0.0-1.0）
        
        【マッチング方式】
        1. ID完全一致: 1.0
        2. 名前完全一致: 0.9
        3. 名前部分一致: 0.7
        4. タグ一致: 0.6
        5. 説明文一致: 0.4
        """
        query_lower = query.lower()
        
        # 1. ID完全一致
        if self.id.lower() == query_lower:
            return 1.0
        
        # 2. 名前完全一致
        if self.name.lower() == query_lower:
            return 0.9
        
        # 3. 名前部分一致
        if query_lower in self.name.lower() or self.name.lower() in query_lower:
            return 0.7
        
        # 4. タグ一致
        if any(tag.lower() == query_lower for tag in self.tags):
            return 0.6
        
        # 5. 説明文一致
        if query_lower in self.description.lower():
            return 0.4
        
        return 0.0


# ========================================
# シナリオカタログ
# ========================================

class ScenarioCatalog:
    """シナリオの集合を管理"""
    
    def __init__(self, scenarios: List[ScenarioDefinition] = None):
        self.scenarios = scenarios or []
        self._index_by_id = {s.id: s for s in self.scenarios}
    
    def add(self, scenario: ScenarioDefinition):
        """シナリオを追加"""
        if scenario.id in self._index_by_id:
            raise ValueError(f"Duplicate scenario id: {scenario.id}")
        
        self.scenarios.append(scenario)
        self._index_by_id[scenario.id] = scenario
    
    def get_by_id(self, scenario_id: str) -> Optional[ScenarioDefinition]:
        """IDで取得"""
        return self._index_by_id.get(scenario_id)
    
    def search(self, query: str, top_k: int = 1) -> List[ScenarioDefinition]:
        """
        クエリにマッチするシナリオを検索
        
        【使用例】
        catalog = ScenarioCatalog(...)
        results = catalog.search("WAN全回線断")
        best_match = results[0] if results else None
        """
        scored = [(s, s.matches(query)) for s in self.scenarios]
        scored = [(s, score) for s, score in scored if score > 0]
        scored.sort(key=lambda x: x[1], reverse=True)
        
        return [s for s, score in scored[:top_k]]
    
    def filter_by_type(self, sim_type: SimulationType) -> List[ScenarioDefinition]:
        """シミュレーションタイプでフィルタ"""
        return [s for s in self.scenarios if s.simulation_type == sim_type]
    
    def filter_by_severity(self, severity: Severity) -> List[ScenarioDefinition]:
        """深刻度でフィルタ"""
        return [s for s in self.scenarios if s.severity == severity]
    
    @classmethod
    def from_yaml(cls, filepath: str) -> 'ScenarioCatalog':
        """YAMLファイルから読み込み"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        scenarios = []
        for item in data.get('scenarios', []):
            # Enum変換
            impact_scope = ImpactScope(item.get('impact_scope', 'single'))
            severity = Severity(item.get('severity', 'WARNING'))
            sim_type = SimulationType(item.get('simulation_type', 'ai_mock'))
            
            # TargetHints構築
            hints_data = item.get('target_hints', {})
            hints = TargetHints(**hints_data) if hints_data else None
            
            scenario = ScenarioDefinition(
                id=item['id'],
                name=item['name'],
                description=item['description'],
                impact_scope=impact_scope,
                severity=severity,
                simulation_type=sim_type,
                target_hints=hints,
                symptoms=item.get('symptoms', []),
                affected_services=item.get('affected_services', []),
                tags=item.get('tags', []),
                related_sop=item.get('related_sop')
            )
            scenarios.append(scenario)
        
        return cls(scenarios)
    
    @classmethod
    def from_json(cls, filepath: str) -> 'ScenarioCatalog':
        """JSONファイルから読み込み"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # YAMLと同じ構造を想定
        scenarios = []
        for item in data.get('scenarios', []):
            impact_scope = ImpactScope(item.get('impact_scope', 'single'))
            severity = Severity(item.get('severity', 'WARNING'))
            sim_type = SimulationType(item.get('simulation_type', 'ai_mock'))
            
            hints_data = item.get('target_hints', {})
            hints = TargetHints(**hints_data) if hints_data else None
            
            scenario = ScenarioDefinition(
                id=item['id'],
                name=item['name'],
                description=item['description'],
                impact_scope=impact_scope,
                severity=severity,
                simulation_type=sim_type,
                target_hints=hints,
                symptoms=item.get('symptoms', []),
                affected_services=item.get('affected_services', []),
                tags=item.get('tags', []),
                related_sop=item.get('related_sop')
            )
            scenarios.append(scenario)
        
        return cls(scenarios)


# ========================================
# デフォルトシナリオカタログ
# ========================================

DEFAULT_SCENARIOS = [
    ScenarioDefinition(
        id="wan_outage",
        name="WAN全回線断",
        description="Edge router experiences complete link failure, affecting all downstream devices",
        impact_scope=ImpactScope.CASCADE,
        severity=Severity.CRITICAL,
        simulation_type=SimulationType.AI_MOCK,
        target_hints=TargetHints(device_type="ROUTER", layer=1),
        symptoms=["Link Down", "BGP Session Lost", "No Route to Host"],
        affected_services=["Internet Access", "VPN", "Cloud Services"],
        tags=["wan", "outage", "critical"]
    ),
    
    ScenarioDefinition(
        id="fw_ha_partial",
        name="FW片系障害",
        description="One firewall in HA pair fails, but redundant unit maintains service",
        impact_scope=ImpactScope.SINGLE,
        severity=Severity.WARNING,
        simulation_type=SimulationType.AI_MOCK,
        target_hints=TargetHints(device_type="FIREWALL", layer=2),
        symptoms=["Heartbeat Loss", "HA Failover Triggered"],
        affected_services=[],
        tags=["firewall", "ha", "warning"]
    ),
    
    ScenarioDefinition(
        id="l2sw_silent",
        name="L2SWサイレント障害",
        description="L2 switch appears online but all downstream APs report connection loss",
        impact_scope=ImpactScope.SILENT_UPSTREAM,
        severity=Severity.CRITICAL,
        simulation_type=SimulationType.AI_MOCK,
        target_hints=TargetHints(device_type="SWITCH", layer=4, keyword="L2"),
        symptoms=["Connection Lost (on children)", "Ping OK (on parent)"],
        affected_services=["WiFi Access"],
        tags=["switch", "silent", "ap"]
    ),
    
    ScenarioDefinition(
        id="psu_single",
        name="電源障害：片系",
        description="Single PSU failure in redundant power supply configuration",
        impact_scope=ImpactScope.SINGLE,
        severity=Severity.WARNING,
        simulation_type=SimulationType.AI_MOCK,
        symptoms=["Power Supply 1 Failed", "PSU Redundancy Lost"],
        tags=["power", "psu", "warning"]
    ),
    
    ScenarioDefinition(
        id="psu_dual",
        name="電源障害：両系",
        description="Dual PSU failure causing complete device shutdown",
        impact_scope=ImpactScope.CASCADE,
        severity=Severity.CRITICAL,
        simulation_type=SimulationType.AI_MOCK,
        symptoms=["Dual PSU Loss", "Device Down", "System Shutdown"],
        tags=["power", "psu", "critical", "outage"]
    ),
    
    ScenarioDefinition(
        id="bgp_flap",
        name="BGPフラッピング",
        description="BGP session instability causing route flapping",
        impact_scope=ImpactScope.SINGLE,
        severity=Severity.WARNING,
        simulation_type=SimulationType.AI_MOCK,
        target_hints=TargetHints(device_type="ROUTER"),
        symptoms=["BGP Flapping", "Route Changes", "Peer Down/Up"],
        affected_services=["Routing Stability"],
        tags=["bgp", "routing", "warning"]
    ),
    
    ScenarioDefinition(
        id="fan_failure",
        name="FAN故障",
        description="Cooling fan failure with potential thermal escalation risk",
        impact_scope=ImpactScope.SINGLE,
        severity=Severity.WARNING,
        simulation_type=SimulationType.AI_MOCK,
        symptoms=["Fan Fail", "High Temperature", "Thermal Warning"],
        tags=["fan", "thermal", "warning"]
    ),
    
    ScenarioDefinition(
        id="memory_leak",
        name="メモリリーク",
        description="Memory leak causing gradual performance degradation",
        impact_scope=ImpactScope.SINGLE,
        severity=Severity.WARNING,
        simulation_type=SimulationType.AI_MOCK,
        symptoms=["Memory High", "Process Restart", "Slow Response"],
        tags=["memory", "resource", "warning"]
    ),
    
    ScenarioDefinition(
        id="live_cisco",
        name="[Live] Cisco実機診断",
        description="Connect to actual Cisco sandbox device for diagnostics",
        impact_scope=ImpactScope.SINGLE,
        severity=Severity.INFO,
        simulation_type=SimulationType.LIVE,
        tags=["live", "cisco", "sandbox"]
    ),
    
    ScenarioDefinition(
        id="normal",
        name="正常稼働",
        description="All systems operational, no issues detected",
        impact_scope=ImpactScope.SINGLE,
        severity=Severity.INFO,
        simulation_type=SimulationType.SKIP,
        tags=["normal", "healthy"]
    ),
]


# ========================================
# グローバルカタログインスタンス
# ========================================

DEFAULT_CATALOG = ScenarioCatalog(DEFAULT_SCENARIOS)


# ========================================
# ユーティリティ関数
# ========================================

def find_scenario(query: str, catalog: ScenarioCatalog = None) -> Optional[ScenarioDefinition]:
    """
    クエリからシナリオを検索（便利関数）
    
    【使用例】
    scenario = find_scenario("WAN全回線断")
    if scenario:
        print(f"Found: {scenario.name}")
    """
    catalog = catalog or DEFAULT_CATALOG
    results = catalog.search(query, top_k=1)
    return results[0] if results else None


def list_scenarios(catalog: ScenarioCatalog = None) -> List[str]:
    """全シナリオ名のリストを返す"""
    catalog = catalog or DEFAULT_CATALOG
    return [s.name for s in catalog.scenarios]


# ========================================
# 使用例
# ========================================

if __name__ == "__main__":
    print("=" * 80)
    print("Scenario Manager - Usage Examples")
    print("=" * 80)
    
    # 1. シナリオ検索
    print("\n1. Scenario Search:")
    queries = ["WAN全回線断", "FW片系", "サイレント", "正常"]
    for q in queries:
        result = find_scenario(q)
        if result:
            print(f"  Query: '{q}' → Found: {result.name} (id={result.id})")
        else:
            print(f"  Query: '{q}' → Not found")
    
    # 2. フィルタリング
    print("\n2. Filter by Severity:")
    critical_scenarios = DEFAULT_CATALOG.filter_by_severity(Severity.CRITICAL)
    print(f"  CRITICAL scenarios: {[s.name for s in critical_scenarios]}")
    
    # 3. YAML出力例
    print("\n3. YAML Format Example:")
    sample_yaml = """
scenarios:
  - id: wan_outage
    name: WAN全回線断
    description: Edge router link failure
    impact_scope: cascade
    severity: CRITICAL
    simulation_type: ai_mock
    target_hints:
      device_type: ROUTER
      layer: 1
    symptoms:
      - Link Down
      - BGP Session Lost
    tags:
      - wan
      - critical
"""
    print(sample_yaml)
    
    print("\n✅ Scenario Manager is ready to use!")
