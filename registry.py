# -*- coding: utf-8 -*-
"""
Tenant/Network Registry (minimal + future-proof)

- Keep A社の topology.json はそのまま（変更不要）
- Tenant/Network を UI で切替できるようにする
- 将来の多数ネットワーク（CMDB/DB/S3/Git）にも差し替えやすい入口を用意
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from data import load_topology_from_json, NetworkNode


@dataclass(frozen=True)
class TenantNetworkPaths:
    tenant_id: str
    network_id: str
    topology_path: Path
    config_dir: Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _tenants_root() -> Path:
    return _project_root() / "tenants"


def list_tenants() -> List[str]:
    troot = _tenants_root()
    if not troot.exists():
        return ["A", "B"]  # fallback
    tenants = sorted([p.name for p in troot.iterdir() if p.is_dir() and not p.name.startswith(".")])
    return tenants or ["A", "B"]


def list_networks(tenant_id: str) -> List[str]:
    nroot = _tenants_root() / tenant_id / "networks"
    if not nroot.exists():
        return ["default"]
    nets = sorted([p.name for p in nroot.iterdir() if p.is_dir() and not p.name.startswith(".")])
    return nets or ["default"]


def get_paths(tenant_id: str, network_id: str) -> TenantNetworkPaths:
    """
    Canonical layout:
      ./tenants/<TENANT>/networks/<NETWORK>/topology.json
      ./tenants/<TENANT>/networks/<NETWORK>/configs/
    Backward compatibility:
      A -> ./topology.json  + ./configs
      B -> ./topology_b.json + ./configs_b
    """
    troot = _tenants_root()
    topo = troot / tenant_id / "networks" / network_id / "topology.json"
    cfg = troot / tenant_id / "networks" / network_id / "configs"
    if topo.exists():
        return TenantNetworkPaths(tenant_id, network_id, topo, cfg)

    root = _project_root()
    if tenant_id.upper() == "B":
        return TenantNetworkPaths(tenant_id, network_id, root / "topology_b.json", root / "configs_b")
    return TenantNetworkPaths(tenant_id, network_id, root / "topology.json", root / "configs")


def topology_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return 0.0


def load_topology(topology_path: Path) -> Dict[str, NetworkNode]:
    return load_topology_from_json(str(topology_path))
