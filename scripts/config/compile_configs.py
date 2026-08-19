#!/usr/bin/env python3
"""Validate sector YAML configs and compile to JSON for scanner runtimes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "config" / "sectors"
SECTORS = ("water", "energy-grid", "bas", "rail")

REQUIRED = {
    "water": ("remote_access_ports", "ot_protocol_ports", "threat_context"),
    "energy-grid": ("cve_checks", "remote_access_ports", "ics_ports"),
    "bas": ("bas_protocol_ports", "remote_access_ports", "threat_context", "vendor_alerts"),
    "rail": ("port_catalog",),
}


def validate_sector(name: str, data: dict) -> None:
    if data.get("sector") != name:
        raise ValueError(f"{name}.yaml: sector field must be '{name}'")
    if "metadata" not in data or "version" not in data["metadata"]:
        raise ValueError(f"{name}.yaml: metadata.version required")

    for key in REQUIRED[name]:
        if key not in data:
            raise ValueError(f"{name}.yaml: missing required key '{key}'")

    if name == "water":
        for group in ("remote_access_ports", "ot_protocol_ports"):
            ports = [p["port"] for p in data[group]]
            if len(ports) != len(set(ports)):
                raise ValueError(f"{name}.yaml: duplicate ports in {group}")
        for key in data["threat_context"]:
            if not key.strip():
                raise ValueError(f"{name}.yaml: empty threat_context key")

    if name == "energy-grid":
        for cve_id, cve in data["cve_checks"].items():
            if not cve.get("ports"):
                raise ValueError(f"{name}.yaml: {cve_id} has no ports")

    if name == "bas":
        alert_ports = [a["port"] for a in data["vendor_alerts"]]
        if len(alert_ports) != len(set(alert_ports)):
            raise ValueError(f"{name}.yaml: duplicate vendor alert ports")

    if name == "rail":
        cats = {e["category"] for e in data["port_catalog"]}
        if "EotHot" not in cats:
            raise ValueError(f"{name}.yaml: port_catalog must include EotHot category")
        ports = [e["port"] for e in data["port_catalog"]]
        if len(ports) != len(set(ports)):
            raise ValueError(f"{name}.yaml: duplicate ports in port_catalog")


def main() -> int:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    errors = 0

    for sector in SECTORS:
        yaml_path = CONFIG_DIR / f"{sector}.yaml"
        json_path = CONFIG_DIR / f"{sector}.json"
        if not yaml_path.exists():
            print(f"MISSING {yaml_path}", file=sys.stderr)
            errors += 1
            continue
        with yaml_path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        try:
            validate_sector(sector, data)
        except ValueError as exc:
            print(f"INVALID {yaml_path}: {exc}", file=sys.stderr)
            errors += 1
            continue
        with json_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"OK {yaml_path.name} -> {json_path.name}")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
