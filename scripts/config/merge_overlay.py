#!/usr/bin/env python3
"""Merge a sector config JSON base with a YAML or JSON overlay."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - CI installs pyyaml
    yaml = None  # type: ignore


PORT_LIST_KEYS = (
    "remote_access_ports",
    "ot_protocol_ports",
    "bas_protocol_ports",
    "ics_ports",
    "port_catalog",
    "vendor_alerts",
)


def _load_overlay(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML required to load YAML overlays")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Overlay must be a mapping: {path}")
    return data


def _merge_port_lists(base: list[Any], overlay: list[Any]) -> list[Any]:
    by_port: dict[int, dict[str, Any]] = {}
    for item in base:
        if isinstance(item, dict) and "port" in item:
            by_port[int(item["port"])] = dict(item)
    for item in overlay:
        if isinstance(item, dict) and "port" in item:
            port = int(item["port"])
            merged = dict(by_port.get(port, {}))
            merged.update(item)
            by_port[port] = merged
    return [by_port[p] for p in sorted(by_port)]


def _merge_dicts(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in overlay.items():
        if key in PORT_LIST_KEYS and isinstance(value, list):
            existing = result.get(key, [])
            if not isinstance(existing, list):
                existing = []
            result[key] = _merge_port_lists(existing, value)
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def merge_config(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    return _merge_dicts(base, overlay)


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: merge_overlay.py <base.json> <overlay.yaml|json>", file=sys.stderr)
        return 2

    base_path = Path(sys.argv[1])
    overlay_path = Path(sys.argv[2])
    base = json.loads(base_path.read_text(encoding="utf-8"))
    overlay = _load_overlay(overlay_path)
    merged = merge_config(base, overlay)
    print(json.dumps(merged, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
