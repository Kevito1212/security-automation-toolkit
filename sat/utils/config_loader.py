from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"


class ConfigError(Exception):
    pass


def load_config(config_path: str | None = None) -> Dict[str, Any]:
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        raise ConfigError(f"Failed to parse YAML: {e}") from e

    _validate_minimum(data)
    return data


def _validate_minimum(cfg: Dict[str, Any]) -> None:
    required = [
        ("app", "name"),
        ("logging", "level"),
        ("logging", "file"),
        ("reports", "output_dir"),
    ]
    for section, key in required:
        if section not in cfg or key not in cfg[section]:
            raise ConfigError(f"Missing config key: {section}.{key}")
