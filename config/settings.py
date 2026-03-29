"""
CRR Pipeline Configuration Management
Loads configuration from YAML files with environment variable overrides.

Priority (highest → lowest):
  1. Environment variables  (prefix: CRR_)
  2. config/default_config.yaml
  3. Hard-coded defaults

Usage::

    from config.settings import CRRSettings
    settings = CRRSettings()
    print(settings.discovery.onvif.timeout)
"""

import os
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Path to the bundled default config
_DEFAULT_CONFIG_PATH = Path(__file__).parent / "default_config.yaml"


def _load_yaml(path: Path) -> Dict:
    """
    Load a YAML file, returning an empty dict on any error.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed YAML contents as a dict.
    """
    try:
        import yaml  # PyYAML — optional; graceful fallback if absent

        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data or {}
    except ImportError:
        logger.debug("PyYAML not installed; using built-in defaults only.")
    except FileNotFoundError:
        logger.debug("Config file not found: %s", path)
    except Exception as exc:
        logger.warning("Failed to load config from %s: %s", path, exc)
    return {}


def _env_override(key_path: str, default: Any) -> Any:
    """
    Check for a CRR_-prefixed environment variable override.

    Converts the dotted key path to uppercase with underscores:
      ``discovery.onvif.timeout``  →  ``CRR_DISCOVERY_ONVIF_TIMEOUT``

    Args:
        key_path: Dot-separated config key path.
        default: Fallback value if no env var is set.

    Returns:
        Environment variable value (coerced to the type of ``default``)
        or ``default`` if not set.
    """
    env_key = "CRR_" + key_path.upper().replace(".", "_")
    raw = os.environ.get(env_key)
    if raw is None:
        return default
    # Coerce type
    if isinstance(default, bool):
        return raw.lower() in ("1", "true", "yes")
    if isinstance(default, int):
        try:
            return int(raw)
        except ValueError:
            return default
    if isinstance(default, float):
        try:
            return float(raw)
        except ValueError:
            return default
    if isinstance(default, list):
        return [item.strip() for item in raw.split(",")]
    return raw


class _NamespaceConfig:
    """Simple namespace class that exposes a flat dict as attributes."""

    def __init__(self, data: Dict) -> None:
        for key, value in data.items():
            if isinstance(value, dict):
                setattr(self, key, _NamespaceConfig(value))
            else:
                setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class CRRSettings:
    """
    Central configuration object for the CRR Pipeline.

    Attributes are populated from ``config/default_config.yaml`` with
    environment variable overrides.

    Attributes:
        scan: Scan-phase settings.
        discovery: Discovery-phase settings (onvif, ssdp, rtsp sub-namespaces).
        fingerprinting: Fingerprinting-phase settings.
        analysis: Analysis-phase settings.
        reporting: Reporting-phase settings.
        logging: Logging settings.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """
        Initialise CRRSettings, merging YAML config with env overrides.

        Args:
            config_path: Optional path to a custom YAML config file.
                If not provided, uses ``config/default_config.yaml``.
        """
        base = _load_yaml(_DEFAULT_CONFIG_PATH)
        if config_path:
            override = _load_yaml(config_path)
            base = _deep_merge(base, override)

        # Apply env overrides to key paths
        base = self._apply_env_overrides(base)

        self._raw = base
        self.scan = _NamespaceConfig(base.get("scan", {}))
        self.discovery = _NamespaceConfig(base.get("discovery", {}))
        self.fingerprinting = _NamespaceConfig(base.get("fingerprinting", {}))
        self.analysis = _NamespaceConfig(base.get("analysis", {}))
        self.reporting = _NamespaceConfig(base.get("reporting", {}))
        self.logging = _NamespaceConfig(base.get("logging", {}))

    def _apply_env_overrides(self, config: Dict, prefix: str = "") -> Dict:
        """
        Recursively apply environment variable overrides to the config dict.

        Args:
            config: Current config dict level.
            prefix: Dotted path prefix for the current level.

        Returns:
            Config dict with overrides applied.
        """
        for key, value in config.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                config[key] = self._apply_env_overrides(value, full_key)
            else:
                config[key] = _env_override(full_key, value)
        return config

    def as_dict(self) -> Dict:
        """Return the full configuration as a plain dict."""
        return dict(self._raw)


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """
    Recursively merge ``override`` into ``base``.

    Args:
        base: Base configuration dict.
        override: Override values to apply on top.

    Returns:
        Merged dict (base is mutated in-place and returned).
    """
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base
