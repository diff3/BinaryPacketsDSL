#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
from pathlib import Path
from copy import deepcopy

# GLOBALS
_config = None


def _merge_dicts(base: dict, override: dict) -> dict:
    """
    Shallow+nested merge: values in override win; dict values are merged recursively.
    """
    result = deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _merge_dicts(result[k], v)
        else:
            result[k] = deepcopy(v)
    return result


def _apply_proxy_profile(base_cfg: dict) -> dict:
    """
    Merge the selected proxy profile into the base config, if defined.
    """
    profile_name = base_cfg.get("proxy_profile")
    profiles = base_cfg.get("proxy_profiles")
    if isinstance(profile_name, dict):
        merged = _merge_dicts(base_cfg, profile_name)
        if profile_name.get("program") is not None:
            merged["program"] = profile_name["program"]
        if profile_name.get("version") is not None:
            merged["version"] = profile_name["version"]
        return merged

    if not profile_name or not isinstance(profiles, dict):
        return base_cfg

    profile_cfg = profiles.get(profile_name)
    if not isinstance(profile_cfg, dict):
        return base_cfg

    merged = _merge_dicts(base_cfg, profile_cfg)
    if profile_cfg.get("program") is not None:
        merged["program"] = profile_cfg["program"]
    if profile_cfg.get("version") is not None:
        merged["version"] = profile_cfg["version"]
    return merged


class ConfigLoader:
    def get_config() -> dict:
        """
        Retrieves a value from the loaded configuration.
        """
        global _config
        if _config is None:
            _config = ConfigLoader.load_config()
        return _config

    @staticmethod
    def load_config(filepath: str = "etc/config.yaml") -> dict:
        """
        Loads the configuration file if not already cached.
        Also overlays optional program-specific config at protocols/<program>/config.yaml.
        Applies selected proxy profile from proxy_profiles/proxy_profile if present.
        """
        global _config

        if _config is None:
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    base_cfg = yaml.safe_load(file) or {}
            except FileNotFoundError:
                raise RuntimeError(f"Configuration file not found at {filepath}.")
            except yaml.YAMLError as e:
                raise RuntimeError(f"Error parsing YAML file: {e}")

            base_cfg = _apply_proxy_profile(base_cfg)
            # Optional program-specific overlay
            try:
                program = base_cfg.get("program")
                version = base_cfg.get("version")
                if program:
                    # Prefer program+version-specific config
                    paths = []
                    if version:
                        paths.append(Path("protocols") / program / version / "config.yaml")
                    paths.append(Path("protocols") / program / "config.yaml")
                    for program_cfg_path in paths:
                        if program_cfg_path.is_file():
                            overlay = yaml.safe_load(program_cfg_path.read_text(encoding="utf-8")) or {}
                            base_cfg = _merge_dicts(base_cfg, overlay)
                            break
            except Exception:
                # best-effort overlay; ignore if missing or malformed
                pass
            _config = base_cfg

        return _config

    @staticmethod
    def reload_config(filepath: str = "etc/config.yaml"):
        """
        Reload the configuration from disk.

        Returns:
            dict: The reloaded configuration dictionary.
        """

        global _config
        _config = None

        return ConfigLoader.load_config(filepath)
