# utils/config_loader.py

from copy import deepcopy
from config import CONFIG as DEFAULT_CONFIG


class ConfigLoader:
    @staticmethod
    def load_active_config(state_name: str) -> dict:
        base = deepcopy(DEFAULT_CONFIG["shared"])
        default = DEFAULT_CONFIG["states"]["default"]
        override = DEFAULT_CONFIG["states"].get(state_name, {})

        # shallow merge first
        cfg = {**base, **default}

        # routes need deep merge by name
        routes = deepcopy(default["routes"])

        for name, route in override.get("routes", {}).items():
            routes[name] = ConfigLoader._merge_dicts(
                routes.get(name, {}),
                route,
            )

        cfg["routes"] = routes

        # merge other top-level overrides (if any later)
        for key, value in override.items():
            if key != "routes":
                cfg[key] = value

        return cfg

    @staticmethod
    def _merge_dicts(base: dict, override: dict) -> dict:
        result = deepcopy(base)
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(result.get(k), dict):
                result[k] = ConfigLoader._merge_dicts(result[k], v)
            else:
                result[k] = v

        return result