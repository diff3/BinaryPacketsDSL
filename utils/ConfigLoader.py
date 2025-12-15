#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml

# GLOBALS
_config = None 


class ConfigLoader:
    def get_config() -> dict:
        """
        Retrieves a value from the loaded configuration.
        """

        global _config

        if _config is None:
            with open("etc/config.yaml", "r", encoding="utf-8") as f:
                _config = yaml.safe_load(f)
                
        return _config

    @staticmethod
    def load_config(filepath:str = "etc/config.yaml") -> dict:
        """
        Loads the configuration file if not already cached.
        """
        global _config
        
        if _config is None:
            try:
                with open(filepath, 'r', encoding="utf-8") as file:
                    _config = yaml.safe_load(file)
            except FileNotFoundError:
                raise RuntimeError(f"Configuration file not found at {filepath}.")
            except yaml.YAMLError as e:
                raise RuntimeError(f"Error parsing YAML file: {e}")
        
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