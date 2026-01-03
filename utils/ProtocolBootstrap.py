#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import importlib
from types import ModuleType

from utils.ConfigLoader import ConfigLoader


def load_bootstrap() -> ModuleType:
    """
    Load the protocol bootstrap module based on config.

    Expects: protocols/<program>/shared/modules/bootstrap.py
    """
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    module_path = f"protocols.{program}.shared.modules.bootstrap"
    return importlib.import_module(module_path)
