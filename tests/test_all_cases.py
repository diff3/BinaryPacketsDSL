#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import json
from modules.DecoderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_all_cases
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

# GLOBALS
config = ConfigLoader.get_config()
session = get_session()

def normalize(obj):
    """Recursively convert tuples to lists for comparison."""
    if isinstance(obj, tuple):
        return [normalize(x) for x in obj]
    if isinstance(obj, list):
        return [normalize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items()}
    return obj


class TestAllCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config["Logging"]["logging_levels"] = "Error, Success"
        Logger.reset_log()
        session.reset()

        cls.program = config["program"]
        cls.version = config["version"]
        cls.all_cases = load_all_cases(cls.program, cls.version)

    def test_cases(self):
        num = 0
        failed = 0
        success = 0

        for case_name, def_lines, binary_data, expected in self.all_cases:
            session.reset()
            num += 1

            with self.subTest(case=case_name):
                try:
                    # NodeTreeParser.parse(def_lines)
                    NodeTreeParser.parse((case_name, def_lines, binary_data, expected))
                    result = DecoderHandler.decode((case_name, def_lines, binary_data, expected))

                    if normalize(result) == normalize(expected):
                        success += 1
                        # Logger.success(f"{case_name}")
                    elif normalize(result) != normalize(expected):
                        Logger.error(f"{case_name}")
                        failed += 1
                    else:
                        print("Unknown error")

                except Exception as e:
                    failed += 1
                    print(f"[ERROR] {case_name}: {e}")

        print()
        print(f"Run {num} tests")
        print(f"Success {success} tests")
        print(f"Failed {failed} tests")