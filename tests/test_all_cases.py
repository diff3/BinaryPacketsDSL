#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import json
from modules.DecorderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_all_cases
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger

# GLOBALS
config = ConfigLoader.get_config()
session = get_session()
class TestAllCases(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        config["Logging"]["logging_levels"] = "None"  # silent to console
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
          

            with self.subTest(case=case_name):
                session.reset()
                num += 1

                try:
                    NodeTreeParser.parse(def_lines)
                    result = DecoderHandler.decode((case_name, def_lines, binary_data, expected))
          
                    python_json_result = json.dumps(result)
                    python_json_expected = json.dumps(expected)
                    
                    if python_json_result == python_json_expected:
                        print(f"[SUCCESS] {case_name}")
                        Logger.to_log('')
                        Logger.success(f"UNIT TEST: {case_name} matched")
                        Logger.to_log('')
                        success += 1
                    else:
                        print(f"[FAILED] {case_name}")
                        failed += 1
                        self.fail(f"{case_name} mismatch")
                        pass

                except Exception as e:
                    Logger.to_log('')
                    Logger.error(f"UNIT TEST: {case_name} mismatch")
                    Logger.debug(f"Expected: {python_json_expected}")
                    Logger.debug(f"Got:      {python_json_result}")
                    Logger.to_log('')

        print()
        print(f'Run {num} tests')
        print(f'Success {success} tests')
        print(f'Failed {failed} tests')