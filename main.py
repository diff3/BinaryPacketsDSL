#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from utils.ConfigLoader import ConfigLoader
from utils.CliArgs import parse_args
from utils.Logger import Logger


# GLOBALS
config = ConfigLoader.load_config()


if __name__ == "__main__":
    Logger.reset_log()
    Logger.info(f"{config['tool_name']} - {config['friendly_name']}")
    Logger.info(f"Parsing {config['program']} v{config['version']}")

    args = parse_args()