#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.Processor import load_case, load_all_cases
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.CliArgs import parse_args
from utils.FileUtils import FileHandler
from utils.Logger import Logger

# GLOBALS
config = ConfigLoader.load_config()


if __name__ == "__main__":
    Logger.reset_log()
    session = get_session()
    args = parse_args()

    Logger.info(f"{config['tool_name']} - {config['friendly_name']}")
    Logger.info(f"Parsing {config['program']} v{config['version']}")
    print()

    if args.file:
        case_data = [load_case(config["program"], config["version"], args.file)]
    else:
        case_data = load_all_cases(config["program"], config["version"])

    if not case_data:
        Logger.error("No .def files found.")
        exit(1)

    for case in case_data:
        Logger.info(f"Processing case: {case[0]}")