#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.DecorderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_case, load_all_cases, handle_add
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.CliArgs import parse_args
from utils.Logger import Logger
from utils.PrintUtils import SessionPrint

# GLOBALS
config = ConfigLoader.get_config()
session = get_session()
args = parse_args()


if __name__ == "__main__":
    Logger.reset_log()
    session.reset()

    tool_name = config['tool_name']
    program = config['program']
    version = config['version']
    friendly_name = config['friendly_name']

    if args.verbose:
        Logger.set_level("ALL")

    if args.program:
        program = args.program
        friendly_name = "manuell"

    if args.version:
        version = args.version
        friendly_name = "manuell"

    if args.add:
        if not args.program or not args.version or not args.file or not args.bin:
            Logger.error("Missing required arguments for --add: --program, --version, --file, and --bin")
            exit(1)

        if handle_add(args.program, args.version, args.file, args.bin):
            Logger.success(f"Successfully added packet: {args.file}")
            exit(0)
        else:
            Logger.error(f"Failed to add packet: {args.file}")
            exit(1)

    if args.silent:
        config["Logging"]["logging_levels"] = "None"    
   
    Logger.info(f"{tool_name} - {friendly_name}")
    Logger.info(f"Parsing {program} v{version}\n")

    if args.file:
        case_data = [load_case(program, version, args.file)]
    else:
        case_data = load_all_cases(program, version)

    if not case_data:
        Logger.error("No .def files found.")
        exit(1)

    for case in case_data:
  
        
        Logger.info(f"Processing case: {case[0]}")
        NodeTreeParser.parse(case[1])

        SessionPrint.pretty_print_compact_all(session)
        Logger.to_log('')

        DecoderHandler.decode(case)