#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fristående snabbtest för att encoda/decoda CMSG_AUTH_SESSION med statiska fältvärden.
Körs från repo-roten: python tools/test_cmsg_auth_session.py
"""

import json
import sys
from pathlib import Path

# Sätt repo-roten på sys.path så att modules/* hittas även när scriptet körs direkt
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.EncoderHandler import EncoderHandler
from modules.DecoderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_case
from modules.Session import get_session
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger


def main() -> int:
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]
    def_name = "CMSG_AUTH_SESSION"

    digest = ["A", "B", "C", "D", "E", "F", "G", "H"]
    # DEF:en använder digest: 1B[8], så skicka in listan som ints
    encoded_fields = {"digest": [ord(ch) for ch in digest]}

    Logger.info(f"Encoding {def_name} for {program} {version}")
    payload = EncoderHandler.encode_packet(def_name, encoded_fields)
    Logger.success(f"Encoded payload ({len(payload)} bytes): {payload.hex(' ')}")

    # Decode tillbaka som sanity-check
    session = get_session()
    session.reset()
    case = load_case(program, version, def_name)
    case_for_decode = (case[0], case[1], payload, {}, None)
    NodeTreeParser.parse(case_for_decode)
    decoded = DecoderHandler.decode(case_for_decode, silent=True)
    Logger.success("Decoded fields:")
    print(json.dumps(decoded, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
