#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader

# ❗ CORRECT MODULE NAMES
from modules.DecoderHandler import DecoderHandler
from modules.EncoderHandler import EncoderHandler

from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_case
from modules.Session import get_session

#
# DSL WRAPPERS — UPDATED TO MATCH CURRENT API
#

def dsl_decode(def_name: str, payload: bytes) -> dict:
    """
    Full DSL decode: load_case → attach raw payload → parse node tree → decode(case)
    """
    config = ConfigLoader.load_config()
    program = config["program"]
    version = config["version"]

    # Load DSL case
    case = load_case(program, version, def_name)
    if not case:
        raise ValueError(f"Unable to load DSL case: {def_name}")

    # Patch case tuple so that DecoderHandler sees the REAL payload
    # case = (name, lines, raw_data, decoded_data)
    case_name, case_lines, _, previously_decoded = case
    case = (case_name, case_lines, payload, previously_decoded)

    # Reset session + parse node tree
    session = get_session()
    session.reset()
    NodeTreeParser.parse(case)

    # Decode using existing DecoderHandler API
    return DecoderHandler.decode(case)


def dsl_encode(def_name: str, payload_dict: dict) -> bytes:
    config = ConfigLoader.load_config()
    program = config["program"]
    version = config["version"]

    case = load_case(program, version, def_name)
    if not case:
        raise ValueError(f"Unable to load DSL case: {def_name}")

    case_name, case_lines, _, _ = case

    # ---- RESET GLOBAL SESSION ----
    session = get_session()
    session.reset()

    # ---- PARSE NODES INTO session.fields ----
    NodeTreeParser.parse(case)

    # ---- BUILD A FAKE ENCODE-SESSION ----
    encode_session = {
        "definition": {
            "data": session.fields       # <-- detta är vad encodern behöver
        },
        "values": payload_dict
    }

    # ---- RUN ENCODER ----
    return EncoderHandler.encode_payload(case_name, payload_dict, session=encode_session)







#
# AUTH HANDLERS
#

def handle_AUTH_LOGON_CHALLENGE(client_socket, opcode, full_packet):
    """
    AUTH_LOGON_CHALLENGE_C handler.
    full_packet = opcode + error + size + payload
    """

    peer = client_socket.getpeername()
    Logger.info(f"RAW AUTH_LOGON_CHALLENGE_C: {full_packet.hex(' ')}")

    try:
        decoded = dsl_decode("AUTH_LOGON_CHALLENGE_C", full_packet)
        # Logger.info(f"[AUTH_LOGON_CHALLENGE_C] Decoded = {decoded}")
    except Exception as e:
        Logger.warning(f"DSL decode failed: {e}")
        decoded = {}

    #
    # Build server challenge (AUTH_LOGON_CHALLENGE_S)
    #
    response_fields = {
        "cmd": 0x00,
        "error": 0x00,
        "success": 0x00,

        "B": b"\x22" * 32,
        "l": 1,
        "g": 7,
        "blog": 1,

        "N": b"\x11" * 32,
        "s": b"\x33" * 32,

        "unk3": b"\x00" * 16,
        "securityFlags": 0x00
    }

    try:
        encoded = dsl_encode("AUTH_LOGON_CHALLENGE_S", response_fields)
        return 0, encoded

    except Exception as e:
        Logger.error(f"Encoding AUTH_LOGON_CHALLENGE_S failed: {e}")
        return 1, None


def handle_AUTH_LOGON_PROOF(client_socket, opcode, full_packet):
    """
    AUTH_LOGON_PROOF_C → AUTH_LOGON_PROOF_S
    """

    peer = client_socket.getpeername()
    Logger.info(f"RAW AUTH_LOGON_PROOF_C: {full_packet.hex(' ')}")

    try:
        decoded = dsl_decode("AUTH_LOGON_PROOF_C", full_packet)
        Logger.info(f"[AUTH_LOGON_PROOF_C] Decoded = {decoded}")
    except Exception as e:
        Logger.warning(f"DSL decode failed: {e}")
        decoded = {}

    # Minimal success answer
    response_fields = {
        "result": 0,   # AUTH_OK
    }

    try:
        encoded = dsl_encode("AUTH_LOGON_PROOF_S", response_fields)
        return 0, encoded

    except Exception as e:
        Logger.error(f"Encoding AUTH_LOGON_PROOF_S failed: {e}")
        return 1, None


def handle_REALM_LIST(client_socket, opcode, full_packet):
    try:
        decoded = dsl_decode("REALM_LIST_C", full_packet)
        Logger.info(f"[REALM_LIST_C] Decoded = {decoded}")
    except Exception:
        decoded = {}

    response_fields = {
        "realms": [
            {
                "realm_id": 1,
                "realm_type": 0,
                "flags": 0,
                "name": "DSL Test Realm",
                "address": "192.168.11.30:8085",
                "population": 1.0,
                "num_chars": 0,
                "timezone": 1,
                "realm_id2": 1,
            }
        ]
    }

    try:
        encoded = dsl_encode("REALM_LIST_S", response_fields)
        return 0, encoded

    except Exception as e:
        Logger.error(f"Encoding REALM_LIST_S failed: {e}")
        return 1, None


# OPCODE TABLE
opcode_handlers = {
    "AUTH_LOGON_CHALLENGE_C": handle_AUTH_LOGON_CHALLENGE,
    "AUTH_LOGON_PROOF": handle_AUTH_LOGON_PROOF,
    "REALM_LIST": handle_REALM_LIST,
}
