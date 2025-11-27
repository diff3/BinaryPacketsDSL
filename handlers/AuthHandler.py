#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader

from modules.DecoderHandler import DecoderHandler
from modules.EncoderHandler import EncoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_case
from modules.Session import get_session
import os

from modules.SRP6Session import SRP6Session

# ============================================================
# SRP-KONTON – 100% SkyFire-kompatibla
# (kan sen bytas mot riktig DB)
# ============================================================

accounts = {
    "MAPE": {
        "salt": bytes.fromhex("3DFEF7D2F4A66F1493A4701DC9281B97D20A9FBEB39BEC52E6EF2E0B7CD41009"),
        "verifier": bytes.fromhex("8DBD5FBE3E640D8CEC9ABD35A99E4B37C6E1C2B87E82A6BCC3A498FC35836470"),
    },
    "ADMIN": {
        "salt": bytes.fromhex("55b0ef553b6dcb6122904c3e5b19ba92de779d94c87aa55d2b9476fceb829b01"),
        "verifier": bytes.fromhex("ef91baf1d2ddaa19dc1031cb2ae618c480eee645c60198c29cb76639be071866"),
    },
      "MAGNUS": {
        "salt": bytes.fromhex("9ed8b7f17f66d37f38a1437013f48c2dee030f6b66a3a61943745a40bfe6ab26"),
        "verifier": bytes.fromhex("f54e40eafc651c89d93c45aa427fcfb7ad405dbdaaea5fe8454e2e905c820b00"),
    },
     "USER": {
        "salt": bytes.fromhex(
            "E2ED4C176D65006641247050F8DFF9C03B2994B5B9EBBEDEB2005A77385AE42C"
        ),
        "verifier": bytes.fromhex(
            "BF14225D6E5A1FE186536F8DC89124EDD220B08DF9732BA31CEF6ABA1159A448"
        ),
    },
}

# Socket-sessioner
srp6_sessions = {}

# ============================================================
# DSL helpers
# ============================================================

def encode_bytes(obj):
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).hex().upper()
    return obj


def dsl_decode(def_name: str, payload: bytes, silent=False) -> dict:
    cfg = ConfigLoader.load_config()
    case = load_case(cfg["program"], cfg["version"], def_name)
    name, lines, _, prev = case
    case = (name, lines, payload, prev)

    session = get_session()
    session.reset()

    NodeTreeParser.parse(case)
    return DecoderHandler.decode(case, silent=silent)

def dsl_encode(def_name: str, values: dict) -> bytes:
    cfg = ConfigLoader.load_config()
    case = load_case(cfg["program"], cfg["version"], def_name)
    name, lines, _, _ = case

    session = get_session()
    session.reset()

    NodeTreeParser.parse(case)
    return EncoderHandler.encode_from_session(name, values, session)


# ============================================================
# AUTH_LOGON_CHALLENGE
# ============================================================

def handle_AUTH_LOGON_CHALLENGE(client_socket, opcode, full_packet):
    try:
        decoded = dsl_decode("AUTH_LOGON_CHALLENGE_C", full_packet, silent=True)
        # Logger.success("AUTH_LOGON_CHALLENGE_C" + json.dumps(decoded, indent=4))
    except Exception as e:
        Logger.error(f"Decode failed: {e}")
        return 1, None

    username = decoded.get("I", "")
    if not username:
        Logger.error("Missing username in challenge")
        return 1, None

    username_u = username.upper()
    if username_u not in accounts:
        Logger.error(f"Unknown user {username_u}")
        return 1, None

    Logger.info(f"SRP6 begin for {username_u}")

    salt = accounts[username_u]["salt"]
    verifier = accounts[username_u]["verifier"]

    # Skapa SRP6 session
    session = SRP6Session(username_u, salt, verifier)
    fd = client_socket.fileno()
    srp6_sessions[fd] = session

    # Hämta endast SRP6-centrerade värden:
    srp = session.build_challenge()

    # ----------------------------------------------------------
    # Här bygger vi ett komplett DSL-paket för CHALLENGE_S
    # ----------------------------------------------------------

    fields = {
        # header
        "cmd": 0x00,
        "error": 0x00,

        # data
        "success": 0x00,
        "B": srp["B"],
        "l": 1,
        "g": srp["g"],

        # ALWAYS 32 for WoW SRP6 (length of N)
        "blob": 32,

        "N": srp["N"],
        "s": srp["s"],

        # MUST be 16 random bytes (client includes in M1 hash)
        "unk3": os.urandom(16),

        "securityFlags": 0,
    }

    # Logger.success("AUTH_LOGON_CHALLENGE_S")
    Logger.to_log(json.dumps(fields, indent=4, default=encode_bytes))

    # Kodning
    try:
        packet = dsl_encode("AUTH_LOGON_CHALLENGE_S", fields)
        return 0, packet
    except Exception as e:
        Logger.error(f"Encoding failed: {e}")
        srp6_sessions.pop(fd, None)
        return 1, None


# ============================================================
# AUTH_LOGON_PROOF
# ============================================================
def handle_AUTH_LOGON_PROOF(client_socket, opcode, full_packet):
    """
    Handles AUTH_LOGON_PROOF_C using SRP6Session.
    """
    try:
        decoded = dsl_decode("AUTH_LOGON_PROOF_C", full_packet, silent=True)
        # Logger.success("AUTH_LOGON_PROOF_C" + json.dumps(decoded, indent=4))
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_PROOF] Decode failed: {exc}")
        return 1, None

    fd = client_socket.fileno()
    session = srp6_sessions.get(fd)
    if not session:
        Logger.error("[AUTH_LOGON_PROOF] Missing SRP6 session")
        return 1, None


    # --------------------------------------------------------------
    # Parse client input
    # --------------------------------------------------------------
    try:
        A = bytes.fromhex(decoded["A"])
        M1 = bytes.fromhex(decoded["M1"])
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_PROOF] Invalid A/M1: {exc}")
        srp6_sessions.pop(fd, None)
        return 1, None

    # --------------------------------------------------------------
    # Perform SRP6 proof verification
    # --------------------------------------------------------------
    ok, M2, fields = session.verify_proof(A, M1)

    if not ok:
        Logger.error("[AUTH_LOGON_PROOF] SRP6 proof failed, closing session")
        srp6_sessions.pop(fd, None)
        return 1, None

    try:
        out_packet = dsl_encode("AUTH_LOGON_PROOF_S", fields)
    except Exception as exc:
        Logger.error(f"[AUTH_LOGON_PROOF_S] Encoding failed: {exc}")
        srp6_sessions.pop(fd, None)
        return 1, None

    srp6_sessions.pop(fd, None)
    return 0, out_packet



# ============================================================
# REALM_LIST
# ============================================================

def handle_REALM_LIST(client_socket, opcode, full_packet):
    try:
        decoded = dsl_decode("REALM_LIST_C", full_packet)
        Logger.info(f"[REALM_LIST_C] Decoded = {decoded}")
    except Exception:
        pass

    fields = {
        "cmd": 0x10,
        "size": 0,
        "realm_list_size": 1,
        "realmlist": [
            {
                "icon": 0,
                "lock": 0,
                "flag": 0,
                "name": "Azarim",
                "address": "192.168.11.30:8085",
                "pop": 0.0,
                "characters": 0,
                "timezone": 1,
                "realmid": 1,
            }
        ],
        "unk2": 16,
        "unk3": 0,
    }
    out = "102C00000000000100000000417A6172696D003139322E3136382E31312E33303A3830383500000000000101011000"
    # out = dsl_encode("REALM_LIST_S", fields)
    return 0, bytes.fromhex(out)


# ============================================================
# OPCODE MAP
# ============================================================

opcode_handlers = {
    "AUTH_LOGON_CHALLENGE_C": handle_AUTH_LOGON_CHALLENGE,
    "AUTH_LOGON_PROOF_C":     handle_AUTH_LOGON_PROOF,
    "REALM_LIST_C":           handle_REALM_LIST,
}