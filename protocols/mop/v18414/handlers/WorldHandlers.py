#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
World opcode handlers for the minimal worldserver.

Each handler follows the authserver pattern:
    handler(sock, opcode_int, payload_bytes) -> (err:int, response:bytes|None)

Responses must include the world header (size + opcode). Helpers below will
encode DSL payloads and prepend the correct header.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Dict, Callable, Tuple, Optional

from modules.EncoderHandler import EncoderHandler
from modules.DslRuntime import DslRuntime
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.OpcodeLoader import load_world_opcodes

# Lookup maps (opcode int -> name)
WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _ = load_world_opcodes()
# Reverse map for server opcodes: name -> opcode int
SERVER_OPCODE_BY_NAME = {name: code for code, name in WORLD_SERVER_OPCODES.items()}

# Track auth stage so first CMSG_AUTH_SESSION triggers challenge, second sends full init stream.
_auth_stage = 0
_runtime: Optional[DslRuntime] = None


def _get_runtime() -> DslRuntime:
    global _runtime
    if _runtime is None:
        cfg = ConfigLoader.load_config()
        try:
            rt = DslRuntime(cfg["program"], cfg["version"], watch=True)
            rt.load_all()
            _runtime = rt
            Logger.info("[WorldHandlers] DSL runtime ready (watching defs)")
        except Exception as exc:
            Logger.error(f"[WorldHandlers] Runtime init failed (watch disabled): {exc}")
            rt = DslRuntime(cfg["program"], cfg["version"], watch=False)
            rt.load_all()
            _runtime = rt
    return _runtime


# ---- Helpers: raw loader -----------------------------------------------

def _load_raw_packet(opcode_name: str) -> Optional[bytes]:
    """
    Load raw (header+payload) bytes for a server opcode from debug or captures.
    """
    cfg = ConfigLoader.load_config()
    paths = [
        Path("protocols") / cfg["program"] / cfg["version"] / "debug" / f"{opcode_name}.json",
        Path("misc") / "captures" / "debug" / f"{opcode_name}.json",
    ]

    for path in paths:
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            Logger.error(f"[WorldHandlers] Failed to read {path}: {exc}")
            continue

        raw_hex = data.get("raw_data_hex")
        if raw_hex:
            try:
                return bytes.fromhex(raw_hex.replace(" ", ""))
            except Exception:
                Logger.error(f"[WorldHandlers] Invalid raw_data_hex in {path}")
                continue

        header_hex = data.get("raw_header_hex")
        payload_hex = data.get("hex_compact") or data.get("hex_spaced")
        if header_hex and payload_hex:
            try:
                header_bytes = bytes.fromhex(header_hex.replace(" ", ""))
                payload_bytes = bytes.fromhex(payload_hex.replace(" ", ""))
                return header_bytes + payload_bytes
            except Exception:
                Logger.error(f"[WorldHandlers] Invalid hex fields in {path}")
                continue

    return None


def _concat_raw(opcodes: list[str]) -> Optional[bytes]:
    """Concatenate multiple raw packets (each already includes header)."""
    out = bytearray()
    for name in opcodes:
        raw = _load_raw_packet(name)
        if not raw:
            Logger.warning(f"[WorldHandlers] Missing raw for {name}")
            continue
        out.extend(raw)
    return bytes(out) if out else None


# ---- Helper: build world packet from DSL payload -----------------------

def build_world_packet(opcode_name: str, payload: bytes) -> bytes:
    """
    Prepend world header (uint16 size, uint16 opcode) to payload.
    Handles SMSG_AUTH_RESPONSE quirk where size includes header bytes.
    """
    opcode = SERVER_OPCODE_BY_NAME.get(opcode_name)
    if opcode is None:
        raise KeyError(f"Unknown server opcode: {opcode_name}")

    size = len(payload)
    if opcode == 0x01F6:  # MoP quirk: size includes header
        size += 4

    header = size.to_bytes(2, "little") + opcode.to_bytes(2, "little")
    return header + payload


def _log_cmsg(name: str, payload: bytes) -> None:
    """Decode and log client payload in JSON form."""
    try:
        rt = _get_runtime()
        decoded = rt.decode(name, payload, silent=True)
        Logger.success(f"[CMSG] {name}\n{json.dumps(decoded, indent=2)}")
    except Exception as exc:
        Logger.error(f"[CMSG] decode {name} failed: {exc}")


def _decode_payload(name: str, payload: bytes) -> dict:
    try:
        rt = _get_runtime()
        return rt.decode(name, payload, silent=True) or {}
    except Exception as exc:
        Logger.error(f"[CMSG] decode {name} failed: {exc}")
        return {}


# ---- Handlers ----------------------------------------------------------

def handle_CMSG_PING(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    """
    Simple ping/pong: echo ping value back in SMSG_PONG.
    """
    _log_cmsg("CMSG_PING", payload)
    try:
        ping_val = struct.unpack_from("<I", payload, 0)[0] if len(payload) >= 4 else 0
    except struct.error:
        ping_val = 0

    try:
        pong_payload = EncoderHandler.encode_packet("SMSG_PONG", {"ping_id": ping_val})
        response = build_world_packet("SMSG_PONG", pong_payload)
        return 0, response
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to encode SMSG_PONG: {exc}")
        return 1, None


def handle_CMSG_CONNECT_TO_WORLD(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_CONNECT_TO_WORLD", payload)
    # Handshake raw packet if available
    raw = _load_raw_packet("SMSG_CONNECT_TO_WORLD")
    if not raw:
        return 0, None
    return 0, raw


def handle_CMSG_AUTH_SESSION(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    global _auth_stage
    decoded = _decode_payload("CMSG_AUTH_SESSION", payload)
    account = decoded.get("account") or decoded.get("username") or decoded.get("I")
    build = decoded.get("build") or decoded.get("client_build")
    try:
        Logger.info(f"[CMSG_AUTH_SESSION] account={account} build={build}")
        if decoded:
            Logger.info(json.dumps(decoded, indent=2))
    except Exception:
        pass

    if _auth_stage == 0:
        _auth_stage = 1
        raw = _load_raw_packet("SMSG_AUTH_CHALLENGE")
        return 0, raw

    # Stage 1 → send full init stream for char screen
    server_packets = [
        "SMSG_AUTH_RESPONSE",
        "SMSG_ACCOUNT_DATA_TIMES",
        "SMSG_CLIENTCACHE_VERSION",
        "SMSG_FEATURE_SYSTEM_STATUS",
        "SMSG_MOTD",
        "SMSG_TUTORIAL_FLAGS",
        "SMSG_TIME_SYNC_REQUEST",
    ]
    raw = _concat_raw(server_packets)
    return 0, raw


def handle_CMSG_TIME_SYNC_RESPONSE(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_TIME_SYNC_RESPONSE", payload)
    # Typically no reply; keep connection alive.
    return 0, None


def handle_CMSG_ENUM_CHARACTERS(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_ENUM_CHARACTERS", payload)
    raw = _load_raw_packet("SMSG_ENUM_CHARACTERS_RESULT")
    return 0, raw


# ---- Opcode map --------------------------------------------------------

opcode_handlers: Dict[str, Callable[[object, int, bytes], Tuple[int, Optional[bytes]]]] = {
    "CMSG_PING": handle_CMSG_PING,
    "CMSG_CONNECT_TO_WORLD": handle_CMSG_CONNECT_TO_WORLD,
    "CMSG_AUTH_SESSION": handle_CMSG_AUTH_SESSION,
    "CMSG_TIME_SYNC_RESPONSE": handle_CMSG_TIME_SYNC_RESPONSE,
    "CMSG_ENUM_CHARACTERS": handle_CMSG_ENUM_CHARACTERS,
}
