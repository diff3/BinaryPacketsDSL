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
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.OpcodeLoader import load_world_opcodes
from modules.interpretation.utils import dsl_decode, to_safe_json

# Lookup maps (opcode int -> name)
WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _ = load_world_opcodes()
# Reverse map for server opcodes: name -> opcode int
SERVER_OPCODE_BY_NAME = {name: code for code, name in WORLD_SERVER_OPCODES.items()}

# Track auth stage per server process.
# 0 = need to send challenge, 1 = ready to send init stream
_auth_stage = 0


# ---- Helpers: raw loader -----------------------------------------------

def _load_raw_from_path(path: Path) -> Optional[bytes]:
    """Load raw (header+payload) bytes from a JSON dump path."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to read {path}: {exc}")
        return None

    raw_hex = data.get("raw_data_hex")
    if raw_hex:
        try:
            return bytes.fromhex(raw_hex.replace(" ", ""))
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid raw_data_hex in {path}")
            return None

    header_hex = data.get("raw_header_hex")
    payload_hex = data.get("hex_compact") or data.get("hex_spaced")
    if header_hex and payload_hex:
        try:
            header_bytes = bytes.fromhex(header_hex.replace(" ", ""))
            payload_bytes = bytes.fromhex(payload_hex.replace(" ", ""))
            return header_bytes + payload_bytes
        except Exception:
            Logger.error(f"[WorldHandlers] Invalid hex fields in {path}")
            return None
    return None


def _load_raw_packet(opcode_name: str) -> Optional[bytes]:
    """
    Load raw (header+payload) bytes for a server opcode from debug or captures.
    Includes focus captures if present.
    """
    cfg = ConfigLoader.load_config()
    paths = [
        Path("protocols") / cfg["program"] / cfg["version"] / "debug" / f"{opcode_name}.json",
        Path("misc") / "captures" / "debug" / f"{opcode_name}.json",
        Path("misc") / "captures" / "focus" / "debug" / f"{opcode_name}.json",
    ]

    for path in paths:
        if not path.exists():
            continue
        raw = _load_raw_from_path(path)
        if raw:
            return raw

    return None


def _load_focus_sequence(opcode_name: str) -> list[bytes]:
    """
    Load a sequence of focus-dump packets for the given opcode, sorted by timestamp suffix.
    Files are expected to follow the pattern <opcode>_<ts>.json in misc/captures/focus/debug.
    """
    focus_dir = Path("misc") / "captures" / "focus" / "debug"
    if not focus_dir.exists():
        return []

    matches = []
    for path in focus_dir.glob(f"{opcode_name}_*.json"):
        try:
            ts_part = path.stem.rsplit("_", 1)[-1]
            ts = int(ts_part)
        except Exception:
            continue
        matches.append((ts, path))

    raws: list[bytes] = []
    for _, path in sorted(matches, key=lambda x: x[0]):
        raw = _load_raw_from_path(path)
        if raw:
            raws.append(raw)
    return raws


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


def _concat_raw_bytes(raws: list[bytes]) -> Optional[bytes]:
    """Concatenate a list of raw packets."""
    out = bytearray()
    for raw in raws:
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
        decoded = dsl_decode(name, payload, silent=True)
        safe = to_safe_json(decoded)
        Logger.success(f"[CMSG] {name}\n{json.dumps(safe, indent=2)}")
    except Exception as exc:
        Logger.error(f"[CMSG] decode {name} failed: {exc}")


def _decode_payload(name: str, payload: bytes) -> dict:
    try:
        return dsl_decode(name, payload, silent=True) or {}
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

    # If client somehow sends AUTH_SESSION without prior challenge, serve challenge first.
    if _auth_stage == 0:
        _auth_stage = 1
        raw = _load_raw_packet("SMSG_AUTH_CHALLENGE")
        return 0, raw

    # Stage 1 → send full init stream for char screen
    server_packets = [
        "SMSG_AUTH_RESPONSE",
        "SMSG_ADDON_INFO",
        "SMSG_CLIENTCACHE_VERSION",
        "SMSG_BATTLE_PAY_DISTRIBUTION_UPDATE",
        "SMSG_TUTORIAL_FLAGS",
        "SMSG_SET_TIME_ZONE_INFORMATION",
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


def handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_READY_FOR_ACCOUNT_DATA_TIMES", payload)
    raw = _load_raw_packet("SMSG_ACCOUNT_DATA_TIMES")
    return 0, raw


def handle_CMSG_CHAR_CREATE(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_CHAR_CREATE", payload)
    raw = _load_raw_packet("SMSG_CHAR_CREATE")
    return 0, raw


def handle_CMSG_CHAR_DELETE(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_CHAR_DELETE", payload)
    raw = _load_raw_packet("SMSG_CHAR_DELETE")
    return 0, raw


def handle_CMSG_BATTLE_PAY_GET_PURCHASE_LIST(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_BATTLE_PAY_GET_PURCHASE_LIST", payload)
    raw = _load_raw_packet("SMSG_BATTLE_PAY_DISTRIBUTION_UPDATE")
    return 0, raw


def handle_CMSG_REQUEST_HOTFIX(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_REQUEST_HOTFIX", payload)
    raw = _load_raw_packet("SMSG_HOTFIX_NOTIFY_BLOB")
    if raw:
        return 0, raw
    # Fallback: minimal blob of four zero bytes
    payload_out = b"\x00\x00\x00\x00"
    try:
        return 0, build_world_packet("SMSG_HOTFIX_NOTIFY_BLOB", payload_out)
    except Exception as exc:
        Logger.error(f"[WorldHandlers] Failed to build HOTFIX blob: {exc}")
        return 1, None


def handle_CMSG_REQUEST_CEMETERY_LIST(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_REQUEST_CEMETERY_LIST", payload)
    raw = _load_raw_packet("SMSG_REQUEST_CEMETERY_LIST_RESPONSE")
    return 0, raw


def _login_world_stream() -> Optional[bytes]:
    """
    Full world-login stream after player login/loading screen notify.
    """
    stream = bytearray()

    # Always send world verify first
    raw = _load_raw_packet("SMSG_LOGIN_VERIFY_WORLD")
    if raw:
        stream.extend(raw)

    # Include focus-dumped UPDATE_OBJECT packets in timestamp order if available.
    focus_updates = _load_focus_sequence("SMSG_UPDATE_OBJECT")
    if focus_updates:
        cu = _concat_raw_bytes(focus_updates)
        if cu:
            stream.extend(cu)
    else:
        raw = _load_raw_packet("SMSG_UPDATE_OBJECT")
        if raw:
            stream.extend(raw)

    # Then remaining login packets
    for name in ("SMSG_MOVE_SET_ACTIVE_MOVER", "SMSG_TIME_SYNC_REQUEST", "SMSG_INIT_WORLD_STATES", "SMSG_LOGIN_SET_TIME_SPEED"):
        raw = _load_raw_packet(name)
        if raw:
            stream.extend(raw)

    return bytes(stream) if stream else None


def handle_CMSG_PLAYER_LOGIN(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_PLAYER_LOGIN", payload)
    return 0, _login_world_stream()


def handle_CMSG_LOADING_SCREEN_NOTIFY(sock, opcode: int, payload: bytes) -> Tuple[int, Optional[bytes]]:
    _log_cmsg("CMSG_LOADING_SCREEN_NOTIFY", payload)
    return 0, _login_world_stream()


def get_auth_challenge() -> Optional[bytes]:
    """
    Expose auth challenge for servers that need to send it immediately after handshake.
    """
    global _auth_stage
    _auth_stage = 1
    return _load_raw_packet("SMSG_AUTH_CHALLENGE")


def reset_state() -> None:
    """Reset handler state between client sessions."""
    global _auth_stage
    _auth_stage = 0


# ---- Opcode map --------------------------------------------------------

opcode_handlers: Dict[str, Callable[[object, int, bytes], Tuple[int, Optional[bytes]]]] = {
    "CMSG_PING": handle_CMSG_PING,
    "CMSG_CONNECT_TO_WORLD": handle_CMSG_CONNECT_TO_WORLD,
    "CMSG_AUTH_SESSION": handle_CMSG_AUTH_SESSION,
    "CMSG_TIME_SYNC_RESPONSE": handle_CMSG_TIME_SYNC_RESPONSE,
    "CMSG_ENUM_CHARACTERS": handle_CMSG_ENUM_CHARACTERS,
    "CMSG_READY_FOR_ACCOUNT_DATA_TIMES": handle_CMSG_READY_FOR_ACCOUNT_DATA_TIMES,
    "CMSG_CHAR_CREATE": handle_CMSG_CHAR_CREATE,
    "CMSG_CHAR_DELETE": handle_CMSG_CHAR_DELETE,
    "CMSG_BATTLE_PAY_GET_PURCHASE_LIST": handle_CMSG_BATTLE_PAY_GET_PURCHASE_LIST,
    "CMSG_PLAYER_LOGIN": handle_CMSG_PLAYER_LOGIN,
    "CMSG_LOADING_SCREEN_NOTIFY": handle_CMSG_LOADING_SCREEN_NOTIFY,
    "CMSG_REQUEST_HOTFIX": handle_CMSG_REQUEST_HOTFIX,
   # "CMSG_REQUEST_CEMETERY_LIST": handle_CMSG_REQUEST_CEMETERY_LIST, # Saknar raw data
}
