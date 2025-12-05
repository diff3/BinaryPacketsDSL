#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal world server for debugging:
  - Listens on the configured world port.
  - Decodes world packets using in-memory DSL runtime (watch enabled when possible).
  - Optional opcode handlers (protocols/<program>/<version>/handlers/WorldHandlers.py).
  - Fallback: can reply with saved raw_data (header+payload) for unfinished packets.
"""

import importlib
import json
import socket
import signal
import threading
import traceback

from modules.DslRuntime import DslRuntime
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.OpcodeLoader import load_world_opcodes


# Map client opcodes → server response opcode to send as raw_data.
# Add entries for unfinished packets, e.g. {"CMSG_PING": "SMSG_PONG"}
RAW_RESPONSE_FALLBACKS: dict[str, str] = {}

# ---- Configuration ------------------------------------------------------

config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

HOST = config["worldserver"]["host"]
PORT = config["worldserver"]["port"]

runtime: DslRuntime | None = None
HANDSHAKE_SERVER = b"0\x00WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT\x00"
HANDSHAKE_CLIENT = b"0\x00WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER\x00"

WORLD_CLIENT_OPCODES, WORLD_SERVER_OPCODES, _world_lookup = load_world_opcodes()

try:
    handlers_mod = importlib.import_module(
        f"protocols.{config['program']}.{config['version']}.handlers.WorldHandlers"
    )
    opcode_handlers = getattr(handlers_mod, "opcode_handlers", {})
    Logger.info("[WorldServer] Loaded world opcode handlers")
except Exception:
    opcode_handlers = {}
    Logger.warning("[WorldServer] No WorldHandlers found, raw fallback only")


# ---- Helpers -----------------------------------------------------------

def recv_exact(sock: socket.socket, length: int) -> bytes | None:
    """Receive exactly length bytes or None on disconnect."""
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def parse_header(header: bytes) -> tuple[int | None, int | None, str]:
    """Parse world header (uint16 size, uint16 opcode)."""
    if len(header) < 4:
        return None, None, "0x????"
    size = int.from_bytes(header[0:2], "little")
    opcode = int.from_bytes(header[2:4], "little")
    return size, opcode, f"0x{opcode:04X}"


def opcode_name(direction: str, opcode: int) -> str | None:
    """Lookup opcode name by direction (C/S)."""
    if direction == "C":
        return WORLD_CLIENT_OPCODES.get(opcode)
    return WORLD_SERVER_OPCODES.get(opcode)


def load_saved_raw(opcode: str) -> bytes | None:
    """Load saved raw packet (header+payload) from protocol debug or captures."""
    base_proto = f"protocols/{config['program']}/{config['version']}/debug/{opcode}.json"
    base_cap = f"misc/captures/debug/{opcode}.json"

    for path in (base_proto, base_cap):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            continue
        except Exception as exc:  # malformed json
            Logger.error(f"[WorldServer] Failed to read raw for {opcode} from {path}: {exc}")
            continue

        raw_hex = data.get("raw_data_hex")
        if raw_hex:
            try:
                return bytes.fromhex(raw_hex.replace(" ", ""))
            except Exception:
                Logger.error(f"[WorldServer] Invalid raw_data_hex in {path}")
                continue

        # fallback: combine header + payload if available
        raw_header = data.get("raw_header_hex")
        payload = data.get("hex_compact") or data.get("hex_spaced")
        if raw_header and payload:
            try:
                header_bytes = bytes.fromhex(raw_header.replace(" ", ""))
                payload_bytes = bytes.fromhex(payload.replace(" ", ""))
                return header_bytes + payload_bytes
            except Exception:
                Logger.error(f"[WorldServer] Invalid hex fields in {path}")
                continue

    return None


def send_raw_response(sock: socket.socket, opcode: str) -> bool:
    """Send a saved raw packet; returns True if sent."""
    raw = load_saved_raw(opcode)
    if not raw:
        Logger.warning(f"[WorldServer] No saved raw_data for {opcode}")
        return False

    try:
        Logger.success(f"[WorldServer] → client {opcode} ({len(raw)} bytes)")
        Logger.success(raw.hex().upper())
        sock.sendall(raw)
        Logger.success(f"[WorldServer] Sent saved raw packet for {opcode} ({len(raw)} bytes)")
        return True
    except Exception as exc:
        Logger.error(f"[WorldServer] Failed to send raw {opcode}: {exc}")
        return False


# ---- Client handling ---------------------------------------------------

def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    Logger.info(f"[WorldServer] New connection from {addr}")
    try:
        sock.sendall(HANDSHAKE_SERVER)
        Logger.success(f"[WorldServer] → client HANDSHAKE ({len(HANDSHAKE_SERVER)} bytes)")
        Logger.success(HANDSHAKE_SERVER.hex().upper())
    except Exception as exc:
        Logger.error(f"[WorldServer] Failed to send handshake: {exc}")
        return

    try:
        while True:
            # Look for client handshake without consuming real packet data.
            try:
                peek = sock.recv(len(HANDSHAKE_CLIENT), socket.MSG_PEEK)
            except Exception:
                peek = b""

            if peek.startswith(HANDSHAKE_CLIENT):
                _ = recv_exact(sock, len(HANDSHAKE_CLIENT))
                Logger.info(f"[WorldServer] {addr}: received client HANDSHAKE")
                continue

            header = recv_exact(sock, 4)
            if not header:
                Logger.info(f"[WorldServer] {addr}: disconnected")
                break

            size, opcode, hexop = parse_header(header)
            if size is None or opcode is None:
                Logger.warning(f"[WorldServer] {addr}: invalid header {header.hex()}")
                break

            # MoP quirk: SMSG_AUTH_RESPONSE includes header size (4 bytes)
            payload_len = max(0, size - 4) if opcode == 0x01F6 else size
            payload = recv_exact(sock, payload_len) or b""

            name = opcode_name("C", opcode) or f"UNKNOWN_CMSG_{hexop}"

            Logger.info(f"[WorldServer] C→S {name} ({hexop}) size={payload_len}")
            Logger.info(f"[WorldServer] Raw: {(header + payload).hex().upper()}")

            try:
                runtime.decode(name, payload, silent=True)
            except Exception as exc:
                Logger.error(f"[WorldServer] DSL decode failed for {name}: {exc}")
                Logger.error(traceback.format_exc())

            handler = opcode_handlers.get(name)
            response = None
            err = 0

            if handler:
                try:
                    err, response = handler(sock, opcode, payload)
                except Exception as exc:
                    Logger.error(f"[WorldServer] Handler crash for {name}: {exc}")
                    Logger.error(traceback.format_exc())
                    err = 1

            if err != 0:
                Logger.warning(f"[WorldServer] Handler error for {name}, closing connection")
                break

            sent = False
            if response:
                try:
                    Logger.success(f"[WorldServer] → client ({len(response)} bytes)")
                    Logger.success(response.hex().upper())
                    sock.sendall(response)
                    sent = True
                    Logger.info(f"[WorldServer] Sent handler response ({len(response)} bytes)")
                except Exception as exc:
                    Logger.error(f"[WorldServer] Failed to send handler response: {exc}")
                    break

            # Optional raw fallback when no handler response produced
            if not sent and name in RAW_RESPONSE_FALLBACKS:
                target = RAW_RESPONSE_FALLBACKS[name]
                sent = send_raw_response(sock, target)
                if not sent:
                    Logger.warning(f"[WorldServer] Missing raw fallback for {target}")

    except Exception as exc:
        Logger.error(f"[WorldServer] {addr}: unexpected error {exc}")
        Logger.error(traceback.format_exc())
    finally:
        try:
            sock.close()
        except Exception:
            pass
        Logger.info(f"[WorldServer] Closed connection from {addr}")


# ---- Server loop ------------------------------------------------------

def start_server() -> None:
    ensure_runtime()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    Logger.info(f"[WorldServer] Listening on {HOST}:{PORT}")

    while True:
        sock, addr = srv.accept()
        threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()


# ---- Main --------------------------------------------------------------

def _init_runtime() -> DslRuntime:
    try:
        rt = DslRuntime(config["program"], config["version"], watch=True)
        rt.load_all()
        Logger.info("[WorldServer] DSL runtime ready (watching defs)")
        return rt
    except Exception as exc:
        Logger.error(f"[WorldServer] Failed to init runtime with watch: {exc}")
        rt = DslRuntime(config["program"], config["version"], watch=False)
        rt.load_all()
        return rt


def ensure_runtime() -> None:
    """Ensure DSL runtime is loaded before handling connections."""
    global runtime
    if runtime is None:
        runtime = _init_runtime()


def sigint(sig, frame):
    Logger.info("Shutting down WorldServer (Ctrl+C)…")
    raise SystemExit


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint)
    ensure_runtime()

    Logger.info(
        f"{config['friendly_name']} "
        f"({config['program']}:{config['version']}) WorldServer (Minimal Mode)"
    )

    start_server()
