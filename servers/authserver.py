#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import signal
import traceback
import threading
import importlib
import sys
from pathlib import Path

# Ensure project root on sys.path when running as a script
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.dsl.DslRuntime import DslRuntime
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.AutoRewrite import resolve_import

config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"
program = config["program"]
version = config["version"]

mod = importlib.import_module(f"protocols.{program}.{version}.modules.database.DatabaseConnection")
DatabaseConnection = getattr(mod, "DatabaseConnection")
DatabaseConnection.initialize()


# ---- Dynamic imports ----------------------------------------------------

opcode_handlers = resolve_import("from handlers.AuthHandler import opcode_handlers")
opcode_pack = resolve_import("from protocols.AuthOpcodes import AUTH_CLIENT_OPCODES")

AUTH_CLIENT_OPCODES = opcode_pack["AUTH_CLIENT_OPCODES"]
AUTH_SERVER_OPCODES = opcode_pack["AUTH_SERVER_OPCODES"]
lookup = opcode_pack["lookup"]


HOST = config["authserver"]["host"]
PORT = config["authserver"]["port"]
running = True
runtime = None


# ---- Signal handling ----------------------------------------------------

def sigint(sig, frame):
    """Gracefully stop authserver on Ctrl+C."""
    global running
    Logger.info("Shutting down AuthServer (Ctrl+C)…")
    running = False


# ---- Utility helpers ----------------------------------------------------

def safe_decode(direction: str, name: str, payload: bytes):
    """Decode DSL packets without crashing handler logic."""
    try:
        runtime.decode(name, payload, silent=True)
    except Exception as exc:
        Logger.error(f"{direction}: decode failed for {name}: {exc}")
        Logger.error(traceback.format_exc())


# ---- Client session handler ---------------------------------------------

def handle_client(sock: socket.socket, addr: tuple[str, int]) -> None:
    """Handle a single authentication client connection."""
    Logger.info(f"New connection from {addr}")

    try:
        while True:
            data = sock.recv(1024)
            if not data:
                Logger.info(f"{addr}: disconnected")
                break

            opcode = data[0]
            opcode_name = AUTH_CLIENT_OPCODES.get(opcode)

            Logger.info("Direction: Client --> Server")
            Logger.info(f"Raw: {data.hex().upper()}")

            if opcode_name is None:
                Logger.warning(f"{addr}: Unknown opcode 0x{opcode:02X}")
                break

            safe_decode("Client", opcode_name, data)

            handler = opcode_handlers.get(opcode_name)
            if handler is None:
                Logger.warning(f"{addr}: No handler for {opcode_name}")
                break

            try:
                err, response = handler(sock, opcode, data)
            except Exception as exc:
                Logger.error(f"{addr}: Handler crash: {exc}")
                Logger.error(traceback.format_exc())
                break

            if err != 0:
                Logger.warning(f"{addr}: Handler returned error={err}")
                break

            if not response:
                Logger.info(f"{addr}: Handler returned no response")
                continue

            server_op = response[0]
            server_name = AUTH_SERVER_OPCODES.get(server_op)

            Logger.info("Direction: Client <-- Server")
            Logger.info(f"Raw: {response.hex().upper()}")

            if server_name:
                safe_decode("Server", server_name, response)

            try:
                sock.send(response)
            except Exception as exc:
                Logger.error(f"{addr}: Failed to send response: {exc}")
                break

    except Exception as exc:
        Logger.error(f"{addr}: Unexpected error: {exc}")
        Logger.error(traceback.format_exc())

    finally:
        Logger.info(f"Closing connection from {addr}")
        sock.close()


# ---- Server loop --------------------------------------------------------

def start_server() -> None:
    global running

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)

    Logger.info(f"AuthServer listening on {HOST}:{PORT}")

    while running:
        try:
            srv.settimeout(1.0)
            sock, addr = srv.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as exc:
            Logger.error(f"Server error: {exc}")
            Logger.error(traceback.format_exc())

    Logger.info("AuthServer stopping…")
    srv.close()


# ---- Main entry ---------------------------------------------------------

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint)

    try:
        # AuthServer: ingen JSON, ingen watcher — exakt som proxyn
        runtime = DslRuntime(config["program"], config["version"], watch=False)
        runtime.load_runtime_all()
        Logger.info("[AuthServer] DSL runtime ready (runtime mode, no JSON)")
    except Exception as exc:
        Logger.error(f"[AuthServer] Runtime init failed (runtime mode): {exc}")
        runtime = DslRuntime(config["program"], config["version"], watch=False)
        runtime.load_runtime_all()

    Logger.info(
        f"{config['friendly_name']} "
        f"({config['program']}:{config['version']}) AuthServer (Minimal Mode)"
    )

    start_server()
