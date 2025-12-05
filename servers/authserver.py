#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal standalone authentication server used for debugging, replay testing,
and reverse-engineering of the MoP 5.4.8 login flow.

Responsibilities:
    • Accept incoming TCP connections on the auth port.
    • Decode incoming DSL-defined packets using the NodeTree + DecoderHandler.
    • Dispatch opcodes to dynamically resolved handlers (AuthHandler).
    • Encode and return server responses.
    • Maintain predictable, synchronous behaviour for testing.
"""

import socket
import signal
import traceback
import threading

from modules.DslRuntime import DslRuntime
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from utils.AutoRewrite import resolve_import

from protocols.mop.v18414.database.DatabaseConnection import DatabaseConnection
DatabaseConnection.initialize()


# ---- Dynamic imports ----------------------------------------------------

opcode_handlers = resolve_import("from handlers.AuthHandler import opcode_handlers")
opcode_pack = resolve_import("from protocols.AuthOpcodes import AUTH_CLIENT_OPCODES")

AUTH_CLIENT_OPCODES = opcode_pack["AUTH_CLIENT_OPCODES"]
AUTH_SERVER_OPCODES = opcode_pack["AUTH_SERVER_OPCODES"]
lookup = opcode_pack["lookup"]


# ---- Configuration ------------------------------------------------------

config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

HOST = config["authserver"]["host"]
PORT = 3724
running = True
runtime = None


# ---- Signal handling ---------------------------------------------------

def sigint(sig, frame):
    """Gracefully stop authserver on Ctrl+C."""
    global running
    Logger.info("Shutting down AuthServer (Ctrl+C)…")
    running = False


# ---- Client session handler --------------------------------------------

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

            if opcode_name is None:
                Logger.warning(f"{addr}: Unknown opcode 0x{opcode:02X}")
                Logger.info(f"Raw: {data.hex().upper()}")
                break

            try:
                Logger.info(f"Raw: {data.hex().upper()}")
                runtime.decode(opcode_name, data, silent=True)

            except Exception as exc:
                Logger.error(f"{addr}: DSL decode failed: {exc}")
                Logger.error(traceback.format_exc())

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
                Logger.info(f"{addr}: No response from handler")
                continue

            try:
                server_op = response[0]
                server_name = AUTH_SERVER_OPCODES.get(server_op)

                Logger.info("Direction: Client <-- Server")

                runtime.decode(server_name, response, silent=True)

                Logger.info(f"Raw: {response.hex().upper()}")

            except Exception as exc:
                Logger.error(f"DSL decode failed on server packet: {exc}")

            sock.send(response)

    except Exception as exc:
        Logger.error(f"{addr}: Unexpected error: {exc}")
        Logger.error(traceback.format_exc())

    finally:
        Logger.info(f"Closing connection from {addr}")
        sock.close()


# ---- Server loop -------------------------------------------------------

def start_server() -> None:
    """Start the listening loop for incoming authentication connections."""
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

            threading.Thread(
                target=handle_client,
                args=(sock, addr),
                daemon=True
            ).start()

        except socket.timeout:
            continue
        except Exception as exc:
            Logger.error(f"Server error: {exc}")
            Logger.error(traceback.format_exc())

    Logger.info("AuthServer stopping…")
    srv.close()


# ---- Main entry --------------------------------------------------------

if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint)

    try:
        runtime = DslRuntime(config["program"], config["version"], watch=True)
        runtime.load_all()
        Logger.info("[AuthServer] DSL runtime ready (watching defs)")
    except Exception as exc:
        Logger.error(f"[AuthServer] Failed to init runtime with watch: {exc}")
        runtime = DslRuntime(config["program"], config["version"], watch=False)
        runtime.load_all()

    Logger.info(
        f"{config['friendly_name']} "
        f"({config['program']}:{config['version']}) AuthServer (Minimal Mode)"
    )

    start_server()
