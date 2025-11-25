#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import signal
import sys
import threading
import traceback

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.BaseServerTemplates import BaseServer
from packets.AuthOpcodes import AUTH_OPCODES
from handlers.AuthHandler import opcode_handlers

config = ConfigLoader.load_config()


class AuthServer(BaseServer):
    """
    Minimal MoP authentication server.
    MoP Auth format:
        uint8 opcode
        uint8 error
        uint16 size (LE)
        <size bytes payload>
    """

    def handle_client(self, client_socket):
        try:
            peer = client_socket.getpeername()
        except Exception:
            peer = ("<unknown>", 0)

        Logger.info(f"New auth connection from {peer}")

        try:
            while not self.stop_event.is_set():

                # --- Läs opcode ---
                opcode_raw = client_socket.recv(1)
                if not opcode_raw:
                    break
                opcode = opcode_raw[0]

                # --- Läs error + size (3 bytes) ---
                hdr = client_socket.recv(3)
                if len(hdr) < 3:
                    break

                error = hdr[0]
                size = int.from_bytes(hdr[1:3], "little")

                # --- Läs payload ---
                payload = client_socket.recv(size)
                if len(payload) < size:
                    break

                # --- Bygg fullständigt paket ---
                full_packet = opcode_raw + hdr + payload

                # Hitta namn för opcode
                opcode_name = AUTH_OPCODES.get(opcode)
                if opcode_name is None:
                    Logger.warning(f"{peer}: Unknown opcode 0x{opcode:02X}")
                    break

                Logger.info(f"{peer}: {opcode_name} (0x{opcode:02X})")

                # Hitta handler
                handler = opcode_handlers.get(opcode_name)
                if handler is None:
                    Logger.warning(f"{peer}: No handler for opcode {opcode_name}")
                    break

                # CALL HANDLER
                # handler(client, opcode, full_packet)
                try:
                    err, response = handler(client_socket, opcode, full_packet)
                except Exception as e:
                    Logger.error(f"Handler crash in {opcode_name}: {e}")
                    Logger.error(traceback.format_exc())
                    break

                if err != 0:
                    Logger.warning(f"{peer}: handler returned error={err}")
                    break

                if response:
                    client_socket.sendall(response)

        except Exception as e:
            Logger.error(f"AuthServer error for {peer}: {e}\n{traceback.format_exc()}")

        finally:
            Logger.info(f"Closing auth connection from {peer}")
            try:
                client_socket.close()
            except Exception:
                pass


if __name__ == "__main__":
    stop_event = threading.Event()

    def handle_sigint(sig, frame):
        Logger.info("Shutting down AuthServer...")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    Logger.info("Mist of Pandaria 5.4.8 AuthServer (DSL-powered)")

    auth_server = AuthServer(
        local_host=config["authserver"]["host"],
        local_port=config["authserver"]["port"],
        stop_event=stop_event
    )

    auth_thread = threading.Thread(target=auth_server.start_server, daemon=True)
    auth_thread.start()

    try:
        auth_thread.join()
    except KeyboardInterrupt:
        Logger.info("Exiting...")
        sys.exit(0)