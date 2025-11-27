#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import signal
import sys
import traceback
import threading
from modules.DecoderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser
from utils.Logger import Logger
from utils.ConfigLoader import ConfigLoader
from packets.AuthOpcodes import AUTH_CLIENT_OPCODES, AUTH_SERVER_OPCODES
from handlers.AuthHandler import opcode_handlers
from modules.Processor import load_case, load_all_cases, handle_add
import json


from modules.Session import get_session
# ----------------------------------------------------------
# LOAD CONFIG
# ----------------------------------------------------------
config = ConfigLoader.load_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

HOST = config["authserver"]["host"]
PORT = 3725

running = True    # global shutdown flag


# ----------------------------------------------------------
# SIGINT HANDLER
# ----------------------------------------------------------
def sigint(sig, frame):
    global running
    Logger.info("Shutting down AuthServer (Ctrl+C)...")
    running = False


# ----------------------------------------------------------
# OPCODE DEREFERENCE
# ----------------------------------------------------------

def get_opcode_name(direction, opcode):
    """
    direction = "C2S" or "S2C"
    Maps opcode byte → opcode_name
    """
    if direction == "C2S":
        return AUTH_CLIENT_OPCODES.get(opcode)
    else:
        return AUTH_SERVER_OPCODES.get(opcode)


# ----------------------------------------------------------
# CLIENT HANDLER
# ----------------------------------------------------------
def handle_client(client_socket, addr):
    Logger.info(f"New connection from {addr}")

    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                Logger.info(f"{addr}: disconnected")
                break

            opcode = data[0]
            opcode_name = AUTH_CLIENT_OPCODES.get(opcode)

            # Direction: client -> server
            Logger.info("Direction: Client --> Server")

            if not opcode_name:
                Logger.warning(f"{addr}: Unknown opcode 0x{opcode:02X}")
                Logger.info(f"Raw: {data!r}")
                break

            # Decode client packet via DSL
            try:
                case_name, def_lines, _, expected  = load_case(config['program'], config['version'], opcode_name)
                case = (case_name, def_lines, data, expected)

                session = get_session()
                session.reset()
                
                NodeTreeParser.parse(case)
                DecoderHandler.decode(case)
                
                Logger.info(f"Raw: {data!r}")

                #result = session.get_json()
               # Logger.success(opcode_name)
               
               # Logger.to_log(json.dumps(result, indent=4))

            except Exception as e:
                Logger.error(f"{addr}: DSL decode failed: {e}")
                Logger.error(traceback.format_exc())


            # Find handler
            handler = opcode_handlers.get(opcode_name)
            if not handler:
                Logger.warning(f"{addr}: No handler for {opcode_name}")
                break

            # Execute handler
            try:
                err, response = handler(client_socket, opcode, data)
            except Exception as e:
                Logger.error(f"{addr}: Handler crash: {e}")
                Logger.error(traceback.format_exc())
                break

            if err != 0:
                Logger.warning(f"{addr}: Handler returned error={err}")
                break

            # Send response (and decode it for logs)
            if response:
                server_opcode = response[0]
                server_case = AUTH_SERVER_OPCODES.get(server_opcode)

                Logger.info("Direction: Client <-- Server")
                # Logger.success(server_case)

                try:
                    case_name, def_lines, _, expected = load_case(config['program'], config['version'], server_case)
                    case = (case_name, def_lines, response, expected)
                    session.reset()
                    NodeTreeParser.parse(case)
                    DecoderHandler.decode(case)
                    Logger.info(f"Raw: {response!r}")
                except Exception as e:
                    Logger.error(f"DSL decode failed on server packet: {e}")

                client_socket.send(response)

            else:
                Logger.info(f"{addr}: No response from handler")

    except Exception as e:
        Logger.error(f"{addr}: Unexpected error: {e}")
        Logger.error(traceback.format_exc())

    finally:
        Logger.info(f"Closing connection from {addr}")
        client_socket.close()


# ----------------------------------------------------------
# SERVER LOOP
# ----------------------------------------------------------
def start_server():
    global running

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    Logger.info(f"AuthServer listening on {HOST}:{PORT}")

    while running:
        try:
            s.settimeout(1.0)
            client_socket, addr = s.accept()

            threading.Thread(
                target=handle_client,
                args=(client_socket, addr),
                daemon=True
            ).start()

        except socket.timeout:
            continue
        except Exception as e:
            Logger.error(f"Server error: {e}")
            Logger.error(traceback.format_exc())

    Logger.info("Server stopping...")
    s.close()


# ----------------------------------------------------------
# MAIN
# ----------------------------------------------------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigint)

    Logger.info("Mist of Pandaria 5.4.8 AuthServer (Minimal Mode)")
    start_server()