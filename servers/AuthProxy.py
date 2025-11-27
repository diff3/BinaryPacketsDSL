#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import argparse
import time

from modules.DecoderHandler import DecoderHandler
from modules.NodeTreeParser import NodeTreeParser
from modules.Processor import load_case
from modules.Session import get_session

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from utils.PacketDump import PacketDump, dump_capture

from packets.AuthOpcodes import lookup


config = ConfigLoader.load_config()

HOST = config["authserver"]["host"]
PORT = config["authserver"]["port"]
config['Logging']['logging_levels'] = "Information, Success, Script, Error"

PROXY_HOST = config["proxyserver"]["auth_host"]
PROXY_PORT = config["proxyserver"]["auth_port"]


class AutoAuthProxy:
    def __init__(self, listen_host, listen_port, forward_host, forward_port, dump=False, update=False):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.forward_host = forward_host
        self.forward_port = forward_port

        self.dump = dump          # Write to captures/
        self.update = update      # Overwrite packets/<program>/<version>/
        self.stop_event = threading.Event()

        # normal dumper for update mode
        self.dumper = PacketDump(f"packets/{config['program']}/{config['version']}")

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.listen_host, self.listen_port))
        sock.listen(5)

        Logger.info(f"AutoAuthProxy listening on {self.listen_host}:{self.listen_port}")

        while not self.stop_event.is_set():
            client_sock, addr = sock.accept()
            Logger.success(f"Client connected: {addr}")

            threading.Thread(
                target=self.handle_client,
                args=(client_sock,),
                daemon=True
            ).start()

    def stop(self):
        self.stop_event.set()

    def handle_client(self, client_sock):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((self.forward_host, self.forward_port))

        while not self.stop_event.is_set():
            data = client_sock.recv(4096)
            if not data:
                break

            self.process_packet(data, "C2S")
            server_sock.sendall(data)

            reply = server_sock.recv(4096)
            if not reply:
                break

            self.process_packet(reply, "S2C")
            client_sock.sendall(reply)

        client_sock.close()
        server_sock.close()

    def process_packet(self, data: bytes, direction: str):
        if not data:
            return

        opcode = data[0]
        case_name = lookup(direction, opcode)

        if not case_name:
            Logger.warning(f"[Unknown AUTH opcode] dir={direction} opcode={opcode:02X} raw={data.hex()}")
            return

        nice_dir = "Client → Server" if direction == "C2S" else "Client ← Server"
        Logger.info(f"Direction: {nice_dir} ({case_name})")

        # DSL decode
        case_name, def_lines, _, expected = load_case(
            config["program"], config["version"], case_name.upper()
        )

        session = get_session()
        session.reset()

        case = (case_name, def_lines, data, expected)
        NodeTreeParser.parse(case)
        decoded = DecoderHandler.decode(case)

        # --- UPDATE MODE (overwrite canonical packet dirs) ---
        if self.update:
            bin_p, json_p, dbg_p = self.dumper.dump_fixed(case_name, data, decoded)
            Logger.success(f"[UPDATE] Updated: {bin_p}")
        
        # --- DUMP MODE (timestamped capture → captures/) ---
        elif self.dump:
            bin_p, json_p, dbg_p = dump_capture(case_name, data, decoded)
            Logger.success(f"[DUMP] Captured: {bin_p}")

        # Always log hex
        Logger.info(f"Raw: {data.hex().upper()}")


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", action="store_true",
                    help="Write timestamped captures to ./captures/")
    ap.add_argument("--update", action="store_true",
                    help="Overwrite saved packet bin/json/debug in packets/<program>/<version>/")
    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()

    Logger.info(f"Starting AutoAuthProxy (dump={args.dump}, update={args.update})")

    proxy = AutoAuthProxy(
        listen_host=PROXY_HOST,
        listen_port=PROXY_PORT,
        forward_host=HOST,
        forward_port=3724,
        dump=args.dump,
        update=args.update
    )

    try:
        proxy.start()
    except KeyboardInterrupt:
        Logger.info("Shutting down AutoAuthProxy...")
        proxy.stop()