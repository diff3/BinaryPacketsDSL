#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import binascii
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger


# ============================================================
# Minimal Socket Forwarder
# ============================================================

def forward(src, dst, tag):
    """
    Very simple forwarder: reads data from src, logs hex dump,
    forwards to dst. No decoding, no opcodes, no exceptions hidden.
    """
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break

            # print raw as hex
            hexstr = binascii.hexlify(data).decode()
            Logger.info(f"[{tag}] {hexstr}")

            dst.sendall(data)

    except Exception as e:
        Logger.error(f"[{tag}] {e}")
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass


# ============================================================
# Minimal Proxy Class
# ============================================================

class MiniProxy:
    def __init__(self, listen_host, listen_port, target_host, target_port, tag):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.tag = tag

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.listen_host, self.listen_port))
        s.listen(5)

        Logger.success(
            f"[{self.tag}] Listening on {self.listen_host}:{self.listen_port} → "
            f"{self.target_host}:{self.target_port}"
        )

        while True:
            client_sock, addr = s.accept()
            Logger.success(f"[{self.tag}] Client connected from {addr}")

            t = threading.Thread(target=self.handle_client, args=(client_sock,))
            t.daemon = True
            t.start()

    def handle_client(self, client_sock):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((self.target_host, self.target_port))
        except Exception as e:
            Logger.error(f"[{self.tag}] Connection to target failed: {e}")
            client_sock.close()
            return

        # Start forwarders
        threading.Thread(
            target=forward, args=(client_sock, server_sock, f"{self.tag} C→S"), daemon=True
        ).start()

        forward(server_sock, client_sock, f"{self.tag} S→C")

        Logger.info(f"[{self.tag}] Connection closed")


# ============================================================
# Main entry
# ============================================================

def start():
    cfg = ConfigLoader.load_config()

    # AUTH
    auth_proxy = MiniProxy(
        cfg["auth_proxy"]["listen_host"],
        cfg["auth_proxy"]["listen_port"],
        cfg["auth_proxy"]["auth_host"],
        cfg["auth_proxy"]["auth_port"],
        tag="AUTH"
    )

    # WORLD
    world_proxy = MiniProxy(
        cfg["world_proxy"]["listen_host"],
        cfg["world_proxy"]["listen_port"],
        cfg["world_proxy"]["world_host"],
        cfg["world_proxy"]["world_port"],
        tag="WORLD"
    )

    # Start AUTH in background
    threading.Thread(target=auth_proxy.start, daemon=True).start()

    # Start WORLD in foreground
    world_proxy.start()


if __name__ == "__main__":
    start()
