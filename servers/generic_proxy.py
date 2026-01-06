#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
from utils.Logger import Logger


class GenericProxy:
    """
    Minimal transparent TCP proxy (no protocol awareness).
    """

    def __init__(self, listen_host, listen_port, target_host, target_port, name="Proxy"):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.name = name

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.listen_host, self.listen_port))
        srv.listen(5)

        Logger.info(
            f"[{self.name}] Listening on {self.listen_host}:{self.listen_port} "
            f"→ {self.target_host}:{self.target_port}"
        )

        while True:
            client_sock, addr = srv.accept()
            Logger.success(f"[{self.name}] Client connected: {addr}")
            t = threading.Thread(
                target=self.handle_client, args=(client_sock,), daemon=True
            )
            t.start()

    def handle_client(self, client_sock):
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((self.target_host, self.target_port))
        except Exception as exc:
            Logger.error(f"[{self.name}] Failed to connect: {exc}")
            try:
                client_sock.close()
            except Exception:
                pass
            return

        threading.Thread(
            target=self.forward, args=(client_sock, target_sock, "C→S"), daemon=True
        ).start()
        self.forward(target_sock, client_sock, "S→C")

        try:
            client_sock.close()
            target_sock.close()
        except Exception:
            pass

        Logger.info(f"[{self.name}] Closed connection")

    def forward(self, src, dst, direction):
        try:
            while True:
                buf = src.recv(4096)
                if not buf:
                    break
                dst.sendall(buf)
        except Exception as exc:
            Logger.error(f"[{self.name} {direction}] Error: {exc}")
