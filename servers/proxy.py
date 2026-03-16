#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Bidirectional TCP proxy.
Version: 0.3

State-aware, datacentric design.

WARNING:
Default listen_host is 127.0.0.1.
Binding to 0.0.0.0 exposes the proxy to the network.
"""

import os
import socket
import threading
import itertools
import signal
from logging.handlers import RotatingFileHandler
import logging
import asyncio

from utils.config_loader import ConfigLoader
from state import SessionState, GlobalState
from state_machine import update_state
from adapters import apply_adapters
from telnet.server import run_telnet_server


# ----------------------------------------------------------------------
# Global runtime state
# ----------------------------------------------------------------------

CONFIG = {}
SHUTDOWN_EVENT = threading.Event()

MAX_CONNECTIONS = 200
CONNECTION_SEMAPHORE = threading.Semaphore(MAX_CONNECTIONS)

CONNECTION_ID_LOCK = threading.Lock()
CONNECTION_IDS = itertools.count(1)

SOCKET_TIMEOUT = 300  # seconds

STATE = GlobalState()

# ----------------------------------------------------------------------
# Logging (rotating, thread-safe)
# ----------------------------------------------------------------------

LOGGER = logging.getLogger("proxy")
LOGGER.setLevel(logging.INFO)


def setup_logging(log_file: str):
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    formatter = logging.Formatter(
        "[%(asctime)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(console_handler)


# ----------------------------------------------------------------------
# Signal handling
# ----------------------------------------------------------------------

def _handle_shutdown(signum, frame):
    SHUTDOWN_EVENT.set()
    STATE.shutdown = True


signal.signal(signal.SIGINT, _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


# ----------------------------------------------------------------------
# Taps (state-aware)
# ----------------------------------------------------------------------

def log_tap(conn_id, client_addr, direction, data, state: SessionState):
    client_ip, client_port = client_addr
    LOGGER.info(
        "conn=%s client=%s:%s phase=%s encrypted=%s %s %r",
        conn_id,
        client_ip,
        client_port,
        state.phase,
        state.encrypted,
        direction,
        data,
    )


def view_tap(conn_id, client_addr, direction, data, state):
    LOGGER.info(
        "conn=%s client=%s:%s phase=%s encrypted=%s %s %r",
        conn_id,
        client_addr[0],
        client_addr[1],
        state.phase,
        state.encrypted,
        direction,
        data,
    )


def build_taps(state: GlobalState):
    taps = []

    if state.enable_log:
        taps.append(log_tap)

    if state.enable_view:
        taps.append(view_tap)

    return tuple(taps)


# ----------------------------------------------------------------------
# Core pipe
# ----------------------------------------------------------------------

def pipe(source, destination, conn_id, client_addr, direction, taps, state):
    while not SHUTDOWN_EVENT.is_set() and not state.shutdown:
        try:
            data = source.recv(CONFIG["buffer_size"])
        except socket.timeout:
            continue
        except OSError:
            break

        update_state(state, data, direction)
        data = apply_adapters(state, data, direction)

        if not data:
            continue

        for tap in taps:
            try:
                tap(conn_id, client_addr, direction, data, state)
            except Exception as exc:
                LOGGER.error("tap error conn=%s: %s", conn_id, exc)

        try:
            destination.sendall(data)
        except OSError:
            break


# ----------------------------------------------------------------------
# Connection handler
# ----------------------------------------------------------------------

def handle_connection(client, client_addr, route, taps):
    if not CONNECTION_SEMAPHORE.acquire(blocking=False):
        client.close()
        return

    with CONNECTION_ID_LOCK:
        conn_id = next(CONNECTION_IDS)

    # PATCH: route-lookup vid connect-ögonblicket (state switch påverkar nya conns)
    route_name = route.get("name")
    current_route = STATE.routes.get(route_name) if route_name else route
    if not current_route:
        LOGGER.warning("route missing conn=%s route=%s", conn_id, route_name)
        client.close()
        CONNECTION_SEMAPHORE.release()
        return

    LOGGER.info(
        "connect conn=%s %s:%s -> %s:%s",
        conn_id,
        CONFIG["listen_host"],
        current_route["listen"],
        current_route["forward"]["host"],
        current_route["forward"]["port"],
    )

    state = SessionState()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.settimeout(SOCKET_TIMEOUT)
        server.connect(
            (current_route["forward"]["host"], current_route["forward"]["port"])
        )

        LOGGER.info(
            "connect conn=%s client=%s:%s",
            conn_id,
            client_addr[0],
            client_addr[1],
        )

        threads = [
            threading.Thread(
                target=pipe,
                args=(
                    client,
                    server,
                    conn_id,
                    client_addr,
                    "IN ---> OUT",
                    taps,
                    state,
                ),
            ),
            threading.Thread(
                target=pipe,
                args=(
                    server,
                    client,
                    conn_id,
                    client_addr,
                    "OUT ---> IN",
                    taps,
                    state,
                ),
            ),
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

    except ConnectionRefusedError:
        LOGGER.warning("backend unavailable conn=%s", conn_id)

    finally:
        state.shutdown = True
        client.close()
        server.close()
        CONNECTION_SEMAPHORE.release()
        LOGGER.info("disconnect conn=%s", conn_id)


# ----------------------------------------------------------------------
# Route runner
# ----------------------------------------------------------------------

def run_route(cfg, route):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.settimeout(1.0)

    listener.bind((cfg["listen_host"], route["listen"]))
    listener.listen(5)

    taps = build_taps(STATE)

    LOGGER.info(
        "listening %s:%s -> %s:%s",
        cfg["listen_host"],
        route["listen"],
        route["forward"]["host"],
        route["forward"]["port"],
    )

    while not SHUTDOWN_EVENT.is_set():
        try:
            client, client_addr = listener.accept()
            client.settimeout(SOCKET_TIMEOUT)

            threading.Thread(
                target=handle_connection,
                args=(client, client_addr, route, taps),
            ).start()

        except socket.timeout:
            continue
        except OSError:
            break

    listener.close()


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def run():
    global CONFIG
    CONFIG = ConfigLoader.load_active_config("default")

    # PATCH: använd global STATE, skugga den inte
    STATE.routes = CONFIG["routes"]

    setup_logging(CONFIG["log_file"])

    for name, route in CONFIG["routes"].items():
        route["name"] = name
        threading.Thread(
            target=run_route,
            args=(CONFIG, route),
            daemon=True,
            name=f"proxy-route-{name}",
        ).start()

    threading.Thread(
        target=lambda: asyncio.run(run_telnet_server(STATE)),
        daemon=True,
        name="telnet-server",
    ).start()

    try:
        SHUTDOWN_EVENT.wait()
    finally:
        pass


if __name__ == "__main__":
    run()