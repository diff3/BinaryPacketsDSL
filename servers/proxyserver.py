#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
from utils.ConfigLoader import ConfigLoader

from modules.proxy.auth_proxy import AuthProxy
from modules.proxy.world_proxy import WorldProxy


def start_proxy(dump=False, update=False):
    cfg = ConfigLoader.load_config()

    # AUTH PROXY
    auth = AuthProxy(
        cfg["auth_proxy"]["listen_host"],
        cfg["auth_proxy"]["listen_port"],
        cfg["auth_proxy"]["auth_host"],
        cfg["auth_proxy"]["auth_port"],
        dump=dump,
        update=update
    )

    # WORLD PROXY
    world = WorldProxy(
        cfg["world_proxy"]["listen_host"],
        cfg["world_proxy"]["listen_port"],
        cfg["world_proxy"]["world_host"],
        cfg["world_proxy"]["world_port"],
        dump=dump,
        update=update
    )

    # Start AUTH i bakgrunden
    threading.Thread(target=auth.start, daemon=True).start()

    # Kör WORLD i foreground
    world.start()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--update", action="store_true")
    args = ap.parse_args()

    start_proxy(dump=args.dump, update=args.update)