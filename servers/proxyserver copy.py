#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import threading
from utils.ConfigLoader import ConfigLoader

from modules.proxy.auth_proxy import AuthProxy
from modules.proxy.world_proxy import WorldProxy
from utils.Logger import Logger

def start_proxy(dump=False, update=False, focus_dump=None):
    cfg = ConfigLoader.load_config()

    # Fokus → aktivera dump automatiskt
    if focus_dump:
        dump = True

    # AUTH PROXY
    auth = AuthProxy(
        cfg["auth_proxy"]["listen_host"],
        cfg["auth_proxy"]["listen_port"],
        cfg["auth_proxy"]["auth_host"],
        cfg["auth_proxy"]["auth_port"],
        dump=dump,
        update=update,
        focus_dump=focus_dump
    )

    # WORLD PROXY
    world = WorldProxy(
        cfg["world_proxy"]["listen_host"],
        cfg["world_proxy"]["listen_port"],
        cfg["world_proxy"]["world_host"],
        cfg["world_proxy"]["world_port"],
        dump=dump,
        update=update,
        focus_dump=focus_dump
    )

    # Start AUTH i bakgrunden
    threading.Thread(target=auth.start, daemon=True).start()

    # Kör WORLD i foreground
    world.start()


if __name__ == "__main__":
    Logger.info("Mist of Pandaria 5.4.8 ProxyServer")


    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--focus-dump", action="append", help="Dump/update endast dessa paket (kan anges flera gånger)")
    args = ap.parse_args()

    focus = set(args.focus_dump) if args.focus_dump else None
    start_proxy(dump=args.dump, update=args.update, focus_dump=focus)
