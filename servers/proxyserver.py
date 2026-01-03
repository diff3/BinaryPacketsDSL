#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import threading
from utils.ConfigLoader import ConfigLoader

from modules.proxy.auth_proxy import AuthProxy
from modules.proxy.world_proxy import WorldProxy
from modules.proxy.control_server import ControlServer
from modules.proxy.control_state import ControlState
from modules.dsl.DslRuntime import DslRuntime
from modules.interpretation.utils import set_dsl_runtime
from utils.Logger import Logger
    
cfg = ConfigLoader.load_config()

def start_proxy(dump=False, update=False, focus_dump=None):
    control_cfg = cfg.get("control_server", {}) if isinstance(cfg, dict) else {}
    control_enabled = bool(control_cfg.get("enabled", True))
    control_host = control_cfg.get("host", "127.0.0.1")
    control_port = int(control_cfg.get("port", 1337))
    control_user = control_cfg.get("username") or None
    control_pass = control_cfg.get("password") or None

    control_state = ControlState(dump=dump, update=update, focus=focus_dump)
    ControlServer(
        control_state,
        host=control_host,
        port=control_port,
        enabled=control_enabled,
        username=control_user,
        password=control_pass,
    ).start()

    try:
        shared_runtime = DslRuntime(cfg["program"], cfg["version"], watch=True)
        shared_runtime.load_runtime_all()
    except Exception as exc:
        Logger.error(f"[ProxyServer] Runtime init failed (runtime mode): {exc}")
        shared_runtime = DslRuntime(cfg["program"], cfg["version"], watch=True)
        shared_runtime.load_runtime_all()

    set_dsl_runtime(shared_runtime)

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
        focus_dump=focus_dump,
        control_state=control_state,
        dsl_runtime=shared_runtime,
    )

    # WORLD PROXY
    world = WorldProxy(
        cfg["world_proxy"]["listen_host"],
        cfg["world_proxy"]["listen_port"],
        cfg["world_proxy"]["world_host"],
        cfg["world_proxy"]["world_port"],
        dump=dump,
        update=update,
        focus_dump=focus_dump,
        control_state=control_state,
    )

    # Start AUTH i bakgrunden
    threading.Thread(target=auth.start, daemon=True).start()

    # Kör WORLD i foreground
    world.start()


if __name__ == "__main__":
    Logger.info(f"{cfg['friendly_name']} ProxyServer")
    print()
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--focus-dump", action="append", help="Dump/update endast dessa paket (kan anges flera gånger)")
    args = ap.parse_args()

    focus = set(args.focus_dump) if args.focus_dump else None
    start_proxy(dump=args.dump, update=args.update, focus_dump=focus)
