#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import shutil
import os
import sys
import yaml

from utils.ConfigLoader import ConfigLoader

TEMPLATE_DEF = """endian: little
header:
data:
"""

def load_config_safe():
    """Load config even when running tools/ scripts."""
    cfg = ConfigLoader.load_config()
    if cfg is not None:
        return cfg

    # fallback: try project root config.yaml
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    config_path = os.path.join(root, "etc/config.yaml")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    if len(sys.argv) != 2:
        print("Usage: promote_capture.py OPCODE_NAME")
        return

    opcode = sys.argv[1]

    cfg = load_config_safe()
    program = cfg["program"]
    version = cfg["version"]

    base = f"protocols/{program}/{version}"

    # LIVE paths
    live_bin  = f"{base}/bin/{opcode}.bin"
    live_json = f"{base}/json/{opcode}.json"
    live_dbg  = f"{base}/debug/{opcode}.json"
    live_def  = f"{base}/def/{opcode}.def"

    # CAPTURE paths
    cap_dir = f"captures"

    src_bin  = f"{cap_dir}/bin/{opcode}.bin"
    src_json = f"{cap_dir}/json/{opcode}.json"
    src_dbg  = f"{cap_dir}/debug/{opcode}.json"

    # check bin exists
    if not os.path.exists(src_bin):
        print(f"Missing capture: {src_bin}")
        return

    # ensure dirs
    for p in [live_bin, live_json, live_dbg, live_def]:
        os.makedirs(os.path.dirname(p), exist_ok=True)

    # copy (always overwrite)
    shutil.copy(src_bin, live_bin)

    if os.path.exists(src_json):
        shutil.copy(src_json, live_json)
    if os.path.exists(src_dbg):
        shutil.copy(src_dbg, live_dbg)

    print(f"[OK] Promoted {opcode} → bin/json/debug")

    # create def if missing
    if not os.path.exists(live_def):
        with open(live_def, "w", encoding="utf-8") as f:
            f.write(TEMPLATE_DEF)
        print(f"[OK] Created DEF: {live_def}")
    else:
        print(f"[SKIP] DEF exists: {live_def}")


if __name__ == "__main__":
    main()