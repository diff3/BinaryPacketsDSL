#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import shutil
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
    parser = argparse.ArgumentParser(
        description="Promote or delete captured opcode artifacts."
    )
    parser.add_argument(
        "opcode",
        nargs="?",
        help="Opcode name, e.g. SMSG_MOVE_SET_ACTIVE_MOVER (omit when using --sync)",
    )
    parser.add_argument(
        "-d",
        "--delete",
        action="store_true",
        help="Delete DEF/JSON files for the opcode from protocols",
    )
    parser.add_argument(
        "-s",
        "--sync",
        action="store_true",
        help="Remove capture artifacts for opcodes already promoted (requires no opcode)",
    )
    args = parser.parse_args()

    if args.sync and (args.opcode or args.delete):
        parser.error("--sync cannot be combined with opcode or --delete")
    if not args.sync and not args.opcode:
        parser.error("opcode is required unless using --sync")

    cfg = load_config_safe()
    program = cfg["program"]
    version = cfg["version"]

    base = f"protocols/{program}/{version}"

    # handle sync first to avoid configuring per-opcode values
    if args.sync:
        def_dir = f"{base}/def"

        def done_def_opcodes(folder):
            if not os.path.isdir(folder):
                return set()
            opcodes = set()
            for name in os.listdir(folder):
                if not name.endswith(".def"):
                    continue
                path = os.path.join(folder, name)
                if not os.path.isfile(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        first_line = f.readline()
                except OSError:
                    continue
                if "done" in first_line.lower():
                    opcodes.add(os.path.splitext(name)[0])
            return opcodes

        done_ops = done_def_opcodes(def_dir)
        if not done_ops:
            print("[INFO] No DEF files marked as done found.")
            return

        cap_dir = "misc/captures"
        removed = 0
        for opcode in sorted(done_ops):
            for path in (
                f"{cap_dir}/json/{opcode}.json",
                f"{cap_dir}/debug/{opcode}.json",
                f"{cap_dir}/bin/{opcode}.bin",
            ):
                if os.path.exists(path):
                    os.remove(path)
                    print(f"[OK] Removed capture {path}")
                    removed += 1
        if removed == 0:
            print("[INFO] No capture files removed.")
        else:
            print(f"[OK] Sync complete, removed {removed} capture files.")
        return

    opcode = args.opcode

    # LIVE paths
    live_json = f"{base}/json/{opcode}.json"
    live_dbg  = f"{base}/debug/{opcode}.json"
    live_def  = f"{base}/def/{opcode}.def"

    # CAPTURE paths
    cap_dir = f"misc/captures"

    src_json = f"{cap_dir}/json/{opcode}.json"
    src_dbg  = f"{cap_dir}/debug/{opcode}.json"

    if args.delete:
        removed_any = False
        for path in [live_def, live_json, live_dbg]:
            if os.path.exists(path):
                os.remove(path)
                print(f"[OK] Removed {path}")
                removed_any = True
            else:
                print(f"[SKIP] Not found: {path}")

        if not removed_any:
            print(f"[INFO] No files removed for {opcode}")
    else:
        # require debug capture
        if not os.path.exists(src_dbg):
            print(f"Missing capture: {src_dbg}")
            return

        # ensure dirs
        for p in [live_json, live_dbg, live_def]:
            os.makedirs(os.path.dirname(p), exist_ok=True)

        # copy (always overwrite)
        if os.path.exists(src_json):
            shutil.copy(src_json, live_json)
        if os.path.exists(src_dbg):
            shutil.copy(src_dbg, live_dbg)

        print(f"[OK] Promoted {opcode} → json/debug")

        # create def if missing
        if not os.path.exists(live_def):
            with open(live_def, "w", encoding="utf-8") as f:
                f.write(TEMPLATE_DEF)
            print(f"[OK] Created DEF: {live_def}")
        else:
            print(f"[SKIP] DEF exists: {live_def}")


if __name__ == "__main__":
    main()
