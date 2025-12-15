#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
from pathlib import Path

from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from modules.Processor import load_case
from modules.EncoderDebug import EncoderDebug


def load_json_fields(program, version, def_name):
    path = Path(f"protocols/{program}/{version}/json/{def_name}.json")
    if not path.exists():
        Logger.error(f"[encode_debug] Ingen JSON-data hittades: {path}")
        return None
    try:
        data = json.loads(path.read_text("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception as e:
        Logger.error(f"[encode_debug] Kunde inte läsa {path}: {e}")
        return None


def load_focus_fields(stem: str, def_name: str, fallback_path: Path) -> dict | None:
    root = Path('misc/captures/focus/json')
    focus_path = root / f'{stem}.json'
    if focus_path.exists():
        try:
            data = json.loads(focus_path.read_text('utf-8'))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    # fallback
    try:
        data = json.loads(fallback_path.read_text('utf-8'))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def load_focus_payloads(def_name):
    root = Path("misc/captures/focus/debug")
    out = []
    if not root.is_dir():
        return out
    for f in sorted(root.glob(f"{def_name}*.json")):
        try:
            data = json.loads(f.read_text("utf-8"))
            hex_payload = (data.get("hex_compact") or data.get("hex_spaced") or "").replace(" ", "")
            if not hex_payload:
                continue
            payload = bytes.fromhex(hex_payload)
            out.append((f, payload))
        except Exception:
            continue
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("def_name", help="DEF name (e.g. SMSG_X)")
    ap.add_argument("--focus", action="store_true", help="Använd sniffade paket i misc/captures/focus")
    args = ap.parse_args()

    def_name = args.def_name
    cfg = ConfigLoader.load_config()
    program = cfg["program"]
    version = cfg["version"]

    # Säkerställ def finns
    try:
        load_case(program, version, def_name)
    except Exception as e:
        Logger.error(f"[encode_debug] DEF {def_name} kunde inte laddas: {e}")
        return 1

    base_fields_path = Path(f"protocols/{program}/{version}/json/{def_name}.json")
    fields = load_json_fields(program, version, def_name)
    if fields is None:
        Logger.error("[encode_debug] Avbryter — ingen fältdata.")
        return 1

    captures = load_focus_payloads(def_name) if args.focus else []

    if captures:
        for fpath, payload in captures:
            Logger.success(f"[encode_debug] Fokus: {fpath.name}")
            stem = fpath.stem
            focus_fields = load_focus_fields(stem, def_name, base_fields_path)
            if focus_fields is None:
                Logger.error(f"[encode_debug] Ingen fältdata för {stem}")
                continue
            EncoderDebug.dump_encoding(def_name, focus_fields, reference_override=payload)
    else:
        Logger.success(f"[encode_debug] Bör encodas: {def_name}")
        Logger.success(f"Program={program}, Version={version}")
        EncoderDebug.dump_encoding(def_name, fields)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
