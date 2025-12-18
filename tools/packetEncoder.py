#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from pathlib import Path

from utils.CliArgs import parse_args
from utils.ConfigLoader import ConfigLoader
from utils.Logger import Logger
from modules.dsl.Processor import load_case
from modules.dsl.EncoderDebug import EncoderDebug


def load_json_fields(program, version, def_name):
    path = Path(f"protocols/{program}/{version}/data/json/{def_name}.json")
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
    # Reuse the same CLI flags as packetAnalyzer
    args = parse_args()

    cfg = ConfigLoader.get_config()
    cfg["Logging"]["logging_levels"] = "Information, Success, Error"

    # Unsupported flags for this tool
    if args.add or args.promote or args.update or args.bin:
        Logger.error("packageEncoder stöder inte --add/--promote/--update/--bin")
        return 1

    if args.verbose:
        cfg["Logging"]["logging_levels"] = "All"
    if args.silent:
        cfg["Logging"]["logging_levels"] = "None"

    program = args.program or cfg["program"]
    version = args.version or cfg["version"]

    def_name = args.file
    if not def_name:
        Logger.error("Ange paketnamn med --file")
        return 1

    # Säkerställ def finns
    try:
        load_case(program, version, def_name)
    except Exception as e:
        Logger.error(f"[encode_debug] DEF {def_name} kunde inte laddas: {e}")
        return 1

    base_fields_path = Path(f"protocols/{program}/{version}/data/json/{def_name}.json")
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
