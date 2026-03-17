#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import json

from DSL.modules.dsl.DecoderHandler import DecoderHandler
from DSL.modules.dsl.NodeTreeParser import NodeTreeParser
from DSL.modules.dsl.Processor import load_case, load_all_cases, handle_add
from DSL.modules.dsl.Session import get_session
from shared.ConfigLoader import ConfigLoader
from DSL.utils.CliArgs import parse_args
from shared.Logger import Logger
from DSL.utils.PrintUtils import SessionPrint
from shared.PathUtils import get_captures_root

def load_focus_payloads(program, expansion, version, case_name: str, focus_file: Path | None = None):
    root = get_captures_root(program=program, expansion=expansion, version=version, focus=True) / "debug"
    out = []
    if focus_file is not None:
        candidate = focus_file
        if not candidate.is_file():
            candidate = root / focus_file.name
        if not candidate.is_file():
            return out
        if not candidate.stem.startswith(case_name):
            return out
        try:
            data = json.loads(candidate.read_text("utf-8"))
            hex_payload = (data.get("hex_compact") or data.get("hex_spaced") or "").replace(" ", "")
            if not hex_payload:
                return out
            payload = bytes.fromhex(hex_payload)
            out.append((candidate, payload))
        except Exception:
            return []
        return out
    if not root.is_dir():
        return out
    for f in sorted(root.glob(f"{case_name}*.json")):
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

def resolve_case_and_focus_file(program, expansion, version, file_arg: str | None) -> tuple[str | None, Path | None]:
    if not file_arg:
        return None, None
    if file_arg.endswith(".json"):
        candidate = Path(file_arg)
        if not candidate.is_file():
            candidate = get_captures_root(program=program, expansion=expansion, version=version, focus=True) / "debug" / file_arg
        if candidate.is_file():
            stem = candidate.stem
            parts = stem.rsplit("_", 1)
            if len(parts) == 2 and parts[1].isdigit():
                return parts[0], candidate
            return stem, candidate
        return file_arg[:-5], None
    return file_arg, None

# GLOBALS
config = ConfigLoader.get_config()
config["Logging"]["logging_levels"] = "Information, Success, Error"

session = get_session()
args = parse_args()


if __name__ == "__main__":
    Logger.reset_log()
    session.reset()

    tool_name = config['tool_name']
    program = config['program']
    expansion = config.get("expansion")
    version = config['version']
    friendly_name = config['friendly_name']

    if args.verbose:
        config["Logging"]["logging_levels"] = "All"

    if args.program:
        program = args.program
        friendly_name = "manuell"

    if args.expansion:
        expansion = args.expansion
        friendly_name = "manuell"

    if args.version:
        version = args.version
        friendly_name = "manuell"

    if args.add:
        if not program or not expansion or not version or not args.file or not args.bin:
            Logger.error(
                "Missing required arguments for --add: --program, --expansion, --version, --file, and --bin"
            )
            exit(1)

        if handle_add(program, version, args.file, args.bin, expansion=expansion):
            Logger.success(f"Successfully added packet: {args.file}")
            exit(0)
        else:
            Logger.error(f"Failed to add packet: {args.file}")
            exit(1)

    if args.silent:
        config["Logging"]["logging_levels"] = "None"    

    if args.promote and not getattr(args, "focus", False):
        Logger.error("--promote kräver --focus")
        exit(1)

    if args.promote and not args.file:
        Logger.error("--promote kräver att du anger ett exakt filnamn med --file")
        exit(1)
   
    Logger.info(f"{tool_name} - {friendly_name}")
    Logger.info(f"Parsing {program} {expansion} {version}\n")

    if args.file:
        case_name, focus_file = resolve_case_and_focus_file(program, expansion, version, args.file)
        case_data = [load_case(program, version, case_name, expansion=expansion)]
    else:
        focus_file = None
        case_data = load_all_cases(program, version, expansion=expansion)

    if not case_data:
        Logger.error("No .def files found.")
        exit(1)

    for case in case_data:
        Logger.info(f"Processing case: {case[0]}")
        NodeTreeParser.parse(case)

        SessionPrint.pretty_print_compact_all(session)
        Logger.to_log('')

        # Fokusläge: decode alla sniffade varianter
        focus_caps = load_focus_payloads(
            program,
            expansion,
            version,
            case[0],
            focus_file=focus_file,
        ) if getattr(args, 'focus', False) else []
        if args.promote and not focus_caps:
            Logger.error(f"[PROMOTE] Hittade inga fokusfiler för {case[0]} att promota.")
            exit(1)
        if focus_caps:
            if args.promote and len(focus_caps) != 1:
                Logger.error(f"[PROMOTE] Hittade {len(focus_caps)} fokusfiler för {case[0]}. Behöver exakt en för att promota.")
                exit(1)

            def_lines = case[1]
            for fpath, payload in focus_caps:
                Logger.success(f"[FOCUS] {fpath.name}")
                session.reset()
                focus_case = (case[0], def_lines, payload, {}, None)
                NodeTreeParser.parse(focus_case)
                result = DecoderHandler.decode(focus_case, silent=args.silent)
            if args.promote:
                out_dir = Path(f"protocols/{program}/{expansion}/{version}/data/json")
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / f"{case[0]}.json"
                out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
                Logger.success(f"[PROMOTE] Wrote expected JSON → {out_path}")
            elif args.update:
                out_dir = get_captures_root(program=program, expansion=expansion, version=version, focus=True) / "json"
                out_dir.mkdir(parents=True, exist_ok=True)
                stem = fpath.stem
                out_path = out_dir / f"{stem}.json"
                out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
                Logger.success(f"[UPDATE FOCUS] Wrote expected JSON → {out_path}")
                continue

        # Standard: använd inladdat payload
        result = DecoderHandler.decode(case, silent=args.silent)

        # Uppdatera expected-json om flaggan --update är satt
        if args.update:
            base = f"protocols/{program}/{expansion}/{version}/data/json"
            out_path = f"{base}/{case[0]}.json"
            import os
            os.makedirs(base, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as jf:
                json.dump(result, jf, indent=2, ensure_ascii=False)
            Logger.success(f"[UPDATE] Wrote expected JSON → {out_path}")
