#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path

from utils.Logger import Logger


STUBS = {
    "modules/database/DatabaseConnection.py": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger


class DatabaseConnection:
    @staticmethod
    def initialize():
        Logger.info("[DatabaseConnection] initialize (stub)")
        return True
""",
    "modules/handlers/AuthHandlers.py": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger

# Map opcode int -> handler function
opcode_handlers = {}

def _not_implemented(*_args, **_kwargs):
    Logger.warning("[AuthHandlers] No handlers registered (stub)")
    return 1, None
""",
    "modules/handlers/WorldHandlers.py": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger

# Map opcode int -> handler function
opcode_handlers = {}

def get_auth_challenge():
    return None

def reset_state():
    return None

def _not_implemented(*_args, **_kwargs):
    Logger.warning("[WorldHandlers] No handlers registered (stub)")
    return 1, None
""",
    "modules/opcodes/AuthOpcodes.py": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

AUTH_CLIENT_OPCODES = {}
AUTH_SERVER_OPCODES = {}
lookup = None
""",
    "modules/opcodes/WorldOpcodes.py": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-

WORLD_CLIENT_OPCODES = {}
WORLD_SERVER_OPCODES = {}
lookup = None
""",
    "config.yaml": """friendly_name: "<program> <expansion> <version>"
""",
}


def _touch(path: Path, force: bool = False) -> None:
    if path.exists() and not force:
        Logger.info(f"[skip] {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    Logger.success(f"[write] {path}")


def _write(path: Path, content: str, force: bool = False) -> None:
    if path.exists() and not force:
        Logger.info(f"[skip] {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    Logger.success(f"[write] {path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create protocol skeleton under protocols/<program>/<expansion>/<version>."
    )
    parser.add_argument("-p", "--program", required=True, help="Program name (e.g., wow)")
    parser.add_argument("-e", "--expansion", required=True, help="Expansion name (e.g., vanilla, mop)")
    parser.add_argument("-v", "--version", required=True, help="Version tag (e.g., v1121, v18414)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing stub files")
    args = parser.parse_args()

    base = Path("protocols") / args.program / args.expansion / args.version

    for path in [
        base / "data" / "def",
        base / "data" / "debug",
        base / "data" / "json",
        base / "modules" / "database",
        base / "modules" / "handlers",
        base / "modules" / "opcodes",
        base / "tests",
        base / "tools",
    ]:
        path.mkdir(parents=True, exist_ok=True)
        Logger.success(f"[mkdir] {path}")

    for init_path in [
        Path("protocols") / args.program / "__init__.py",
        Path("protocols") / args.program / args.expansion / "__init__.py",
        base / "__init__.py",
        base / "modules" / "__init__.py",
        base / "modules" / "database" / "__init__.py",
        base / "modules" / "handlers" / "__init__.py",
        base / "modules" / "opcodes" / "__init__.py",
        base / "tests" / "__init__.py",
    ]:
        _touch(init_path, force=args.force)

    for rel_path, content in STUBS.items():
        if rel_path == "config.yaml":
            rendered = content.replace(
                "<program> <expansion> <version>",
                f"{args.program} {args.expansion} {args.version}",
            )
            _write(base / rel_path, rendered, force=args.force)
        else:
            _write(base / rel_path, content, force=args.force)

    Logger.success(
        f"[done] protocols/{args.program}/{args.expansion}/{args.version} created"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
