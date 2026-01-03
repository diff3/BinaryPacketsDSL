#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path

from utils.ConfigLoader import ConfigLoader


def get_protocol_root(
    program: str | None = None,
    expansion: str | None = None,
    version: str | None = None,
) -> Path | None:
    cfg = ConfigLoader.load_config()
    program = program or cfg.get("program")
    if expansion is None:
        expansion = cfg.get("expansion")
    version = version or cfg.get("version")

    if not program or not version:
        return None

    if expansion:
        return Path("protocols") / program / expansion / version
    return Path("protocols") / program / version


def get_captures_root(
    program: str | None = None,
    expansion: str | None = None,
    version: str | None = None,
    *,
    focus: bool = False,
) -> Path:
    base = get_protocol_root(program=program, expansion=expansion, version=version)
    if base is None:
        root = Path("captures")
    else:
        root = base / "captures"

    return root / "focus" if focus else root


def get_logs_root(
    program: str | None = None,
    expansion: str | None = None,
    version: str | None = None,
) -> Path:
    base = get_protocol_root(program=program, expansion=expansion, version=version)
    if base is None:
        return Path("logs")
    return base / "logs"
