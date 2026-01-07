#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder utility helpers for logging and argument parsing."""

from __future__ import annotations

from utils.Logger import Logger


def split_print_args(expression: str) -> list[str]:
    """Split a print expression into comma-separated arguments.

    Args:
        expression (str): Raw print argument string.

    Returns:
        list[str]: Parsed argument expressions.
    """
    if not isinstance(expression, str):
        return []

    text = expression.strip()
    if not text:
        return []

    parts: list[str] = []
    buffer_chars: list[str] = []
    depth = 0
    in_string = False
    quote_char = ""
    is_escape = False

    for character in text:
        if in_string:
            buffer_chars.append(character)
            if is_escape:
                is_escape = False
                continue
            if character == "\\":
                is_escape = True
                continue
            if character == quote_char:
                in_string = False
            continue

        if character in ("'", '"'):
            in_string = True
            quote_char = character
            buffer_chars.append(character)
            continue

        if character in "([{" :
            depth += 1
            buffer_chars.append(character)
            continue

        if character in ")]}":
            depth = max(0, depth - 1)
            buffer_chars.append(character)
            continue

        if character == "," and depth == 0:
            part = "".join(buffer_chars).strip()
            if part:
                parts.append(part)
            buffer_chars = []
            continue

        buffer_chars.append(character)

    if buffer_chars:
        part = "".join(buffer_chars).strip()
        if part:
            parts.append(part)

    return parts


def log_print_message(level: str, message: str) -> None:
    """Log a debug message with a level-aware logger.

    Args:
        level (str): Log level indicator (debug, info, warning, error, etc.).
        message (str): Message to log.
    """
    normalized_level = (level or "debug").strip().lower()
    if normalized_level in ("info", "i"):
        Logger.info(message)
    elif normalized_level in ("warn", "warning", "w"):
        Logger.warning(message)
    elif normalized_level in ("error", "err", "e"):
        Logger.error(message)
    elif normalized_level in ("success", "ok", "s"):
        Logger.success(message)
    elif normalized_level in ("anticheat", "anti", "a"):
        Logger.anticheat(message)
    elif normalized_level in ("script", "sc"):
        Logger.script(message)
    else:
        Logger.debug(message)
