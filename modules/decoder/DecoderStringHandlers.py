#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder helpers for string and raw payload handling."""

from __future__ import annotations

from typing import Any


def resolve_string_format(field: Any, raw_data: bytes, offset: int) -> Any:
    """Resolve a null-terminated string field to a struct field.

    Args:
        field (Any): Field node containing string metadata.
        raw_data (bytes): Raw packet payload.
        offset (int): Byte offset to start reading.

    Returns:
        Any: Updated field node.
    """
    end = offset
    while end < len(raw_data) and raw_data[end] != 0:
        end += 1

    raw = raw_data[offset:end]
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError:
        value = raw.hex()

    length = (end - offset) + 1
    field.value = value
    field.format = f"{length}s"
    field.interpreter = "struct"
    field.raw_length = length

    return field


def handle_read_rest(field: Any, raw_data: bytes, bitstate: Any) -> Any:
    """Read the remaining payload as a raw string/hex value.

    Args:
        field (Any): Field node representing the rest of payload.
        raw_data (bytes): Raw packet payload.
        bitstate (Any): Current bit/byte reader state.

    Returns:
        Any: Updated field node.
    """
    start = bitstate.offset
    end = len(raw_data)

    raw = raw_data[start:end]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        value = raw.hex()

    field.value = value
    field.raw_length = end - start
    field.raw_data = raw
    field.format = f"{end - start}s"
    field.interpreter = "raw"

    bitstate.offset = end
    field.processed = True
    return field
