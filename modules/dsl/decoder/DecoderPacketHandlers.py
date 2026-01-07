#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder helpers for packet-specific constructs."""

from __future__ import annotations

import re
import zlib
from typing import Any, Callable

from modules.dsl.Session import BaseNode, get_session
from modules.dsl.bitsHandler import BitState
from utils.DebugHelper import DebugHelper
from utils.Logger import Logger


ProcessField = Callable[[Any, bytes, Any, str, Any], tuple[Any, bool, str]]
ResolveVariable = Callable[[str, dict[str, Any]], Any]


def combine_guid(target_name: str, mask: Any, values: dict[str, Any], result: dict[str, Any]) -> int:
    """Combine GUID-like structures into an integer.

    Args:
        target_name (str): Base name used to find mask fields.
        mask (Any): Explicit mask list or lookup key.
        values (dict[str, Any]): Current values for lookup.
        result (dict[str, Any]): Decode output map with meta fields.

    Returns:
        int: Combined GUID value.
    """
    session = get_session()
    scope = session.scope
    index_value = scope.get("i")
    if index_value is None:
        return 0

    try:
        meta = result["chars_meta"][index_value]
    except Exception:
        return 0

    if isinstance(mask, list):
        mask_list = mask
    else:
        prefix = target_name.rstrip("_")
        regex = re.compile(rf"^{prefix}_?(\d+)_mask$", re.IGNORECASE)
        mask_list = [
            int(match.group(1))
            for key, flag in meta.items()
            if (match := regex.match(key)) and flag
        ]

    guid_value = 0
    prefix = target_name.rstrip("_")

    for bit_index in mask_list:
        for key in (f"{target_name}_{bit_index}", f"{prefix}_{bit_index}", f"{prefix}{bit_index}"):
            if key in values:
                guid_value |= (values[key] & 0xFF) << (bit_index * 8)
                break

    return guid_value


def handle_packed_guid(field: Any, raw_data: bytes, bitstate: Any, state: Any) -> tuple[Any, bool, str]:
    """Decode a packed GUID field.

    Args:
        field (Any): Packed GUID node.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit/byte reader state.
        state (Any): Decoder state container.

    Returns:
        tuple[Any, bool, str]: (field, stored, endian).
    """
    bitstate.align_to_byte()
    start = bitstate.offset
    if start >= len(raw_data):
        Logger.error("packed_guid: no data")
        return field, True, "<"

    mask = raw_data[start]
    offset = start + 1

    guid_bytes = [0] * 8
    for index in range(8):
        if mask & (1 << index):
            if offset >= len(raw_data):
                Logger.error("packed_guid: out of data")
                break
            guid_bytes[index] = raw_data[offset]
            offset += 1

    bitstate.advance_to(offset, 0)
    guid_value = int.from_bytes(bytes(guid_bytes), "little")

    field.value = guid_value
    field.raw_offset = start
    field.raw_length = offset - start
    field.raw_data = raw_data[start:offset]
    setattr(field, "mask", mask)

    state.set_field(field, guid_value)
    mask_field = BaseNode(
        name=f"{field.name}_mask",
        format="B",
        interpreter="struct",
        ignore=getattr(field, "ignore", False),
        visible=getattr(field, "visible", True),
        payload=getattr(field, "payload", True),
    )
    state.set_field(mask_field, mask)

    return field, True, "<"


def handle_uncompress(
    field: Any,
    raw_data: bytes,
    bitstate: Any,
    endian: str,
    state: Any,
    *,
    process_field: ProcessField,
    resolve_variable: ResolveVariable,
) -> tuple[Any, bool, str]:
    """Decode a compressed payload block.

    Args:
        field (Any): Uncompress node.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit/byte reader state.
        endian (str): Current endianness token.
        state (Any): Decoder state container.
        process_field (Callable): Function to process child nodes.
        resolve_variable (Callable): Variable resolver.

    Returns:
        tuple[Any, bool, str]: (field, stored, endian).
    """
    algo = (field.algo or "").lower()
    length_expr = field.length_expr

    length = None
    if length_expr:
        expression = length_expr.strip()
        if expression.startswith("€"):
            expression = expression[1:]
        if expression.endswith("B"):
            expression = expression[:-1]
        try:
            length = int(expression)
        except ValueError:
            length = resolve_variable(expression, state.all)

    if length is None:
        length = len(raw_data) - bitstate.offset

    compressed = raw_data[bitstate.offset:bitstate.offset + length]
    bitstate.advance_to(bitstate.offset + length, 0)

    if algo != "zlib":
        Logger.error(f"uncompress: unsupported algorithm {algo}")
        return field, True, endian

    try:
        inflated = zlib.decompress(compressed)
    except Exception as exc:
        Logger.error(f"uncompress failed: {exc}")
        return field, True, endian

    child_state = BitState()
    for child_template in field.children:
        child = child_template.copy()
        process_field(child, inflated, child_state, endian, state)
        DebugHelper.trace_field(field, bitstate, label_prefix=field.name)

    field.raw_data = compressed
    field.value = inflated
    return field, True, endian
