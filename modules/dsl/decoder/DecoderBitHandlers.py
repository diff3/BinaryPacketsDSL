#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder helpers for bit fields and bitmask blocks."""

from __future__ import annotations

import re
from typing import Any, Callable

from modules.dsl.ModifierMapping import modifiers_operation_mapping
from modules.dsl.bitsHandler import BitState
from utils.DebugHelper import DebugHelper


ProcessField = Callable[[Any, bytes, Any, str, Any], tuple[Any, bool, str]]
StateFactory = Callable[[], Any]


def decode_bits_field(field: Any, raw_data: bytes, bitstate: Any) -> Any:
    """Decode a single bits field using configured modifiers.

    Args:
        field (Any): Bits field node.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit reader state.

    Returns:
        Any: Updated field.
    """
    raw_start = None
    raw_end = None

    for modifier in field.modifiers:
        match = re.fullmatch(r"(\d+)([Bb])", modifier)
        if match:
            func = modifiers_operation_mapping[match.group(2)]
            if raw_start is None:
                raw_start = bitstate.offset

            bits_value, new_offset, bit_pos = func(
                raw_data, bitstate.offset, bitstate.bit_pos, int(match.group(1))
            )

            raw_end = new_offset + (1 if bit_pos > 0 else 0)
            field.value = bits_value
            bitstate.advance_to(new_offset, bit_pos)
            continue

        func = modifiers_operation_mapping.get(modifier)
        if func and field.value is not None:
            field.value = func(field.value)

    if raw_start is not None and raw_end is not None:
        field.raw_offset = raw_start
        field.raw_length = raw_end - raw_start
        field.raw_data = raw_data[raw_start:raw_end]

    return field


def handle_bitmask(
    field: Any,
    raw_data: bytes,
    bitstate: Any,
    endian: str,
    state: Any,
    *,
    process_field: ProcessField,
    state_factory: StateFactory,
) -> tuple[Any, bool, str]:
    """Decode a bitmask block.

    Args:
        field (Any): Bitmask node.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit reader state.
        endian (str): Current endianness token.
        state (Any): Decoder state container.
        process_field (Callable): Function to process child nodes.
        state_factory (Callable): Factory for child DecodeState instances.

    Returns:
        tuple[Any, bool, str]: (field, stored, endian).
    """
    start_offset = bitstate.offset
    start_bit = bitstate.bit_pos
    total_bits = getattr(field, "size", 0)

    end_abs = start_offset * 8 + start_bit + total_bits
    end_offset = end_abs // 8
    end_bit = end_abs % 8

    child_state = BitState()
    child_state.offset = start_offset
    child_state.bit_pos = start_bit

    temporary_state = state_factory()
    for child_template in field.children:
        child = child_template.copy()
        process_field(child, raw_data, child_state, endian, temporary_state)
        DebugHelper.trace_field(field, bitstate, label_prefix=field.name)

    bitstate.advance_to(end_offset, end_bit)

    field.raw_offset = start_offset
    field.raw_length = end_offset - start_offset + (1 if end_bit > 0 else 0)
    field.raw_data = raw_data[start_offset:start_offset + field.raw_length]
    field.value = temporary_state.public
    state.set_field(field, temporary_state.public)

    return field, True, endian
