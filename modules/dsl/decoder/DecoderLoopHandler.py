#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder helpers for DSL loop handling."""

from __future__ import annotations

from typing import Any, Callable

from modules.dsl.Session import get_session
from utils.Logger import Logger


DecodeProcessField = Callable[[Any, bytes, Any, str, Any], tuple[Any, bool, str]]
ResolveVariable = Callable[[str, dict[str, Any]], Any]
StateFactory = Callable[[], Any]


def handle_loop_block(
    field: Any,
    raw_data: bytes,
    bitstate: Any,
    endian: str,
    state: Any,
    *,
    process_field: DecodeProcessField,
    resolve_variable: ResolveVariable,
    state_factory: StateFactory,
) -> tuple[Any, bool, str]:
    """Process a loop block for the decoder.

    Args:
        field (Any): The LoopNode instance.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit/byte reader state.
        endian (str): Current endianness token.
        state (Any): Decoder state container.
        process_field (Callable): Function to process child nodes.
        resolve_variable (Callable): Helper to resolve loop counters.
        state_factory (Callable): Factory for child DecodeState instances.

    Returns:
        tuple[Any, bool, str]: (field, stored, endian).
    """
    session = get_session()
    scope = session.scope

    if field.count_from == "until_end":
        out_all = []
        out_public = []

        while bitstate.offset < len(raw_data):
            before_offset = bitstate.offset
            before_bit = bitstate.bit_pos

            entry_state = state_factory()
            success = True

            scope.push()
            scope.set("i", len(out_all))

            try:
                for child_template in field.children:
                    child = child_template.copy()
                    child, _, _ = process_field(
                        child, raw_data, bitstate, endian, entry_state
                    )
                    if child.value is None:
                        success = False
                        break
            finally:
                scope.pop()

            if not success:
                bitstate.offset = before_offset
                bitstate.bit_pos = before_bit
                break

            if bitstate.offset == before_offset and bitstate.bit_pos == before_bit:
                break

            out_all.append(entry_state.all)
            out_public.append(entry_state.public)

        state.set_field(field, out_all, public_value=out_public)
        field.value = out_all
        field.processed = True
        return field, True, endian

    loop_count = resolve_variable(field.count_from, state.all)
    if not isinstance(loop_count, int) or loop_count < 0:
        Logger.debug(f"[handle_loop] Invalid count '{field.count_from}' → using 0")
        loop_count = 0

    out_all = []
    out_public = []

    for idx in range(loop_count):
        scope.push()
        scope.set("i", idx)

        try:
            entry_state = state_factory()
            for child_template in field.children:
                child = child_template.copy()
                process_field(child, raw_data, bitstate, endian, entry_state)
            out_all.append(entry_state.all)
            out_public.append(entry_state.public)
        finally:
            scope.pop()

    state.set_field(field, out_all, public_value=out_public)
    field.value = out_all
    field.processed = True
    return field, True, endian
