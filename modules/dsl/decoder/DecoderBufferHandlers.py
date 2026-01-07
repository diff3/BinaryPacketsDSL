#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder helpers for buffer allocation and indexed access."""

from __future__ import annotations

from typing import Any, Callable

from modules.dsl.ModifierMapping import modifiers_operation_mapping


ResolveVariable = Callable[[str, dict[str, Any]], Any]
PresentBuffer = Callable[[list[Any]], str]


def resolve_length_expression(
    expression: str | None,
    scope: dict[str, Any],
    *,
    resolve_variable: ResolveVariable,
) -> int | None:
    """Resolve a buffer size expression into an integer.

    Args:
        expression (str | None): Raw length expression.
        scope (dict[str, Any]): Current decode scope.
        resolve_variable (Callable): Variable resolver.

    Returns:
        int | None: Parsed length or None if unresolved.
    """
    if expression is None:
        return None

    cleaned = str(expression).strip()
    if cleaned.startswith("€"):
        cleaned = cleaned[1:]
    if cleaned.endswith("B"):
        cleaned = cleaned[:-1]
    if not cleaned:
        return None

    try:
        return int(cleaned)
    except ValueError:
        pass

    try:
        return resolve_variable(cleaned, scope)
    except Exception:
        return None


def handle_buffer_allocation(
    field: Any,
    bitstate: Any,
    state: Any,
    *,
    resolve_variable: ResolveVariable,
    present_buffer: PresentBuffer,
) -> Any:
    """Allocate a buffer for later indexed reads/writes.

    Args:
        field (Any): Buffer allocation node.
        bitstate (Any): Current bit/byte reader state.
        state (Any): Decoder state container.
        resolve_variable (Callable): Variable resolver.
        present_buffer (Callable): Presentation helper for buffer output.

    Returns:
        Any: Updated field.
    """
    raw_expression = getattr(field, "alloc_size_expr", None) or getattr(field, "format", "") or ""
    size = resolve_length_expression(raw_expression, state.all, resolve_variable=resolve_variable)
    try:
        size = int(size or 0)
    except Exception:
        size = 0
    size = max(0, size)

    buffer_values = [None] * size
    field.value = buffer_values
    field.raw_offset = bitstate.offset
    field.raw_length = 0
    field.raw_data = b""
    field.processed = True

    state.remember_buffer(field, buffer_values, public_value=present_buffer(buffer_values))
    return field


def handle_buffer_io(
    field: Any,
    raw_data: bytes,
    bitstate: Any,
    state: Any,
    *,
    resolve_variable: ResolveVariable,
) -> Any:
    """Read bytes into a buffer and expose the optional IO field.

    Args:
        field (Any): Buffer IO node.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit/byte reader state.
        state (Any): Decoder state container.
        resolve_variable (Callable): Variable resolver.

    Returns:
        Any: Updated field.
    """
    buffer_name = getattr(field, "buffer_name", getattr(field, "name", ""))
    start_index = getattr(field, "index_start", 0) or 0
    end_index = getattr(field, "index_end", start_index) or start_index
    default_length = max(1, end_index - start_index + 1)

    size_expression = getattr(field, "io_size_expr", None)
    size = resolve_length_expression(size_expression, state.all, resolve_variable=resolve_variable)
    try:
        size = int(size) if size is not None else default_length
    except Exception:
        size = default_length

    size = max(1, size)

    bitstate.align_to_byte()
    start = bitstate.offset
    if getattr(field, "optional", False) and start + size > len(raw_data):
        field.value = None
        field.raw_offset = start
        field.raw_length = 0
        field.raw_data = b""
        field.processed = True
        state.set_field(field, None)
        return field

    chunk = raw_data[start:start + size]
    bitstate.advance_to(start + len(chunk), 0)

    field.raw_offset = start
    field.raw_length = len(chunk)
    field.raw_data = chunk
    value_int = chunk[0] if chunk else 0
    value_mod = value_int

    for modifier in getattr(field, "modifiers", []) or []:
        func = modifiers_operation_mapping.get(modifier)
        if func is not None:
            try:
                value_mod = func(value_mod)
            except Exception:
                pass

    field.value = value_mod
    field.processed = True

    existing = state.all.get(buffer_name)
    if isinstance(existing, list):
        buffer_values = existing
    elif isinstance(existing, (bytes, bytearray)):
        buffer_values = [b for b in existing]
    else:
        buffer_values = []

    required_length = start_index + 1
    if required_length > len(buffer_values):
        buffer_values.extend([None] * (required_length - len(buffer_values)))
    buffer_values[start_index] = value_mod

    state.update_buffer(buffer_name, buffer_values, force_visible=None)

    public_value = value_mod if getattr(field, "visibility_prefix", None) == "+" else f"{value_int & 0xFF:02X}"
    state.set_field(field, value_mod, public_value=public_value)
    return field


def handle_buffer_assign(
    field: Any,
    raw_data: bytes,
    bitstate: Any,
    state: Any,
    *,
    resolve_variable: ResolveVariable,
) -> Any:
    """Read bytes into a buffer and assign them without exposing payload.

    Args:
        field (Any): Buffer assignment node.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit/byte reader state.
        state (Any): Decoder state container.
        resolve_variable (Callable): Variable resolver.

    Returns:
        Any: Updated field.
    """
    buffer_name = getattr(field, "buffer_name", getattr(field, "name", ""))
    start_index = getattr(field, "index_start", 0) or 0
    end_index = getattr(field, "index_end", start_index) or start_index
    default_length = max(1, end_index - start_index + 1)

    size_expression = getattr(field, "io_size_expr", None)
    size = resolve_length_expression(size_expression, state.all, resolve_variable=resolve_variable)
    try:
        size = int(size) if size is not None else default_length
    except Exception:
        size = default_length

    size = max(1, size)

    bitstate.align_to_byte()
    start = bitstate.offset
    if getattr(field, "optional", False) and start + size > len(raw_data):
        field.value = None
        field.raw_offset = start
        field.raw_length = 0
        field.raw_data = b""
        field.processed = True
        state.set_field(field, None)
        return field

    chunk = raw_data[start:start + size]
    bitstate.advance_to(start + len(chunk), 0)

    field.raw_offset = start
    field.raw_length = len(chunk)
    field.raw_data = chunk
    value_int = chunk[0] if chunk else 0
    value_mod = value_int

    for modifier in getattr(field, "modifiers", []) or []:
        func = modifiers_operation_mapping.get(modifier)
        if func is not None:
            try:
                value_mod = func(value_mod)
            except Exception:
                pass

    field.value = value_mod
    field.processed = True

    existing = state.all.get(buffer_name)
    if isinstance(existing, list):
        buffer_values = existing
    elif isinstance(existing, (bytes, bytearray)):
        buffer_values = [b for b in existing]
    else:
        buffer_values = []

    required_length = start_index + size
    if required_length > len(buffer_values):
        buffer_values.extend([None] * (required_length - len(buffer_values)))
    for index, byte_value in enumerate(chunk):
        buffer_values[start_index + index] = value_mod if index == 0 else byte_value

    state.update_buffer(buffer_name, buffer_values, force_visible=None)

    public_value = value_mod if getattr(field, "visibility_prefix", None) == "+" else f"{value_int & 0xFF:02X}"
    state.set_field(field, value_mod, public_value=public_value)
    return field
