#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DecoderBufferHandlers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import unittest

from modules.dsl.Session import BaseNode
from modules.dsl.decoder.DecoderBufferHandlers import (
    handle_buffer_allocation,
    handle_buffer_assign,
    handle_buffer_io,
    resolve_length_expression,
)


@dataclass
class DummyBitState:
    """Minimal bitstate for buffer handler tests."""

    offset: int = 0

    def align_to_byte(self) -> None:
        """Alignment no-op for tests."""
        return None

    def advance_to(self, offset: int, bit_pos: int) -> None:
        """Advance to a new offset, ignoring bit position for tests."""
        self.offset = offset


class DummyDecodeState:
    """Minimal decode state to capture buffer outputs."""

    def __init__(self) -> None:
        self.all: dict[str, Any] = {}
        self.public: dict[str, Any] = {}
        self._buffers: dict[str, list[Any]] = {}

    def remember_buffer(self, field: Any, value: list[Any], public_value: str | None = None) -> None:
        """Store buffer in state."""
        name = getattr(field, "name", None)
        if not name:
            return
        self.all[name] = value
        if public_value is None:
            self.public[name] = value
        else:
            self.public[name] = public_value
        self._buffers[name] = value

    def update_buffer(self, name: str, buffer_values: list[Any], *, force_visible: Any | None = None) -> None:
        """Update buffer in state."""
        self.all[name] = buffer_values
        if force_visible is None:
            self.public[name] = buffer_values
        else:
            self.public[name] = buffer_values

    def set_field(self, field: Any, value: Any, *, public_value: Any | None = None) -> None:
        """Store a field result for tests."""
        name = getattr(field, "name", None)
        if not name:
            return
        self.all[name] = value
        if public_value is None:
            self.public[name] = value
        else:
            self.public[name] = public_value


class DecoderBufferHandlersTest(unittest.TestCase):
    """Tests for DecoderBufferHandlers."""

    def test_resolve_length_expression(self) -> None:
        """Parses raw length expressions and variables."""
        scope = {"len": 3}
        resolve_variable = lambda key, scope_data: scope_data.get(key)

        self.assertEqual(resolve_length_expression("4B", scope, resolve_variable=resolve_variable), 4)
        self.assertEqual(resolve_length_expression("3", scope, resolve_variable=resolve_variable), 3)
        self.assertEqual(resolve_length_expression("€len", scope, resolve_variable=resolve_variable), 3)
        self.assertIsNone(resolve_length_expression("", scope, resolve_variable=resolve_variable))

    def test_handle_buffer_allocation(self) -> None:
        """Allocates buffers with the requested size."""
        field = BaseNode(name="buffer", format="", interpreter="buffer_alloc")
        field.alloc_size_expr = "4"
        bitstate = DummyBitState(offset=2)
        state = DummyDecodeState()

        def resolve_variable(key: str, scope: dict[str, Any]) -> Any:
            return scope.get(key)

        def present_buffer(buffer_values: list[Any]) -> str:
            return "".join("00" if value is None else f"{value:02X}" for value in buffer_values)

        result = handle_buffer_allocation(
            field,
            bitstate,
            state,
            resolve_variable=resolve_variable,
            present_buffer=present_buffer,
        )

        self.assertEqual(len(result.value), 4)
        self.assertEqual(state.all.get("buffer"), result.value)
        self.assertEqual(result.raw_offset, 2)

    def test_handle_buffer_io_reads_byte(self) -> None:
        """Reads a byte into a buffer and advances the offset."""
        field = BaseNode(name="buf[0]", format="B", interpreter="buffer_io")
        field.buffer_name = "buf"
        field.index_start = 0
        field.index_end = 0
        field.io_size_expr = "1"
        field.modifiers = []
        bitstate = DummyBitState(offset=0)
        state = DummyDecodeState()

        handle_buffer_io(
            field,
            b"\x2A",
            bitstate,
            state,
            resolve_variable=lambda key, scope: None,
        )

        self.assertEqual(bitstate.offset, 1)
        self.assertEqual(state.all.get("buf"), [0x2A])
        self.assertEqual(state.all.get("buf[0]"), 0x2A)

    def test_handle_buffer_assign_reads_bytes(self) -> None:
        """Reads multiple bytes into a buffer assignment."""
        field = BaseNode(name="buf[0-1]", format="2B", interpreter="buffer_assign")
        field.buffer_name = "buf"
        field.index_start = 0
        field.index_end = 1
        field.io_size_expr = "2"
        field.modifiers = []
        bitstate = DummyBitState(offset=0)
        state = DummyDecodeState()

        handle_buffer_assign(
            field,
            b"\x2A\x2B",
            bitstate,
            state,
            resolve_variable=lambda key, scope: None,
        )

        self.assertEqual(bitstate.offset, 2)
        self.assertEqual(state.all.get("buf"), [0x2A, 0x2B])
        self.assertEqual(state.all.get("buf[0-1]"), 0x2A)


if __name__ == "__main__":
    unittest.main()
