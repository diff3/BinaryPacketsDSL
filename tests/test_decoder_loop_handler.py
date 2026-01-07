#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DecoderLoopHandler."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, List
import unittest

from modules.dsl.Session import BaseNode, LoopNode, get_session
from modules.dsl.decoder.DecoderLoopHandler import handle_loop_block


@dataclass
class DummyBitState:
    """Minimal bitstate for loop handler tests."""

    offset: int = 0
    bit_pos: int = 0


class DummyDecodeState:
    """Minimal decode state to capture loop output."""

    def __init__(self) -> None:
        self.all: dict[str, Any] = {}
        self.public: dict[str, Any] = {}

    def set_field(self, field: Any, value: Any, *, public_value: Any | None = None) -> None:
        """Store a field result for loop output."""
        name = getattr(field, "name", None)
        if not name:
            return
        self.all[name] = value
        if public_value is None:
            self.public[name] = value
        else:
            self.public[name] = public_value


class DecoderLoopHandlerTest(unittest.TestCase):
    """Tests for DecoderLoopHandler behavior."""

    def setUp(self) -> None:
        """Reset global scope before each test."""
        session = get_session()
        session.scope.reset()

    def test_until_end_consumes_all(self) -> None:
        """Loops until end of data and collects entries."""
        children = [BaseNode(name="value")]
        field = LoopNode(
            name="items",
            format="",
            interpreter="loop",
            count_from="until_end",
            target="items",
            dynamic=False,
            children=children,
        )

        state = DummyDecodeState()
        bitstate = DummyBitState()
        raw_data = b"\x01\x02\x03"

        def process_field(child: Any, raw: bytes, bit: DummyBitState, endian: str, entry_state: DummyDecodeState) -> tuple[Any, bool, str]:
            value = raw[bit.offset]
            child.value = value
            entry_state.set_field(child, value)
            bit.offset += 1
            return child, True, endian

        session = get_session()
        scope_depth_before = len(session.scope.scope_stack)

        handle_loop_block(
            field,
            raw_data,
            bitstate,
            "<",
            state,
            process_field=process_field,
            resolve_variable=lambda key, scope: None,
            state_factory=DummyDecodeState,
        )

        self.assertEqual(bitstate.offset, 3)
        self.assertEqual(len(state.all.get("items", [])), 3)
        self.assertEqual(len(session.scope.scope_stack), scope_depth_before)

    def test_until_end_stops_on_none(self) -> None:
        """Stops scanning when a child field resolves to None."""
        children = [BaseNode(name="value")]
        field = LoopNode(
            name="items",
            format="",
            interpreter="loop",
            count_from="until_end",
            target="items",
            dynamic=False,
            children=children,
        )

        state = DummyDecodeState()
        bitstate = DummyBitState()
        raw_data = b"\x01\x02\x03"

        def process_field(child: Any, raw: bytes, bit: DummyBitState, endian: str, entry_state: DummyDecodeState) -> tuple[Any, bool, str]:
            if bit.offset >= 1:
                child.value = None
            else:
                child.value = raw[bit.offset]
                entry_state.set_field(child, child.value)
            bit.offset += 1
            return child, True, endian

        handle_loop_block(
            field,
            raw_data,
            bitstate,
            "<",
            state,
            process_field=process_field,
            resolve_variable=lambda key, scope: None,
            state_factory=DummyDecodeState,
        )

        self.assertEqual(bitstate.offset, 1)
        self.assertEqual(len(state.all.get("items", [])), 1)

    def test_count_loop_executes(self) -> None:
        """Executes the fixed-count loop and captures outputs."""
        children = [BaseNode(name="value")]
        field = LoopNode(
            name="items",
            format="",
            interpreter="loop",
            count_from="€count",
            target="items",
            dynamic=True,
            children=children,
        )

        state = DummyDecodeState()
        state.all["count"] = 2
        bitstate = DummyBitState()
        raw_data = b"\x00\x01"

        def process_field(child: Any, raw: bytes, bit: DummyBitState, endian: str, entry_state: DummyDecodeState) -> tuple[Any, bool, str]:
            session = get_session()
            index_value = session.scope.get("i")
            child.value = index_value
            entry_state.set_field(child, index_value)
            bit.offset += 1
            return child, True, endian

        def resolve_variable(key: str, scope: dict[str, Any]) -> Any:
            cleaned = key.lstrip("€")
            return scope.get(cleaned)

        handle_loop_block(
            field,
            raw_data,
            bitstate,
            "<",
            state,
            process_field=process_field,
            resolve_variable=resolve_variable,
            state_factory=DummyDecodeState,
        )

        self.assertEqual(len(state.all.get("items", [])), 2)
        self.assertEqual(bitstate.offset, 2)

    def test_invalid_count_returns_empty(self) -> None:
        """Handles invalid loop counts by returning an empty list."""
        children = [BaseNode(name="value")]
        field = LoopNode(
            name="items",
            format="",
            interpreter="loop",
            count_from="€count",
            target="items",
            dynamic=True,
            children=children,
        )

        state = DummyDecodeState()
        bitstate = DummyBitState()
        raw_data = b"\x00\x01"

        def process_field(child: Any, raw: bytes, bit: DummyBitState, endian: str, entry_state: DummyDecodeState) -> tuple[Any, bool, str]:
            child.value = 0
            entry_state.set_field(child, 0)
            bit.offset += 1
            return child, True, endian

        def resolve_variable(key: str, scope: dict[str, Any]) -> Any:
            return "invalid"

        handle_loop_block(
            field,
            raw_data,
            bitstate,
            "<",
            state,
            process_field=process_field,
            resolve_variable=resolve_variable,
            state_factory=DummyDecodeState,
        )

        self.assertEqual(len(state.all.get("items", [])), 0)


if __name__ == "__main__":
    unittest.main()
