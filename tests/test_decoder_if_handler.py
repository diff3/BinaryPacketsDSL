#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DecoderIfHandler."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List
import unittest
from unittest.mock import patch

from modules.dsl.Session import BaseNode, IfNode, get_session
from modules.dsl.decoder.DecoderIfHandler import handle_if_block


@dataclass
class DummyState:
    """Minimal decode state for testing branch selection."""

    all: dict[str, Any]


class DecoderIfHandlerTest(unittest.TestCase):
    """Tests for DecoderIfHandler branch selection."""

    def setUp(self) -> None:
        """Reset global scope before each test."""
        session = get_session()
        session.scope.reset()

    def test_true_branch_executes(self) -> None:
        """Selects the true branch when the condition matches."""
        true_nodes = [BaseNode(name="true_one"), BaseNode(name="true_two")]
        false_nodes = [BaseNode(name="false_one")]
        field = IfNode(
            name="if_flag",
            format="",
            interpreter="if",
            condition="€flag == 1",
            true_branch=true_nodes,
            false_branch=false_nodes,
            elif_branches=None,
        )

        state = DummyState(all={"flag": 1})
        processed: List[str] = []

        def process_field(child: Any, raw_data: bytes, bitstate: Any, endian: str, state_obj: Any) -> tuple[Any, bool, str]:
            processed.append(child.name)
            return child, True, endian

        session = get_session()
        scope_depth_before = len(session.scope.scope_stack)

        with patch("utils.DebugHelper.DebugHelper.trace_field", return_value=None):
            handle_if_block(field, b"", None, "<", state, process_field=process_field)

        self.assertEqual(processed, ["true_one", "true_two"])
        self.assertEqual(len(session.scope.scope_stack), scope_depth_before)

    def test_elif_branch_executes(self) -> None:
        """Selects the first matching elif branch when the main condition fails."""
        elif_one = [BaseNode(name="elif_one")]
        elif_two = [BaseNode(name="elif_two")]
        else_nodes = [BaseNode(name="else_one")]
        field = IfNode(
            name="if_flag",
            format="",
            interpreter="if",
            condition="€flag == 1",
            true_branch=[BaseNode(name="true_one")],
            false_branch=else_nodes,
            elif_branches=[("€flag == 2", elif_one), ("€flag == 3", elif_two)],
        )

        state = DummyState(all={"flag": 3})
        processed: List[str] = []

        def process_field(child: Any, raw_data: bytes, bitstate: Any, endian: str, state_obj: Any) -> tuple[Any, bool, str]:
            processed.append(child.name)
            return child, True, endian

        with patch("utils.DebugHelper.DebugHelper.trace_field", return_value=None):
            handle_if_block(field, b"", None, "<", state, process_field=process_field)

        self.assertEqual(processed, ["elif_two"])

    def test_else_branch_executes(self) -> None:
        """Falls back to else branch when no conditions match."""
        else_nodes = [BaseNode(name="else_one")]
        field = IfNode(
            name="if_flag",
            format="",
            interpreter="if",
            condition="€flag == 1",
            true_branch=[BaseNode(name="true_one")],
            false_branch=else_nodes,
            elif_branches=None,
        )

        state = DummyState(all={"flag": 0})
        processed: List[str] = []

        def process_field(child: Any, raw_data: bytes, bitstate: Any, endian: str, state_obj: Any) -> tuple[Any, bool, str]:
            processed.append(child.name)
            return child, True, endian

        with patch("utils.DebugHelper.DebugHelper.trace_field", return_value=None):
            handle_if_block(field, b"", None, "<", state, process_field=process_field)

        self.assertEqual(processed, ["else_one"])

    def test_and_condition_executes(self) -> None:
        """Evaluates an 'and' condition correctly."""
        field = IfNode(
            name="if_flag_mode",
            format="",
            interpreter="if",
            condition="€flag == 1 and €mode == 2",
            true_branch=[BaseNode(name="true_one")],
            false_branch=[BaseNode(name="else_one")],
            elif_branches=None,
        )

        state = DummyState(all={"flag": 1, "mode": 2})
        processed: List[str] = []

        def process_field(child: Any, raw_data: bytes, bitstate: Any, endian: str, state_obj: Any) -> tuple[Any, bool, str]:
            processed.append(child.name)
            return child, True, endian

        with patch("utils.DebugHelper.DebugHelper.trace_field", return_value=None):
            handle_if_block(field, b"", None, "<", state, process_field=process_field)

        self.assertEqual(processed, ["true_one"])

    def test_or_condition_executes(self) -> None:
        """Evaluates an 'or' condition correctly."""
        field = IfNode(
            name="if_flag_mode",
            format="",
            interpreter="if",
            condition="€flag == 1 or €mode == 2",
            true_branch=[BaseNode(name="true_one")],
            false_branch=[BaseNode(name="else_one")],
            elif_branches=None,
        )

        state = DummyState(all={"flag": 0, "mode": 2})
        processed: List[str] = []

        def process_field(child: Any, raw_data: bytes, bitstate: Any, endian: str, state_obj: Any) -> tuple[Any, bool, str]:
            processed.append(child.name)
            return child, True, endian

        with patch("utils.DebugHelper.DebugHelper.trace_field", return_value=None):
            handle_if_block(field, b"", None, "<", state, process_field=process_field)

        self.assertEqual(processed, ["true_one"])


if __name__ == "__main__":
    unittest.main()
