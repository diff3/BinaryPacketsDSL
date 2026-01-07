#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for DecoderExpressions."""

from __future__ import annotations

import unittest

from modules.dsl.Session import get_session
from modules.dsl.decoder.DecoderExpressions import (
    build_eval_context,
    eval_expr,
    preprocess_condition,
    resolve_variable,
)


class DecoderExpressionsTest(unittest.TestCase):
    """Tests for DecoderExpressions helpers."""

    def setUp(self) -> None:
        """Reset global scope before each test."""
        session = get_session()
        session.scope.reset()

    def test_preprocess_condition_handles_dot_access(self) -> None:
        """Converts dot access into dictionary syntax."""
        condition = "€foo.bar == 1"
        result = preprocess_condition(condition)
        self.assertEqual(result, 'foo["bar"] == 1')

    def test_build_eval_context_merges_global_scope(self) -> None:
        """Builds evaluation context from scope and local state."""
        session = get_session()
        session.scope.set("global_value", 7)

        context = build_eval_context({"local_value": 3})

        self.assertEqual(context.get("global_value"), 7)
        self.assertEqual(context.get("local_value"), 3)

    def test_resolve_variable_with_index_and_key(self) -> None:
        """Resolves a variable with index and subkey."""
        session = get_session()
        session.scope.set("items", [{"value": 10}, {"value": 20}])
        session.scope.set("i", 1)

        result = resolve_variable("€items[i].value", {})

        self.assertEqual(result, 20)

    def test_eval_expr_arithmetic(self) -> None:
        """Evaluates arithmetic expressions."""
        result = eval_expr("1 + 2 * 3", {})
        self.assertEqual(result, 7)

    def test_eval_expr_slice_tuple(self) -> None:
        """Returns slice instruction for raw slice expressions."""
        result = eval_expr("raw[1:4]", {})
        self.assertEqual(result, ("slice", 1, 4, None))

    def test_eval_expr_variable_reference(self) -> None:
        """Resolves variable references with the € prefix."""
        scope = {"count": 5}
        result = eval_expr("€count", scope)
        self.assertEqual(result, 5)

    def test_eval_expr_subscript_access(self) -> None:
        """Evaluates subscript access for lists."""
        scope = {"values": [10, 20, 30]}
        result = eval_expr("values[1]", scope)
        self.assertEqual(result, 20)


if __name__ == "__main__":
    unittest.main()
