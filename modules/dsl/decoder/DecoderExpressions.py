#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder expression helpers.

This module keeps DSL expression parsing and evaluation isolated from the
DecoderHandler core for readability and testing.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from modules.dsl.Session import get_session
from utils.Logger import Logger


def preprocess_condition(condition: str | None) -> str | None:
    """Normalize DSL conditions to Python-like expressions.

    Args:
        condition (str | None): Raw condition string from the DSL.

    Returns:
        str | None: Normalized condition string or the original value if empty.
    """
    if not isinstance(condition, str) or not condition:
        return condition

    normalized = condition.replace("€", "")
    normalized = re.sub(r"(\w+\[[^\]]+\])\.(\w+)", r'\1["\2"]', normalized)
    normalized = re.sub(r"\b([A-Za-z_]\w*)\.(\w+)", r'\1["\2"]', normalized)
    return normalized


def build_eval_context(state_data: dict[str, Any] | None) -> dict[str, Any]:
    """Build the evaluation context from local state and global scope.

    Args:
        state_data (dict[str, Any] | None): Local decode state.

    Returns:
        dict[str, Any]: Merged context for expression evaluation.
    """
    context: dict[str, Any] = {}
    if isinstance(state_data, dict):
        context.update(state_data)

    session = get_session()
    scope = session.scope

    if getattr(scope, "global_vars", None):
        context.update(scope.global_vars)

    for frame in getattr(scope, "scope_stack", []):
        context.update(frame)

    return context


def resolve_variable(key: str, result: dict[str, Any] | None) -> Any:
    """Resolve a DSL variable reference against scope and current state.

    Args:
        key (str): Variable key, including optional prefix (e.g. "€foo").
        result (dict[str, Any] | None): Current decode state values.

    Returns:
        Any: Resolved value, or None if not found/invalid.
    """
    session = get_session()
    scope = session.scope
    original_key = key
    result = result or {}

    if not isinstance(key, str):
        return None

    if key.endswith("'s"):
        key = key[:-2]

    if key.startswith("€"):
        key = key[1:]

        match = re.match(r"^(\w+)(?:\[(\w+)\])?(?:\.(\w+))?$", key)
        if not match:
            Logger.debug(f"[resolve_variable] regex miss: {original_key}")
            return None

        base, index, subkey = match.groups()
        Logger.debug(
            f"[resolve_variable] key={original_key} → base={base}, index={index}, subkey={subkey}"
        )

        value = scope.get(base, result.get(base))
        if value is None:
            return None

        if index is not None:
            if index == "i":
                index_value = scope.get("i")
            elif index.isdigit():
                index_value = int(index)
            else:
                index_value = scope.get(index, result.get(index))

            Logger.debug(f"[resolve_variable] index={index!r} → {index_value!r}")
            if not isinstance(index_value, int):
                return None

            try:
                value = value[index_value]
            except Exception:
                Logger.debug(f"[resolve_variable] index error {base}[{index_value}]")
                return None

        if subkey is not None:
            try:
                value = value[subkey]
            except Exception:
                Logger.debug(f"[resolve_variable] subkey error {base}.{subkey}")
                return None

        Logger.debug(f"[resolve_variable] resolved {original_key!r} → {value!r}")
        return value

    try:
        return int(key)
    except ValueError:
        pass

    try:
        return float(key)
    except ValueError:
        return None


def eval_expr(expression: str, scope: dict[str, Any], raw: bytes | None = None) -> Any:
    """Evaluate a DSL expression safely with limited operators.

    Args:
        expression (str): Expression string from the DSL.
        scope (dict[str, Any]): Local scope values.
        raw (bytes | None): Raw payload bytes (unused except for slice markers).

    Returns:
        Any: Evaluated value or a slice instruction tuple.
    """
    if not isinstance(expression, str):
        return expression

    expression = expression.strip()

    match = re.fullmatch(r"raw\[\s*(.+?)\s*:\s*(.+?)\s*\]", expression)
    if match:
        start_expression, end_expression = match.groups()

        start_value = eval_expr(start_expression, scope, raw)
        end_value = eval_expr(end_expression, scope, raw)

        if not isinstance(start_value, int) or not isinstance(end_value, int):
            raise ValueError(f"Invalid slice bounds: {expression}")

        return ("slice", start_value, end_value, None)

    if expression.startswith("€") and re.fullmatch(
        r"€\w+(?:\[\w+\])?(?:\.\w+)?", expression
    ):
        return resolve_variable(expression, scope)

    def evaluate_node(node: ast.AST, context: dict[str, Any]) -> Any:
        if isinstance(node, ast.Expression):
            return evaluate_node(node.body, context)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            value = context.get(node.id, 0)
            return 0 if value is None else value
        if isinstance(node, ast.BinOp):
            left_value = evaluate_node(node.left, context)
            right_value = evaluate_node(node.right, context)
            if isinstance(node.op, ast.Add):
                return left_value + right_value
            if isinstance(node.op, ast.Sub):
                return left_value - right_value
            if isinstance(node.op, ast.Mult):
                return left_value * right_value
            if isinstance(node.op, ast.Div):
                return left_value / right_value
            if isinstance(node.op, ast.Mod):
                return left_value % right_value
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        if isinstance(node, ast.UnaryOp):
            value = evaluate_node(node.operand, context)
            if isinstance(node.op, ast.UAdd):
                return +value
            if isinstance(node.op, ast.USub):
                return -value
            raise ValueError(f"Unsupported unary operator: {type(node.op).__name__}")
        if isinstance(node, ast.Subscript):
            target = evaluate_node(node.value, context)
            slice_value = evaluate_node(node.slice, context)
            return target[slice_value]
        if isinstance(node, ast.Slice):
            lower = evaluate_node(node.lower, context) if node.lower is not None else None
            upper = evaluate_node(node.upper, context) if node.upper is not None else None
            step = evaluate_node(node.step, context) if node.step is not None else None
            return slice(lower, upper, step)
        if hasattr(ast, "Index") and isinstance(node, ast.Index):  # py<3.9
            return evaluate_node(node.value, context)
        raise ValueError(f"Unsupported expression node: {type(node).__name__}")

    normalized_expression = preprocess_condition(expression) or ""
    context = build_eval_context(scope)
    try:
        tree = ast.parse(normalized_expression, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Invalid expression: {expression}") from exc

    return evaluate_node(tree, context)
