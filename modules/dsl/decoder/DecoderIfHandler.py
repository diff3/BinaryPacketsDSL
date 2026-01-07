#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder helpers for DSL if/elif/else handling."""

from __future__ import annotations

from typing import Any, Callable

from modules.dsl.Session import get_session
from modules.dsl.decoder.DecoderConditions import evaluate_condition
from utils.DebugHelper import DebugHelper


DecodeProcessField = Callable[[Any, bytes, Any, str, Any], tuple[Any, bool, str]]


def handle_if_block(
    field: Any,
    raw_data: bytes,
    bitstate: Any,
    endian: str,
    state: Any,
    *,
    process_field: DecodeProcessField,
) -> tuple[Any, bool, str]:
    """Evaluate and execute an if/elif/else branch for the decoder.

    Args:
        field (Any): The IfNode instance.
        raw_data (bytes): Raw packet bytes.
        bitstate (Any): Current bit/byte reader state.
        endian (str): Current endianness token.
        state (Any): Decoder state container.
        process_field (Callable): Function to process child nodes.

    Returns:
        tuple[Any, bool, str]: (field, stored, endian).
    """
    session = get_session()
    scope = session.scope

    branch = None

    if evaluate_condition(field.condition, state.all):
        branch = field.true_branch
    else:
        if field.elif_branches:
            for condition, nodes in field.elif_branches:
                if evaluate_condition(condition, state.all):
                    branch = nodes
                    break

        if branch is None:
            branch = field.false_branch or []

    scope.push()
    try:
        for child_template in (branch or []):
            child = child_template.copy()
            process_field(child, raw_data, bitstate, endian, state)
            DebugHelper.trace_field(child, bitstate)
    finally:
        scope.pop()

    return field, True, endian
