#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder condition helpers for DSL if/elif/else evaluation."""

from __future__ import annotations

from typing import Any

from modules.dsl.decoder.DecoderExpressions import (
    preprocess_condition,
    build_eval_context,
)


def evaluate_condition(condition: str | None, state_data: dict[str, Any]) -> bool:
    """Evaluate a DSL condition using the current decode context.

    Args:
        condition (str | None): Raw condition string from the DSL.
        state_data (dict[str, Any]): Current decode state dictionary.

    Returns:
        bool: True when the condition evaluates truthy.
    """
    normalized = preprocess_condition((condition or "").strip())
    if not normalized:
        return False

    context = build_eval_context(state_data)
    try:
        return bool(eval(normalized, {}, context))
    except Exception:
        return False
