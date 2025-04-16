#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class SliceInterpreter:
    @staticmethod
    def extract_variable_and_slice(expr: str) -> tuple[str, slice]:
        """
        Parses '€var[1:4]' or '€var[::-1]' into ('var', slice(...))

        Returns:
            tuple: (variable name, Python slice object)
        """
        if not expr.startswith("€") or "[" not in expr or not expr.endswith("]"):
            raise ValueError("Invalid slice expression")

        var_part = expr[1:expr.index("[")]
        slice_expr = expr[expr.index("[")+1 : -1]

        # Split into parts: start:end:step
        parts = slice_expr.split(":")
        if not 1 <= len(parts) <= 3:
            raise ValueError(f"Invalid slice: {slice_expr}")

        # Convert to int or None
        start = int(parts[0]) if parts[0] else None
        stop = int(parts[1]) if len(parts) > 1 and parts[1] else None
        step = int(parts[2]) if len(parts) > 2 and parts[2] else None

        return var_part, slice(start, stop, step)

    @staticmethod
    def apply_slice(value, slice_obj: slice):
        """
        Applies a Python slice to a string or bytes-like object.
        """
        return value[slice_obj]