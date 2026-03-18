#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from shared.ConfigLoader import ConfigLoader
from shared.Logger import Logger
import pprint


def dsl_debug_enabled() -> bool:
    """Return True when internal DSL debug output is enabled."""
    try:
        cfg = ConfigLoader.get_config()
        return bool(cfg.get("dsl", {}).get("debug", False))
    except Exception:
        return False


def dsl_debug(message: str) -> None:
    """Emit a debug message only when DSL debug is explicitly enabled."""
    if dsl_debug_enabled():
        Logger.debug(message)


class DebugHelper:
    """Deep inspection debugging for BaseNode structures."""

    @staticmethod
    def trace_node_state(label, node):
        """
        Print a deep dump of the BaseNode object:
            - All attributes
            - Children
            - Raw offsets and values
        """

        if node is None:
            dsl_debug(f"[NODE STATE @ {label}] <None>")
            return

        dsl_debug(f"\n[NODE STATE @ {label}] type={type(node).__name__}")

        # dump node.__dict__ in readable form
        try:
            pretty = pprint.pformat(node.__dict__, indent=4, width=120)
            dsl_debug(pretty)
        except Exception as e:
            dsl_debug(f"Failed to print node: {e}")

        dsl_debug("")  # extra spacing

    @staticmethod
    def trace_field(field, bitstate=None, label_prefix="after"):
        """
        Old behavior + new node debugging.
        """
        DebugHelper.trace_node_state(label_prefix, field)

        if bitstate:
            name = getattr(field, "name", "")
            bitstate.debug(f"{label_prefix} {name}")
