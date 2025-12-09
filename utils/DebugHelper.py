#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger
import pprint


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
            Logger.debug(f"[NODE STATE @ {label}] <None>")
            return

        Logger.debug(f"\n[NODE STATE @ {label}] type={type(node).__name__}")

        # dump node.__dict__ in readable form
        try:
            pretty = pprint.pformat(node.__dict__, indent=4, width=120)
            Logger.debug(pretty)
        except Exception as e:
            Logger.debug(f"Failed to print node: {e}")

        Logger.debug("")  # extra spacing

    @staticmethod
    def trace_field(field, bitstate=None, label_prefix="after"):
        """
        Old behavior + new node debugging.
        """
        DebugHelper.trace_node_state(label_prefix, field)

        if bitstate:
            name = getattr(field, "name", "")
            bitstate.debug(f"{label_prefix} {name}")