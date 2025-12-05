#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.Logger import Logger


class DebugHelper:
    """Lightweight debug helper to centralize field/bitstate logging."""

    @staticmethod
    def trace_field(field, bitstate=None, label_prefix="after"):
        """
        Log a field and optional bitstate snapshot.
        """
        Logger.debug(field)
        if bitstate:
            name = getattr(field, "name", "")
            bitstate.debug(f"{label_prefix} {name}")

