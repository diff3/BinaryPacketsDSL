#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# state.py
from dataclasses import dataclass, field
from typing import Literal
from threading import Lock

Phase = Literal["auth", "world"]


@dataclass
class SessionState:
    """
    Per-connection session state.
    Describes protocol position and capabilities.
    """
    phase: Phase = "auth"
    encrypted: bool = False
    shutdown: bool = False


@dataclass
class GlobalState:
    """
    Global control-plane state.
    Controlled by telnet, observed by proxy.
    """
    shutdown: bool = False
    enable_log: bool = True
    enable_view: bool = True
    enable_decode: bool = False

    lock: Lock = field(default_factory=Lock)