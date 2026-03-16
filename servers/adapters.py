#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
adapters.py

Adapter layer for proxy/auth/world.

Design:
- Adapters are pure functions or small objects.
- No sockets, no routing, no listener logic.
- Data flows through adapters in order.
- Adapters may observe or modify bytes.

This file supports:
- simple functional adapter chains
- optional class-based adapters (future-proof)
"""

from __future__ import annotations

import time
from typing import Callable, Iterable, List


# ============================================================
# Adapter type
# ============================================================

# Adapter function signature:
#   adapter(state, data: bytes, direction: str) -> bytes
AdapterFn = Callable[[object, bytes, str], bytes]


# ============================================================
# Core helper used by proxy
# ============================================================

def apply_adapters(state, data: bytes, direction: str) -> bytes:
    """
    Apply all adapters attached to the current connection/state.

    This is intentionally SIMPLE.
    The proxy core already calls this.

    Arguments:
        state     – connection/session state object
        data      – raw bytes
        direction – "C2S" or "S2C"

    Returns:
        bytes to forward (possibly modified)
    """
    adapters: Iterable[AdapterFn] = getattr(state, "adapters", [])

    out = data
    for adapter in adapters:
        try:
            out = adapter(state, out, direction)
            if not out:
                # Adapter explicitly dropped packet
                return b""
        except Exception as exc:
            # Adapters must never crash the proxy
            print(f"[adapter-error] {adapter.__name__}: {exc}")
            return data  # fail-open

    return out


# ============================================================
# Built-in adapters (functional)
# ============================================================

def size_logger_adapter(state, data: bytes, direction: str) -> bytes:
    """
    Logs packet size only (safe, cheap).
    """
    conn_id = getattr(state, "conn_id", "?")
    role = getattr(state, "role", "?")
    print(f"[{conn_id} {role} {direction}] {len(data)} bytes")
    return data


def hex_dump_adapter(max_bytes: int = 256) -> AdapterFn:
    """
    Factory: returns an adapter that hex-dumps packets.
    """
    def _adapter(state, data: bytes, direction: str) -> bytes:
        conn_id = getattr(state, "conn_id", "?")
        role = getattr(state, "role", "?")
        sample = data[:max_bytes]
        print(
            f"[{conn_id} {role} {direction}] HEX ({len(data)} bytes)\n"
            f"{sample.hex(' ')}"
        )
        return data
    return _adapter


def latency_adapter(state, data: bytes, direction: str) -> bytes:
    """
    Measures time between packets per direction.
    """
    now = time.time()
    key = f"_lat_{direction}"
    last = getattr(state, key, None)
    setattr(state, key, now)

    if last is not None:
        delta_ms = (now - last) * 1000.0
        if delta_ms > 50:
            conn_id = getattr(state, "conn_id", "?")
            role = getattr(state, "role", "?")
            print(f"[{conn_id} {role} {direction}] Δ {delta_ms:.1f} ms")

    return data


def byte_patch_adapter(offset: int, value: int) -> AdapterFn:
    """
    Factory: patches one byte at a fixed offset.
    EXPERIMENTAL.
    """
    def _adapter(state, data: bytes, direction: str) -> bytes:
        if len(data) <= offset:
            return data
        b = bytearray(data)
        b[offset] = value
        return bytes(b)
    return _adapter


# ============================================================
# DSL adapter (bridges BinaryDSL into proxy)
# ============================================================

def dsl_decode_adapter(runtime, client_opcodes: dict, server_opcodes: dict) -> AdapterFn:
    """
    Adapter that decodes packets using BinaryDSL runtime.

    - Observes only
    - Never blocks forwarding
    """
    def _adapter(state, data: bytes, direction: str) -> bytes:
        if not data:
            return data

        opcode = data[0]
        name = (
            client_opcodes.get(opcode)
            if direction == "C2S"
            else server_opcodes.get(opcode)
        )
        if not name:
            return data

        try:
            decoded = runtime.decode(name, data, silent=True)
            conn_id = getattr(state, "conn_id", "?")
            role = getattr(state, "role", "?")
            print(f"[{conn_id} {role} {direction}] {name} (0x{opcode:02X})")
            print(decoded)
        except Exception as exc:
            print(f"[dsl-error] {name}: {exc}")

        return data

    return _adapter


# ============================================================
# Default wiring helper
# ============================================================

def default_adapters_for_role(role: str) -> List[AdapterFn]:
    """
    Policy helper.
    Decide here what adapters a role gets.
    """
    if role == "LOGIN":
        return [
            size_logger_adapter,
            # latency_adapter,
        ]
    if role == "WORLD":
        return [
            latency_adapter,
        ]
    return []