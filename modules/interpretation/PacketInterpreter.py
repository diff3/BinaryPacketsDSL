#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Packet interpretation helpers: decode, normalize, and dump."""

from typing import Any, Iterable, Optional

from modules.interpretation.utils import dump_capture, to_safe_json, dsl_decode


class PacketInterpreter:
    """Coordinates decoding, normalization, and optional dumping of packets."""

    def __init__(self, decoder: "DslDecoder", normalizer: "JsonNormalizer", policy: "DumpPolicy", dumper: "PacketDumper") -> None:
        """Initialize interpreter with collaborators."""
        self.decoder = decoder
        self.normalizer = normalizer
        self.policy = policy
        self.dumper = dumper

    def interpret(self, name: str, raw_header: bytes, payload: bytes) -> dict:
        """
        Decode and normalize a packet, then dump/update if policy allows.

        Args:
            name: Packet name (opcode resolved).
            raw_header: Raw header bytes.
            payload: Raw payload bytes.

        Returns:
            JSON-safe decoded structure.
        """
        decoded = self.decoder.decode(name, payload)
        safe = self.normalizer.normalize(decoded)

        if self.policy.allows(name):
            if self.policy.update:
                self.dumper.update(name, raw_header, payload, safe)
            if self.policy.dump:
                self.dumper.dump(name, raw_header, payload, safe)

        return safe


class PacketDumper:
    """Wraps dump/update operations for decoded packets."""

    def __init__(self, dumper: Any) -> None:
        self.dumper = dumper

    def dump(self, name: str, raw_header: bytes, payload: bytes, safe: dict) -> None:
        dump_capture(name, raw_header, payload, safe)

    def update(self, name: str, raw_header: bytes, payload: bytes, safe: dict) -> None:
        self.dumper.dump_fixed(name, raw_header, payload, safe)


class DumpPolicy:
    """Controls whether packets are dumped or updated."""

    def __init__(self, dump: bool = False, update: bool = False, focus_dump: Optional[Iterable[str]] = None) -> None:
        self.dump = dump
        self.update = update
        self.focus_dump = set(focus_dump) if focus_dump else None

    def allows(self, name: str) -> bool:
        return self.focus_dump is None or name in self.focus_dump


class JsonNormalizer:
    """Converts decoded values into JSON-safe structures."""

    def normalize(self, value: Any) -> Any:
        return to_safe_json(value)


class DslDecoder:
    """
    Thin wrapper around DSL decode.
    Forces DSL runtime initialization at construction time.
    """

    def __init__(self):
        dsl_decode("__INIT__", b"", silent=True)

    def decode(self, name: str, payload: bytes) -> dict:
        return dsl_decode(name, payload, silent=True) or {}