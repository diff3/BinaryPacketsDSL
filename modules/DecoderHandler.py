#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Decoder entry point and core dispatch logic for DSL parsing.

This module keeps the hot path in _process_field while delegating each
interpreter to small, testable handlers. The order matters: guard optional IO,
then interpreter dispatch, then special cases (endian/dynamic/string), and
finally struct fallback. Add new interpreter handlers to INTERPRETER_HANDLERS.
"""

from __future__ import annotations

import json
import re
import struct
from typing import Any, Callable, Optional

from DSL.modules.ModifierMapping import modifiers_operation_mapping
from DSL.modules.Session import VariableNode, get_session
from DSL.modules.bitsHandler import BitState
from DSL.modules.decoder.DecoderBitHandlers import decode_bits_field, handle_bitmask
from DSL.modules.decoder.DecoderBufferHandlers import (
    handle_buffer_allocation,
    handle_buffer_assign,
    handle_buffer_io,
    resolve_length_expression,
)
from DSL.modules.decoder.DecoderExpressions import eval_expr, resolve_variable
from DSL.modules.decoder.DecoderIfHandler import handle_if_block
from DSL.modules.decoder.DecoderLoopHandler import handle_loop_block
from DSL.modules.decoder.DecoderPacketHandlers import (
    combine_guid,
    handle_packed_guid,
    handle_uncompress,
)
from DSL.modules.decoder.DecoderStringHandlers import handle_read_rest, resolve_string_format
from DSL.modules.decoder.DecoderUtilities import split_print_args, log_print_message
from shared.Logger import Logger


class DecodeState:
    """Stores decode output values and presentation state."""

    def __init__(self, session=None) -> None:
        """Initialize a new decode state container.

        Args:
            session (Any | None): Optional session override for tests.
        """
        self._session = session or get_session()
        self.all: dict[str, Any] = {}
        self.public: dict[str, Any] = {}
        self.buffer_visibility: dict[str, bool] = {}

    def remember_buffer(self, field: Any, value: list[Any], public_value: Optional[str] = None) -> None:
        """Store a newly allocated buffer in state.

        Args:
            field (Any): Buffer allocation field.
            value (list[Any]): Buffer values.
            public_value (str | None): Optional public representation.
        """
        name = getattr(field, "name", None)
        if not name:
            return
        self.buffer_visibility[name] = DecoderHandler.is_visible(field)
        self.set_field(field, value, public_value=public_value)

    def update_buffer(self, name: str, buffer_values: Any, *, force_visible: Optional[bool] = None) -> None:
        """Update a buffer and its public representation.

        Args:
            name (str): Buffer name.
            buffer_values (Any): Buffer-like object.
            force_visible (bool | None): Optional visibility override.
        """
        if not name:
            return

        if isinstance(buffer_values, (bytes, bytearray)):
            normalized = [b for b in buffer_values]
        elif isinstance(buffer_values, list):
            normalized = list(buffer_values)
        else:
            try:
                normalized = list(buffer_values)
            except Exception:
                normalized = []

        self.all[name] = normalized
        self._session.scope.set(name, normalized)

        visible = self.buffer_visibility.get(name, True)
        if force_visible is not None:
            visible = force_visible
        self.buffer_visibility[name] = visible

        if visible:
            self.public[name] = DecoderHandler.present_buffer(normalized)
        else:
            self.public.pop(name, None)

    def set_field(self, field: Any, value: Any, *, public_value: Optional[Any] = None) -> None:
        """Store a field value in state.

        Args:
            field (Any): Field node being stored.
            value (Any): Raw value.
            public_value (Any | None): Optional public representation.
        """
        name = getattr(field, "name", None)
        if not name or getattr(field, "ignore", False):
            return

        self.all[name] = value
        self._session.scope.set(name, value)

        if DecoderHandler.is_visible(field):
            self.public[name] = public_value if public_value is not None else value
        else:
            self.public.pop(name, None)
class DecoderHandler:
    """Core DSL decoder dispatcher."""

    @staticmethod
    def _trace_field_state(field: Any) -> None:
        Logger.trace(
            f"{getattr(field, 'name', None)} fmt={getattr(field, 'format', None)} value={getattr(field, 'value', None)}",
            scope="dsl",
        )

    @staticmethod
    def is_visible(field: Any) -> bool:
        """Return True when a field should appear in public output."""
        return bool(getattr(field, "visible", True)) and not getattr(field, "ignore", False)

    @staticmethod
    def present_buffer(buffer_values: list[Any]) -> str:
        """Convert a buffer to a hex-like string for public output."""
        output: list[str] = []
        for value in buffer_values:
            if value is None:
                output.append("??")
            elif isinstance(value, int):
                output.append(f"{value & 0xFF:02X}")
            elif isinstance(value, (bytes, bytearray)) and len(value) > 0:
                output.append(f"{value[0] & 0xFF:02X}")
            else:
                try:
                    output.append(f"{int(value) & 0xFF:02X}")
                except Exception:
                    output.append("??")
        return "".join(output)

    @staticmethod
    def _process_field(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        """Process a single field node and advance decoding state.

        Routing order is strict: optional IO guard → VariableNode → interpreter
        dispatch (INTERPRETER_HANDLERS) → endian/dynamic/string handling →
        struct default. New interpreters must be added to the dispatch map.

        Args:
            field (Any): Node to decode.
            raw_data (bytes): Raw packet bytes.
            bitstate (BitState): Current bit/byte reader state.
            endian (str): Current endianness token.
            state (DecodeState): Decode state container.

        Returns:
            tuple[Any, bool, str]: (field, stored, endian).
        """
        scope = state.all
        if getattr(field, "optional", False) and getattr(field, "has_io", True):
            if bitstate.offset >= len(raw_data):
                field.value = None
                field.raw_offset = bitstate.offset
                field.raw_length = 0
                field.raw_data = b""
                state.set_field(field, None)
                field.processed = True
                DecoderHandler._trace_field_state(field)
                return field, True, endian

        if isinstance(field, VariableNode):
            return DecoderHandler._handle_variable_node(
                field, raw_data, bitstate, endian, state
            )

        handler_result = DecoderHandler._dispatch_interpreter(
            field, raw_data, bitstate, endian, state
        )
        if handler_result is not None:
            DecoderHandler._trace_field_state(handler_result[0])
            return handler_result

        if field.name == "endian":
            endian = "<" if field.format == "little" else ">"
            field.processed = True
            DecoderHandler._trace_field_state(field)
            return field, True, endian

        if field.interpreter == "dynamic":
            if not DecoderHandler._handle_dynamic(field, scope):
                DecoderHandler._trace_field_state(field)
                return field, True, endian

        if field.format == "S":
            field = resolve_string_format(field, raw_data, bitstate.offset)

        if field.format == "R":
            field = handle_read_rest(field, raw_data, bitstate)
            val = DecoderHandler.apply_modifiers(field)
            state.set_field(field, val)
            DecoderHandler._trace_field_state(field)
            return field, True, endian

        result = DecoderHandler._handle_struct_default(
            field, raw_data, bitstate, endian, state
        )
        DecoderHandler._trace_field_state(result[0])
        return result

    @staticmethod
    def _dispatch_interpreter(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> Optional[tuple[Any, bool, str]]:
        handler = INTERPRETER_HANDLERS.get(field.interpreter)
        if handler is None:
            return None
        return handler(field, raw_data, bitstate, endian, state)

    @staticmethod
    def _handle_variable_node(
        field: VariableNode,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        raw_expr = field.raw_value

        try:
            val = eval_expr(raw_expr, state.all, raw_data)
        except Exception as exc:
            Logger.error(
                f"Failed evaluating variable '{field.name}' = {raw_expr}: {exc}",
                scope="dsl",
            )
            val = None

        field.value = val
        state.set_field(field, val)
        field.processed = True

        return field, True, endian

    @staticmethod
    def _handle_slice(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        scope = state.all

        try:
            spec = field.slice_expr or ""
            parts = spec.split(":")

            if len(parts) not in (2, 3):
                raise ValueError(f"Invalid slice spec: {spec}")

            def eval_part(expression: str) -> Optional[int]:
                expression = expression.strip()
                if not expression:
                    return None
                return eval_expr(expression, scope, raw_data)

            start = eval_part(parts[0])
            end = eval_part(parts[1]) if len(parts) >= 2 else None
            step = eval_part(parts[2]) if len(parts) == 3 else None

            if start is not None and not isinstance(start, int):
                raise ValueError(f"start is not int: {start!r}")
            if end is not None and not isinstance(end, int):
                raise ValueError(f"end is not int: {end!r}")
            if step is not None and not isinstance(step, int):
                raise ValueError(f"step is not int: {step!r}")

            sl = slice(start, end, step)
            bytes_slice = raw_data[sl]

            field.value = bytes_slice
            field.raw_data = bytes_slice
            field.raw_length = len(bytes_slice)
            field.raw_offset = start or 0
            field.processed = True

            state.set_field(field, bytes_slice, public_value=bytes_slice.hex())

            if end is not None:
                bitstate.advance_to(end, 0)

            return field, True, endian

        except Exception as exc:
            Logger.error(f"slice failed: {exc}", scope="dsl")
            field.value = None
            field.processed = True
            return field, True, endian

    @staticmethod
    def _handle_print(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        expr = getattr(field, "print_expr", "") or ""
        level = getattr(field, "print_level", "") or "debug"
        parts = split_print_args(expr)
        values = []

        for part in parts:
            try:
                val = eval_expr(part, state.all, raw_data)
            except Exception:
                val = part
            values.append(str(val))

        msg = " ".join(values) if values else ""
        log_print_message(level, msg)
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_var(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        expr = getattr(field, "raw_value", None) or field.format

        if expr is None:
            field.value = None
            field.processed = True
            return field, True, endian

        expr = expr.strip()

        try:
            val = eval_expr(expr, state.all, raw_data)
        except Exception as exc:
            Logger.error(
                f"Failed evaluating expr for field '{field.name}' = {expr}: {exc}",
                scope="dsl",
            )
            val = None

        for mod in getattr(field, "modifiers", []) or []:
            func = modifiers_operation_mapping.get(mod)
            if func is not None:
                try:
                    val = func(val)
                except Exception:
                    pass

        field.value = val
        state.set_field(field, val)
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_buffer_alloc(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        field = DecoderHandler.handle_buffer_alloc(field, bitstate, state)
        return field, True, endian

    @staticmethod
    def _handle_buffer_io(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        field = DecoderHandler.handle_buffer_io(field, raw_data, bitstate, state)
        return field, True, endian

    @staticmethod
    def _handle_buffer_assign(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        field = DecoderHandler.handle_buffer_assign(field, raw_data, bitstate, state, endian)
        return field, True, endian

    @staticmethod
    def _handle_padding(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        if getattr(field, "value", 0) == 0:
            bitstate.align_to_byte()
        else:
            bitstate.offset += field.value
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_seek_match(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        bitstate.align_to_byte()
        pattern = getattr(field, "pattern", b"")
        start = bitstate.offset

        if not pattern:
            if not getattr(field, "optional", False):
                Logger.warning("seek next: empty pattern", scope="dsl")
                bitstate.advance_to(len(raw_data), 0)
            field.processed = True
            return field, True, endian

        idx = raw_data.find(pattern, start)
        if idx == -1:
            if not getattr(field, "optional", False):
                Logger.warning(
                    "seek next: pattern not found "
                    f"({getattr(field, 'pattern_desc', '')})",
                    scope="dsl",
                )
                bitstate.advance_to(len(raw_data), 0)
            field.processed = True
            return field, True, endian

        bitstate.advance_to(idx, 0)
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_seek(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        bitstate.offset = field.value
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_combine(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        mask_name = field.format
        mask = DecoderHandler.resolve_variable(mask_name, state.all)

        combined = combine_guid(
            target_name=field.name,
            mask=mask,
            values=state.all,
            result=state.all,
        )

        field.value = combined
        state.set_field(field, combined)
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_dynamic(field: Any, scope: dict[str, Any]) -> bool:
        expr = getattr(field, "depends_on", None) or field.format
        length = None

        if expr is not None:
            try:
                length = eval_expr(expr, scope)
            except Exception:
                length = None

        if length is None:
            length = DecoderHandler.resolve_variable(field.format, scope)

        if isinstance(length, (bytes, bytearray)):
            length = sum(bin(b).count("1") for b in length) * 4
        elif isinstance(length, dict):
            if isinstance(length.get("bitcount"), int):
                length = length["bitcount"] * 4
            else:
                hex_value = length.get("hex")
                if isinstance(hex_value, str):
                    try:
                        raw = bytes.fromhex(hex_value)
                    except ValueError:
                        raw = None
                    if raw is not None:
                        length = sum(bin(b).count("1") for b in raw) * 4
        elif isinstance(length, str):
            expr_name = getattr(field, "depends_on", None) or ""
            if "mask" in expr_name:
                try:
                    raw = bytes.fromhex(length)
                except ValueError:
                    raw = None
                if raw is not None:
                    length = sum(bin(b).count("1") for b in raw) * 4

        try:
            length = int(length)
        except Exception:
            length = None

        if length is None:
            Logger.warning(f"Failed to resolve dynamic field: {field.name}", scope="dsl")
            return False

        field.interpreter = "struct"
        field.format = f"{length}s"
        return True

    @staticmethod
    def _handle_bits(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        bits_required = 0
        for mod in getattr(field, "modifiers", []) or []:
            match = re.fullmatch(r"(\d+)([Bb])", mod)
            if match:
                bits_required += int(match.group(1))
        remaining_bits = (len(raw_data) - bitstate.offset) * 8 - bitstate.bit_pos

        if getattr(field, "optional", False) and bits_required > remaining_bits:
            field.value = None
            field.raw_offset = bitstate.offset
            field.raw_length = 0
            field.raw_data = b""
            state.set_field(field, None)
            field.processed = True
            return field, True, endian

        field = decode_bits_field(field, raw_data, bitstate)
        state.set_field(field, field.value)
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_bitmask(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        handle_bitmask(
            field,
            raw_data,
            bitstate,
            endian,
            state,
            process_field=DecoderHandler._process_field,
            state_factory=DecodeState,
        )
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_packed_guid(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        handle_packed_guid(field, raw_data, bitstate, state)
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_uncompress(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        handle_uncompress(
            field,
            raw_data,
            bitstate,
            endian,
            state,
            process_field=DecoderHandler._process_field,
            resolve_variable=DecoderHandler.resolve_variable,
        )
        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_append(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        field, _, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)
        value = DecoderHandler.apply_modifiers(field)

        prev = state.all.get(field.name)
        if prev is None:
            state.set_field(field, value)
        elif isinstance(prev, list):
            prev.append(value)
        else:
            state.set_field(field, [prev, value])

        field.processed = True
        return field, True, endian

    @staticmethod
    def _handle_struct_default(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        field, value, _ = DecoderHandler.decode_struct(field, raw_data, bitstate, endian)

        if getattr(field, "modifiers", None):
            value = DecoderHandler.apply_modifiers(field)

        field.value = value
        state.set_field(field, value)
        field.processed = True
        return field, True, endian

    @staticmethod
    def decode(case: tuple, silent: bool = False, warn: bool = True) -> dict[str, Any]:
        """Decode a case tuple into a public field dictionary.

        Args:
            case (tuple): (name, lines, raw_bytes, expected).
            silent (bool): Skip printing success output.

        Returns:
            dict[str, Any]: Decoded public fields.
        """
        session = get_session()
        fields = session.fields
        raw_data = case[2]

        bitstate = BitState()
        state = DecodeState(session=session)
        endian = "<"

        session.scope.global_vars.clear()
        session.scope.scope_stack.clear()
        session.silent = silent
        session.warn = warn

        if Logger.is_enabled("TRACE", scope="dsl"):
            Logger.trace("[RAW NODE TREE BEFORE DECODING]", scope="dsl")
            for idx, field in enumerate(session.fields, start=1):
                Logger.trace(
                    f"[{idx}] {field.__class__.__name__} name='{field.name}' interp='{field.interpreter}' fmt='{field.format}' ignore={field.ignore}",
                    scope="dsl",
                )
                Logger.trace(
                    "    " + ", ".join(
                        f"{k}={v!r}"
                        for k, v in field.__dict__.items()
                        if k not in ("children", "nodes")
                    ),
                    scope="dsl",
                )
                if hasattr(field, "children"):
                    Logger.trace("    CHILDREN:", scope="dsl")
                    for cidx, child in enumerate(field.children, start=1):
                        Logger.trace(
                            f"        [{cidx}] {child.__class__.__name__} name='{child.name}' fmt='{child.format}' interp='{child.interpreter}'",
                            scope="dsl",
                        )

        i = 0
        while i < len(fields):
            field = fields[i]

            if getattr(field, "processed", False):
                i += 1
                continue

            needs_io = getattr(field, "has_io", True)
            if field.name != "endian" and needs_io and bitstate.offset >= len(raw_data):
                if getattr(field, "optional", False):
                    field, _, endian = DecoderHandler._process_field(
                        field, raw_data, bitstate, endian, state
                    )
                    fields[i] = field
                    i += 1
                    continue
                if session.warn:
                    Logger.warning(
                        f"Ran out of raw data before field '{getattr(field, 'name', '?')}'",
                        scope="dsl",
                    )
                break
            
            field, _, endian = DecoderHandler._process_field(
                field, raw_data, bitstate, endian, state
            )

            fields[i] = field
            i += 1

        try:
            json_output = json.dumps(state.public, indent=4)
            if not silent and Logger.is_enabled("DEBUG", scope="dsl"):
                for line in json_output.splitlines():
                    Logger.debug(line, scope="dsl")
        except TypeError:
            Logger.error("FAILED RESULT (non-serializable type)", scope="dsl")

        if Logger.is_enabled("TRACE", scope="dsl"):
            Logger.trace("[FINAL STATE DUMP]", scope="dsl")
            if session.scope.global_vars:
                Logger.trace("Global Vars:", scope="dsl")
                for k, v in session.scope.global_vars.items():
                    Logger.trace(f"    {k} = {v}", scope="dsl")
            else:
                Logger.trace("Global Vars: (empty)", scope="dsl")

            if session.scope.scope_stack:
                Logger.trace("Local Scopes:", scope="dsl")
                for idx, frame in enumerate(session.scope.scope_stack):
                    Logger.trace(f"  Frame {idx}:", scope="dsl")
                    for k, v in frame.items():
                        Logger.trace(f"      {k} = {v}", scope="dsl")
            else:
                Logger.trace("Local Scopes: (empty)", scope="dsl")

            if state.public:
                Logger.trace("Result Fields:", scope="dsl")
                for k, v in state.public.items():
                    Logger.trace(f"    {k} = {v}", scope="dsl")
            else:
                Logger.trace("Result Fields: (empty)", scope="dsl")

            Logger.trace("===================================================", scope="dsl")

        if not silent:
            Logger.info(f"{case[0]} decoded ({len(state.public)} fields)", scope="dsl")

        session.silent = False
        session.warn = True

        return state.public

    


    @staticmethod
    def substitute_vars(expression: str, scope: dict[str, Any]) -> str:
        """Replace €variables in an expression with literal values.

        Args:
            expression (str): DSL expression string.
            scope (dict[str, Any]): Variable mapping.

        Returns:
            str: Expression with variables substituted.
        """
        def replace(match: re.Match[str]) -> str:
            variable = match.group(1)
            return str(scope.get(variable, 0))

        return re.sub(r"€([A-Za-z_]\w*)", replace, expression)
    
    @staticmethod
    def parse_slice_spec(spec: str) -> tuple[Optional[int], Optional[int], Optional[int]]:
        """Parse a slice specification like 'start:end:step'.

        Args:
            spec (str): Slice specification string.

        Returns:
            tuple[Optional[int], Optional[int], Optional[int]]: (start, end, step).
        """
        parts = spec.split(":")

        if len(parts) == 2:
            start, end = parts
            step = None
        elif len(parts) == 3:
            start, end, step = parts
        else:
            raise ValueError(f"Invalid slice spec: {spec}")

        def convert(value: str) -> Optional[int]:
            value = value.strip()
            return int(value) if value else None

        return convert(start), convert(end), convert(step)

    @staticmethod
    def apply_modifiers(field: Any) -> Any:
        """Apply decode modifiers to a field value.

        Args:
            field (Any): Field node with modifiers.

        Returns:
            Any: Modified value.
        """
        if not getattr(field, "modifiers", None):
            return field.value

        value = field.raw_data

        for modifier in field.modifiers:
            func = modifiers_operation_mapping.get(modifier)
            if not func:
                continue
            if modifier == "E":
                value = func(value, field.format)
            else:
                value = func(value)

        return value

    @staticmethod
    def decode_struct(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
    ) -> tuple[Any, Any, str]:
        """Decode a struct field using the current endianness.

        Args:
            field (Any): Field node to decode.
            raw_data (bytes): Raw packet bytes.
            bitstate (BitState): Current bit/byte reader state.
            endian (str): Endianness token.

        Returns:
            tuple[Any, Any, str]: (field, value, endian).
        """
        bitstate.align_to_byte()
        fmt = field.format
        start = bitstate.offset

        try:
            size = struct.calcsize(f"{endian}{fmt}")
            if getattr(field, "optional", False) and start + size > len(raw_data):
                field.value = None
                field.raw_offset = start
                field.raw_length = 0
                field.raw_data = b""
                return field, None, endian

            if 's' not in fmt:
                # Normal struct unpack
                value = struct.unpack_from(f"{endian}{fmt}", raw_data, start)

                # NEW: unwrap single-value tuple → return pure scalar
                if isinstance(value, tuple) and len(value) == 1:
                    value = value[0]

            else:
                # String format → unpack gives bytes as value[0]
                value = struct.unpack_from(f"{endian}{fmt}", raw_data, start)[0]

        except struct.error as e:
            session = get_session()
            if getattr(session, "warn", True) and not getattr(session, "silent", False):
                Logger.warning("Struct unpack error", scope="dsl")
            Logger.trace(f"fmt={fmt} error={e}", scope="dsl")
            field.value = None
            field.raw_offset = start
            field.raw_length = 0
            field.raw_data = b""
            return field, None, endian

        # Convert bytes → string/hex
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                value = value.hex()

        field.value = value
        field.raw_offset = start
        field.raw_length = size
        field.raw_data = raw_data[start:start + size]

        bitstate.advance_to(start + size, 0)
        return field, value, size

    @staticmethod
    def resolve_variable(key: str, result: dict[str, Any]) -> Any:
        """Resolve a DSL variable through DecoderExpressions."""
        return resolve_variable(key, result)
    
    @staticmethod
    def _resolve_length_expr(expression: str | None, scope: dict[str, Any]) -> Optional[int]:
        """Resolve a buffer length expression to an integer."""
        return resolve_length_expression(
            expression, scope, resolve_variable=DecoderHandler.resolve_variable
        )

    @staticmethod
    def handle_buffer_alloc(field: Any, bitstate: BitState, state: DecodeState) -> Any:
        """Allocate a buffer node via DecoderBufferHandlers."""
        return handle_buffer_allocation(
            field,
            bitstate,
            state,
            resolve_variable=DecoderHandler.resolve_variable,
            present_buffer=DecoderHandler.present_buffer,
        )

    @staticmethod
    def handle_buffer_io(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        state: DecodeState,
    ) -> Any:
        """Read a buffer slice via DecoderBufferHandlers."""
        return handle_buffer_io(
            field,
            raw_data,
            bitstate,
            state,
            resolve_variable=DecoderHandler.resolve_variable,
        )

    @staticmethod
    def handle_buffer_assign(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        state: DecodeState,
        endian: str = "<",
    ) -> Any:
        """Assign bytes into a buffer via DecoderBufferHandlers."""
        return handle_buffer_assign(
            field,
            raw_data,
            bitstate,
            state,
            resolve_variable=DecoderHandler.resolve_variable,
        )
    
    @staticmethod
    def handle_loop(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        """Handle loop nodes via DecoderLoopHandler."""
        return handle_loop_block(
            field,
            raw_data,
            bitstate,
            endian,
            state,
            process_field=DecoderHandler._process_field,
            resolve_variable=DecoderHandler.resolve_variable,
            state_factory=DecodeState,
        )

    @staticmethod
    def handle_if(
        field: Any,
        raw_data: bytes,
        bitstate: BitState,
        endian: str,
        state: DecodeState,
    ) -> tuple[Any, bool, str]:
        """Handle if/elif/else nodes via DecoderIfHandler."""
        return handle_if_block(
            field,
            raw_data,
            bitstate,
            endian,
            state,
            process_field=DecoderHandler._process_field,
        )


INTERPRETER_HANDLERS: dict[
    str,
    Callable[[Any, bytes, BitState, str, DecodeState], tuple[Any, bool, str]],
] = {
    "slice": DecoderHandler._handle_slice,
    "print": DecoderHandler._handle_print,
    "var": DecoderHandler._handle_var,
    "buffer_alloc": DecoderHandler._handle_buffer_alloc,
    "buffer_io": DecoderHandler._handle_buffer_io,
    "buffer_assign": DecoderHandler._handle_buffer_assign,
    "padding": DecoderHandler._handle_padding,
    "seek_match": DecoderHandler._handle_seek_match,
    "seek": DecoderHandler._handle_seek,
    "combine": DecoderHandler._handle_combine,
    "bits": DecoderHandler._handle_bits,
    "loop": DecoderHandler.handle_loop,
    "bitmask": DecoderHandler._handle_bitmask,
    "if": DecoderHandler.handle_if,
    "packed_guid": DecoderHandler._handle_packed_guid,
    "uncompress": DecoderHandler._handle_uncompress,
    "append": DecoderHandler._handle_append,
}
