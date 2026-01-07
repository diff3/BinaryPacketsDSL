#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for Processor helpers."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from modules.dsl import Processor


class ProcessorTest(unittest.TestCase):
    """Tests for Processor module helpers."""

    def test_process_case_loads_payload_and_json(self) -> None:
        """Loads payload, expected JSON, and debug JSON when present."""
        def fake_exists(path: str) -> bool:
            return path.endswith("debug/CASE.json") or path.endswith("json/CASE.json")

        def fake_load_json(path: str) -> dict[str, Any]:
            if path.endswith("debug/CASE.json"):
                return {"debug": True}
            return {"expected": 1}

        with patch.object(Processor, "_build_base_path", return_value="root"), \
            patch.object(Processor.os.path, "exists", side_effect=fake_exists), \
            patch.object(Processor.FileHandler, "load_file", return_value=["line"]), \
            patch.object(Processor.FileHandler, "load_payload", return_value=b"\x01"), \
            patch.object(Processor.FileHandler, "load_json_file", side_effect=fake_load_json):
            success, definition, payload, expected, debug = Processor.process_case(
                "prog",
                "1",
                "CASE",
                expansion="exp",
            )

        self.assertTrue(success)
        self.assertEqual(definition, ["line"])
        self.assertEqual(payload, b"\x01")
        self.assertEqual(expected, {"expected": 1})
        self.assertEqual(debug, {"debug": True})

    def test_process_case_missing_payload_with_expected(self) -> None:
        """Fails when payload is missing but expected JSON exists."""
        def fake_exists(path: str) -> bool:
            return path.endswith("json/CASE.json")

        with patch.object(Processor, "_build_base_path", return_value="root"), \
            patch.object(Processor.os.path, "exists", side_effect=fake_exists), \
            patch.object(Processor.FileHandler, "load_file", return_value=["line"]), \
            patch.object(Processor.FileHandler, "load_payload", side_effect=FileNotFoundError), \
            patch.object(Processor.FileHandler, "load_json_file", return_value={"expected": 1}):
            success, _, payload, expected, _ = Processor.process_case(
                "prog",
                "1",
                "CASE",
            )

        self.assertFalse(success)
        self.assertEqual(payload, b"")
        self.assertIsNone(expected)

    def test_process_case_missing_payload_without_expected(self) -> None:
        """Keeps empty payload when both payload and JSON are missing."""
        with patch.object(Processor, "_build_base_path", return_value="root"), \
            patch.object(Processor.os.path, "exists", return_value=False), \
            patch.object(Processor.FileHandler, "load_file", return_value=["line"]), \
            patch.object(Processor.FileHandler, "load_payload", side_effect=FileNotFoundError):
            success, _, payload, expected, _ = Processor.process_case(
                "prog",
                "1",
                "CASE",
            )

        self.assertTrue(success)
        self.assertEqual(payload, b"")
        self.assertEqual(expected, {})

    def test_process_case_without_payload(self) -> None:
        """Skips payload loading when require_payload is False."""
        with patch.object(Processor, "_build_base_path", return_value="root"), \
            patch.object(Processor.FileHandler, "load_file", return_value=["line"]), \
            patch.object(Processor.FileHandler, "load_payload", side_effect=AssertionError):
            success, _, payload, expected, _ = Processor.process_case(
                "prog",
                "1",
                "CASE",
                require_payload=False,
            )

        self.assertTrue(success)
        self.assertEqual(payload, b"")
        self.assertEqual(expected, {})

    def test_load_case_raises_when_missing(self) -> None:
        """Raises when the case could not be loaded."""
        with patch.object(Processor, "process_case", return_value=(False, [], b"", None, None)):
            with self.assertRaises(FileNotFoundError):
                Processor.load_case("prog", "1", "CASE")

    def test_load_all_cases_returns_empty(self) -> None:
        """Returns empty list when no cases are found."""
        with patch.object(Processor.FileHandler, "list_def_files", return_value=[]):
            result = Processor.load_all_cases("prog", "1")
        self.assertEqual(result, [])

    def test_load_all_cases_filters_opcodes(self) -> None:
        """Skips cases filtered out by the opcode filter."""
        def fake_process_case(*args, **kwargs):
            return True, ["line"], b"\x01", {}, {}

        with patch.object(Processor.FileHandler, "list_def_files", return_value=["A", "B"]), \
            patch.object(Processor, "process_case", side_effect=fake_process_case), \
            patch.object(Processor, "filter_opcode", side_effect=[True, False]):
            result = Processor.load_all_cases("prog", "1")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], "A")

    def test_handle_add_creates_files(self) -> None:
        """Creates new def/json/debug files for a case."""
        base_dir = Path(__file__).resolve().parent / "tmp_processor"
        base_dir.mkdir(parents=True, exist_ok=True)

        def cleanup() -> None:
            for root, _, files in os.walk(base_dir, topdown=False):
                for fname in files:
                    os.remove(Path(root) / fname)
            for root, dirs, _ in os.walk(base_dir, topdown=False):
                for dname in dirs:
                    os.rmdir(Path(root) / dname)
            if base_dir.exists():
                os.rmdir(base_dir)

        self.addCleanup(cleanup)

        with patch.object(Processor, "_build_base_path", return_value=str(base_dir)):
            result = Processor.handle_add("prog", "1", "CASE", "b'\\x01\\x02'")

        self.assertTrue(result)

        def_path = base_dir / "def" / "CASE.def"
        json_path = base_dir / "json" / "CASE.json"
        debug_path = base_dir / "debug" / "CASE.json"

        self.assertTrue(def_path.exists())
        self.assertTrue(json_path.exists())
        self.assertTrue(debug_path.exists())

        debug_data = json.loads(debug_path.read_text(encoding="utf-8"))
        self.assertEqual(debug_data.get("hex_compact"), "0102")
        self.assertEqual(debug_data.get("hex_spaced"), "01 02")


if __name__ == "__main__":
    unittest.main()
