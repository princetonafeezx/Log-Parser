"""Tests for primary stdout serialization."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


def _load_formatter_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("dataguard_formatter_under_test", root / "formatter.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_f = _load_formatter_module()
serialize_primary_output = _f.serialize_primary_output


class SerializePrimaryOutputTests(unittest.TestCase):
    def test_text_dict_is_indented_json(self) -> None:
        out = serialize_primary_output({"a": 1}, "text")
        self.assertIn("\n", out)
        self.assertEqual(json.loads(out), {"a": 1})

    def test_raw_dict_is_compact_json(self) -> None:
        out = serialize_primary_output({"a": 1, "b": [2, 3]}, "raw")
        self.assertNotIn("\n", out)
        self.assertEqual(json.loads(out), {"a": 1, "b": [2, 3]})

    def test_raw_string_is_plain_str(self) -> None:
        self.assertEqual(serialize_primary_output("hello", "raw"), "hello")

    def test_json_encodes_string_as_json(self) -> None:
        self.assertEqual(serialize_primary_output("hello", "json"), '"hello"')
