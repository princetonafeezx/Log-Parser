"""Tests for log parsing, validation helpers, and run() behavior."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _load_log_parser_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("log_parser_under_test", root / "log_parser.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_lp = _load_log_parser_module()
normalize_client_ip = _lp.normalize_client_ip
valid_ip = _lp.valid_ip
parse_response_size = _lp.parse_response_size
parse_line = _lp.parse_line
run = _lp.run


class NormalizeClientIpTests(unittest.TestCase):
    def test_strips_ipv6_brackets(self) -> None:
        self.assertEqual(normalize_client_ip("[2001:db8::1]"), "2001:db8::1")

    def test_passes_plain_ipv4(self) -> None:
        self.assertEqual(normalize_client_ip(" 192.168.0.1 "), "192.168.0.1")


class ValidIpTests(unittest.TestCase):
    def test_ipv4(self) -> None:
        self.assertTrue(valid_ip("192.168.0.1"))

    def test_ipv6(self) -> None:
        self.assertTrue(valid_ip("::1"))
        self.assertTrue(valid_ip("2001:db8::1"))

    def test_invalid(self) -> None:
        self.assertFalse(valid_ip("999.999.999.999"))
        self.assertFalse(valid_ip("not-an-ip"))


class ParseResponseSizeTests(unittest.TestCase):
    def test_dash_is_zero(self) -> None:
        self.assertEqual(parse_response_size("-"), (0, True))

    def test_positive_int(self) -> None:
        self.assertEqual(parse_response_size("1024"), (1024, True))

    def test_negative_invalid(self) -> None:
        self.assertEqual(parse_response_size("-3"), (0, False))

    def test_non_numeric_invalid(self) -> None:
        self.assertEqual(parse_response_size("abc"), (0, False))


class ParseLineTests(unittest.TestCase):
    def test_apache_combined_sample(self) -> None:
        line = (
            '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] '
            '"GET /apache_pb.gif HTTP/1.0" 200 2326'
        )
        data = parse_line(line, "apache")
        assert data is not None
        self.assertEqual(data["ip"], "127.0.0.1")
        self.assertEqual(data["method"], "GET")
        self.assertEqual(data["url"], "/apache_pb.gif")
        self.assertEqual(data["status"], "200")
        self.assertEqual(data["size"], "2326")


class RunDedupeAndThreatTests(unittest.TestCase):
    def test_rapid_fire_alert_once_per_ip(self) -> None:
        base = '1.1.1.1 - - [01/Jan/2024:12:00:{sec:02d} +0000] "GET /x HTTP/1.0" 200 0\n'
        lines = "".join(base.format(sec=i % 60) for i in range(55))
        result = run(lines, {"format": "apache", "top": 5})
        rapid = [f for f in result["findings"] if f.get("category") == "rapid_fire"]
        self.assertEqual(len(rapid), 1)

    def test_brute_force_alert_once_per_ip(self) -> None:
        base = (
            '9.9.9.9 - - [01/Jan/2024:12:00:{sec:02d} +0000] '
            '"POST /login HTTP/1.0" 401 0\n'
        )
        lines = "".join(base.format(sec=i % 60) for i in range(15))
        result = run(lines, {"format": "apache", "top": 5})
        brute = [f for f in result["findings"] if f.get("category") == "brute_force"]
        self.assertEqual(len(brute), 1)

    def test_malformed_response_size_does_not_crash(self) -> None:
        line = '127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.0" 200 not-a-size\n'
        result = run(line, {"format": "apache"})
        self.assertEqual(len(result["entries"]), 1)
        bad = [f for f in result["findings"] if f.get("category") == "malformed_response_size"]
        self.assertEqual(len(bad), 1)


class MainCliTests(unittest.TestCase):
    def test_main_export_writes_json(self) -> None:
        import tempfile

        log_line = (
            '127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.0" 200 10\n'
        )
        mod = _lp
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".log") as log_f:
            log_f.write(log_line)
            log_path = log_f.name
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".json") as out_f:
            out_path = out_f.name
        try:
            argv = ["--file", log_path, "--export", out_path, "--progress-every", "0", "--format", "apache"]
            code = mod.main(argv)
            self.assertEqual(code, 0)
            payload = json.loads(Path(out_path).read_text(encoding="utf-8"))
            self.assertEqual(payload["stats"]["parsed_lines"], 1)
        finally:
            Path(log_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

    def test_main_raises_input_error_for_missing_file(self) -> None:
        import errors as errors_mod

        mod = _lp
        missing = _ROOT / "___missing_log_for_test__.log"
        with self.assertRaises(errors_mod.InputError):
            mod.main(["--file", str(missing), "--progress-every", "0"])


if __name__ == "__main__":
    unittest.main()
