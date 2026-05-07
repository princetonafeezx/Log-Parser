# Architecture Decision Record
## App 05 — Log Parser
**DataGuard Group | Document 1 of 5**
**Status: Accepted**

---

## Context

DataGuard processes server log files as part of its data ingestion pipeline. Apache and Nginx access logs are the most common format — each line records a request's IP, timestamp, method, URL, status code, response size, referer, and user agent. These files can be large (millions of lines), contain lines in multiple formats, and carry signals about both traffic patterns and security incidents. The Log Parser is the fifth module in the DataGuard group, responsible for parsing structured entries, computing traffic statistics, and flagging security-relevant patterns for operator review.

---

## Decisions

### Decision 1 — Format auto-detection from the first 5 lines

**Chosen:** `detect_format()` applies all three patterns (`APACHE_PATTERN`, `NGINX_PATTERN`, `GENERIC_PATTERN`) to the first 5 lines and returns the format that matches the most. Callers can override with `config["format"]` or `--format`.

**Rejected:** Requiring callers to always specify the format.

**Reason:** Log files frequently arrive without documentation of which server generated them, and Apache and Nginx formats are nearly identical. Auto-detection from a small sample is reliable for the common case and eliminates a common operator error. The manual override is available for edge cases.

---

### Decision 2 — Three regex patterns (Apache, Nginx, Generic)

**Chosen:** Three pre-compiled patterns. Apache and Nginx patterns are high-specificity — they require a full Combined Log Format structure. The generic pattern is a looser fallback that extracts IPv4, method, URL, status, and size from any line containing them.

**Rejected:** A single universal pattern.

**Reason:** A single pattern that handles all three formats would either be too strict (missing non-standard lines) or too loose (producing false positives). The three-tier approach gives high accuracy on known formats and best-effort parsing on unknown ones. The `detect_format()` function measures which tier works best.

---

### Decision 3 — Single-pass line processing with deduplication sets for threat alerts

**Chosen:** One `for` loop over all lines. Threat alert deduplication uses `rapid_fire_alerted: set[str]` and `brute_force_alerted: set[str]` — once an IP triggers an alert, it is added to the set and no further alerts are generated for it regardless of how many subsequent lines would re-trigger.

**Rejected:** Post-processing analysis over parsed entries, or alerting on every triggering line.

**Reason:** Single-pass is efficient for large files. Alert-per-line for high-frequency IPs would produce hundreds of identical findings that bury the signal. One alert per IP per threat type is the correct operator-oriented behavior — the test `test_rapid_fire_alert_once_per_ip` and `test_brute_force_alert_once_per_ip` enforce this explicitly.

---

### Decision 4 — Sliding 60-second time window for rate-based threats

**Chosen:** `window_by_ip` and `login_windows` use `defaultdict(list)` storing timestamps per IP. After each append, timestamps older than 60 seconds are pruned. Thresholds: 50+ requests/IP/60s → `rapid_fire`; 10+ login requests/IP/60s → `brute_force`.

**Rejected:** Total count per IP across the entire file.

**Reason:** A total count across the whole file would flag legitimate high-traffic IPs that simply generated a lot of traffic over hours. The sliding window targets concentrated bursts — the behavior pattern of DoS and brute force attacks. The pruning step (`[item for item in recent if item >= cutoff]`) is the correct list-based window implementation.

---

### Decision 5 — `formatter.py` as shared DataGuard output module

**Chosen:** `format_table()` imported from `formatter.py` (Amendment 3.2 exempt module). The CLI uses `render_report_text()`, `render_report()`, and `stream_supports_color()` from the same module.

**Rejected:** Defining table and report formatting directly in `log_parser.py`.

**Reason:** By App 05 the DataGuard group has accumulated several modules that all need the same table rendering, ANSI color, and report generation behavior. `formatter.py` centralizes this and ensures consistency. It was ratified as an Amendment 3.2 exempt module during the evaluation.

---

### Decision 6 — `entries` list in result alongside `output` text

**Chosen:** `result["entries"]` contains all successfully parsed log entries as structured dicts. `result["output"]` contains the pre-formatted human-readable summary text.

**Rejected:** Only returning the text summary.

**Reason:** Callers that want to do their own analysis (e.g., the DataGuard bootstrapper building a cross-module daily report) need structured data, not rendered text. Providing both means the module works as a CLI tool and as a programmatic data source without requiring callers to re-parse the output text.

---

### Decision 7 — Parse failures capped at 20 in findings

**Chosen:** At most 20 `"parse_failure"` findings are added to the result. The count of total parse failures appears in `stats["unparseable_lines"]`.

**Rejected:** Adding a finding for every unparseable line.

**Reason:** Large log files with a format mismatch can produce thousands of parse failures. Including all of them would create a findings list that is unusable for review. The total count in stats preserves the full picture; the 20-entry cap keeps findings readable.

---

## Consequences

**Positive:**
- Single-pass with deduplication sets handles large files efficiently.
- Sliding window detection catches burst behavior without flagging legitimate high-volume traffic.
- Three-tier format support handles the most common real-world log formats.
- Structured `entries` list makes the result useful as a data source, not just a report.
- `formatter.py` shared module prevents drift across DataGuard report formats.

**Negative / Trade-offs:**
- The module docstring is explicit: threat findings are heuristic triage, not security validation. SQL injection patterns in URLs and path traversal signatures will produce false positives on legitimate test traffic.
- The time-window pruning loop (`[item for item in recent if item >= cutoff]`) creates a new list on every request from that IP. For extremely high-volume IPs this is O(n) per line. A `deque`-based sliding window would be more efficient.
- Parse failures for unrecognized log formats can produce a large `stats["unparseable_lines"]` count without explanation of what format was expected. The `--format` flag is the mitigation.

---

*Constitution reference: Articles 1, 2, 3. Amendment 3.2: `formatter.py` is a shared formatting module exempt from line limit.*


---


# Technical Design Document
## App 05 — Log Parser
**DataGuard Group | Document 2 of 5**

---

## Overview

Log Parser reads Apache/Nginx-style server log text, parses each line into structured entries, computes traffic statistics, and runs a security triage scan. It outputs both a human-readable summary and a structured result dict.

**File:** `log_parser.py` (483 lines), `formatter.py` (shared, Amendment 3.2)
**Entry points:** `run()` (public API), `main()` (CLI)
**Dependencies:** `re`, `ipaddress`, `sys`, `collections.Counter`, `collections.defaultdict`, `datetime` (stdlib); `formatter.format_table` (DataGuard shared)

---

## Data Flow

```
Input log text (str)
        │
        ▼
splitlines()  →  list[str]
        │
        ├─ detect_format(lines[:5])  →  log_format: str
        │
        └─ FOR EACH LINE:
               ├─ parse_line(line, log_format)     → entry dict | None
               │      (None → parse_failures list)
               ├─ normalize_client_ip()
               ├─ parse_response_size()
               ├─ parse_timestamp()
               ├─ Security checks (IP, method, status, URL patterns, agent)
               ├─ Counter updates (status, ip, url, error_ip, error_url)
               └─ Sliding window checks (rapid_fire, brute_force)
        │
        ▼
stats calculation
        │
        ▼
render_output_summary()  →  output_text: str
        │
        ▼
Standard DataGuard result dict
  + entries: list[dict]
```

---

## Module-Level Constants

### Compiled Regex Patterns

| Name | Format | Key Groups |
|---|---|---|
| `APACHE_PATTERN` | Apache Combined Log | ip, timestamp, method, url, status, size, referer, agent |
| `NGINX_PATTERN` | Nginx access log | ip, timestamp, method, url, status, size, referer, agent |
| `GENERIC_PATTERN` | Fallback (IPv4 only) | ip, method, url, status, size |

### Security Patterns

| Name | What it detects |
|---|---|
| `PATH_TRAVERSAL_PATTERN` | `../`, `..%2f`, `/etc/passwd`, `/proc/self` |
| `SQLI_PATTERN` | `union select`, `or 1=1`, `drop table`, `--` |
| `LOGIN_PATH_PATTERN` | `/login`, `/auth`, `/signin`, `/wp-login` |

### Sets and Collections

| Name | Type | Content |
|---|---|---|
| `HTTP_METHODS` | `set[str]` | Standard HTTP verbs |
| `SCANNER_SIGNATURES` | `set[str]` | Lowercase tool names (nikto, sqlmap, etc.) |

---

## Function Reference

### `parse_timestamp(raw_timestamp: str) -> datetime | None`
Tries three format strings in order:
1. `"%d/%b/%Y:%H:%M:%S %z"` — Apache/Nginx Combined Log Format
2. `"%Y-%m-%dT%H:%M:%S"` — ISO 8601
3. `"%Y-%m-%d %H:%M:%S"` — Common database-style log format

Strips timezone info after parsing (makes arithmetic comparisons simpler). Returns `None` on all-format failure.

---

### `normalize_client_ip(raw_ip: str) -> str`
Strips whitespace. If the result is surrounded by `[` and `]` (IPv6 bracket notation from some log formats), removes the brackets.

---

### `valid_ip(ip_address: str) -> bool`
Delegates to `ipaddress.ip_address()`. Returns `True` for any syntactically valid IPv4 or IPv6 address. Returns `False` on `ValueError`.

---

### `parse_response_size(size_field: str) -> tuple[int, bool]`
- `"-"` → `(0, True)` — conventional "no body" representation
- Valid non-negative integer → `(int(value), True)`
- Negative integer → `(0, False)`
- Non-numeric → `(0, False)`

Returns `(value, is_valid)`.

---

### `detect_format(lines: list[str]) -> str`
Counts matches for each of the three patterns against the provided lines. Returns `"apache"`, `"nginx"`, or `"generic"` based on which matched the most. Tie between Apache and generic defaults to `"apache"`.

---

### `parse_line(line: str, log_format: str) -> dict | None`
Looks up the pattern for `log_format`. Returns `None` if no match. Sets default `"-"` for optional `referer` and `agent` fields that may not be captured by the generic pattern.

---

### `add_threat(findings, line_number, category, severity, ip_address, message)`
Appends a finding with the standard finding schema plus an `"ip"` field:
```python
{"severity": str, "category": str, "line": int, "ip": str, "message": str}
```

---

### `render_output_summary(stats, top_ips, top_error_ips, top_urls, top_error_urls, findings, top_n, threats_only) -> str`
Builds the human-readable output text. If `threats_only=True`, only the threat table is included. Otherwise, adds the overview stats and four top-N tables (top IPs, top error IPs, top URLs, top error URLs). Uses `format_table()` from `formatter.py` for all table rendering.

---

### `run(input_text: str, config: dict | None = None) -> dict`
Main engine. Config keys:

| Key | Type | Default | Description |
|---|---|---|---|
| `format` | `str` | `"auto"` | `"auto"`, `"apache"`, `"nginx"`, `"generic"` |
| `top` | `int` | `10` | Number of top IPs/URLs to include |
| `threats_only` | `bool` | `False` | Include only threat section in output |
| `source_name` | `str` | `"<input>"` | Label for metadata |
| `progress_every` | `int` | `0` | Progress report interval (0 = disabled) |
| `progress_stream` | `TextIO` | `None` | Stream for progress messages |

Returns result dict with additional `"entries"` key (all parsed log entries as dicts).

---

### `main(argv: list[str] | None = None) -> int`
CLI entry. Deferred imports (`argparse`, `Path`, `errors`, `formatter`) keep module import cost low. Raises `InputError` on file read failure rather than printing and returning — the outer `if __name__ == "__main__"` block catches it.

Flags: `--file`, `--format`, `--top`, `--threats-only`, `--export`, `--progress-every`.

---

## Threat Alert Categories

| Category | Severity | Trigger |
|---|---|---|
| `rapid_fire` | high | 50+ requests from one IP in 60 seconds |
| `brute_force` | high | 10+ requests to login paths from one IP in 60 seconds |
| `path_traversal` | high | URL matches `PATH_TRAVERSAL_PATTERN` |
| `sql_injection_probe` | high | URL matches `SQLI_PATTERN` |
| `scanner_fingerprint` | medium | User agent contains a known scanner name |
| `invalid_ip` | medium | IP fails `ipaddress.ip_address()` validation |
| `invalid_method` | medium | Method not in `HTTP_METHODS` |
| `invalid_status` | medium | Status code outside 100–599 |
| `malformed_status` | medium | Status field is not parseable as integer |
| `malformed_response_size` | low | Size field is not a non-negative integer or `-` |
| `parse_failure` | low | Line did not match the format pattern |

---

## Stats Schema

```python
{
    "format": str,              # Detected or forced format
    "total_lines": int,
    "parsed_lines": int,
    "unparseable_lines": int,
    "parse_rate": str,          # "XX.X%"
    "error_rate": str,          # "XX.X%" (4xx + 5xx / parsed_lines)
    "2xx": int,
    "3xx": int,
    "4xx": int,
    "5xx": int,
    "other_status": int,
}
```

---

## Entry Schema

Each item in `result["entries"]`:
```python
{
    "line": int,
    "ip": str,
    "timestamp": str,       # ISO format or "" if parsing failed
    "method": str,
    "url": str,
    "status": int,
    "response_size": int,
    "agent": str,
}
```


---


# Interface Design Specification
## App 05 — Log Parser
**DataGuard Group | Document 3 of 5**

---

## Public API

### Primary Entry Point

```python
run(input_text: str, config: dict | None = None) -> dict
```

**Config keys:**

| Key | Type | Default | Description |
|---|---|---|---|
| `format` | `str` | `"auto"` | `"auto"`, `"apache"`, `"nginx"`, `"generic"` |
| `top` | `int` | `10` | Top-N count for IP/URL tables |
| `threats_only` | `bool` | `False` | Limit output to threat section only |
| `source_name` | `str` | `"<input>"` | Label for metadata |
| `progress_every` | `int` | `0` | Lines between progress messages (0 = off) |
| `progress_stream` | `TextIO\|None` | `None` | Where to write progress messages |

---

### CLI

```bash
# Basic analysis with auto-format detection
python log_parser.py --file access.log

# Force Apache format
python log_parser.py --file access.log --format apache

# Top 20 IPs and URLs
python log_parser.py --file access.log --top 20

# Security threats only
python log_parser.py --file access.log --threats-only

# Export full result as JSON
python log_parser.py --file access.log --export analysis.json

# Progress reporting every 5000 lines
python log_parser.py --file access.log --progress-every 5000

# Module invocation
python -m log_parser --file access.log
```

Exit codes: `0` success, `2` `InputError` (file not found or not UTF-8).

---

## Result Envelope

```python
{
    "module_name": "logs",
    "title": "DataGuard Log Analysis Report",
    "output": str,          # Human-readable summary (tables)
    "entries": list[dict],  # Parsed log entries
    "findings": list[dict], # Threat alerts + parse failures
    "warnings": list[str],  # Empty or ["N lines could not be parsed."]
    "errors": [],
    "stats": dict,
    "metadata": {"source": str, "format": str, "top": int},
    "summary": str,
}
```

---

## Input/Output Examples

### Typical Apache log line
```
127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
```
Parsed entry:
```python
{
    "line": 1,
    "ip": "127.0.0.1",
    "timestamp": "2000-10-10T13:55:36",
    "method": "GET",
    "url": "/apache_pb.gif",
    "status": 200,
    "response_size": 2326,
    "agent": "-"
}
```

### Rapid fire detection
```python
# 55 lines from 1.1.1.1 within 60 seconds
result = run(log_text, {"format": "apache"})
rapid = [f for f in result["findings"] if f["category"] == "rapid_fire"]
# len(rapid) == 1  — one alert per IP, regardless of count
```

### Brute force detection
```python
# 15 POST /login lines from 9.9.9.9 within 60 seconds
brute = [f for f in result["findings"] if f["category"] == "brute_force"]
# len(brute) == 1
```

### Malformed response size
```python
line = '127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.0" 200 not-a-size'
result = run(line, {"format": "apache"})
# result["entries"]: 1 entry (line still parsed)
# findings: [{"category": "malformed_response_size", "severity": "low", ...}]
```

### Threats-only mode
```python
result = run(log_text, {"threats_only": True})
# result["output"] contains only the threat table (or "No threats detected.")
# stats and top tables are computed but not rendered in output
```

### JSON export via CLI
```bash
python log_parser.py --file access.log --export report.json
# report.json contains the full result dict as indented JSON
```

---

## Output Text Format

The `result["output"]` text contains (in order, unless `threats_only=True`):

```
Threat Alerts
Severity  Category  IP        Message
--------  --------  --------  -------
high      rapid_fire  1.1.1.1  50+ requests from the same IP inside 60 seconds.

Overview
Requests parsed: 10000/10000 (100.0%)
Error rate: 2.3%

Top IPs
IP          Requests
----------  --------
192.168.1.1  4200
...

Top error IPs (4xx/5xx)
...

Top URLs
...

Top error URLs (4xx/5xx)
...
```

---

## Formatter Module Interface

`log_parser.py` imports from `formatter.py`:

```python
from formatter import format_table                          # render_output_summary
from formatter import render_report, render_report_text    # main() CLI output
from formatter import stream_supports_color                # color detection
```

`formatter.py` provides three output formats via `render_report(result, report_format)`:
- `"text"` — Human-readable with ANSI color support
- `"json"` — Indented JSON of the full result dict
- `"csv"` — Findings as CSV rows


---


# Runbook
## App 05 — Log Parser
**DataGuard Group | Document 4 of 5**

---

## Requirements

- Python 3.10 or later
- No third-party dependencies — stdlib only
- `formatter.py` and `errors.py` must be in the same directory or on `PYTHONPATH`

---

## Installation

```bash
git clone https://github.com/PrincetonAfeez/Log-Parser
cd Log-Parser
```

Confirm `formatter.py` and `errors.py` are present. No `pip install` required.

---

## Running the CLI

### Basic analysis
```bash
python log_parser.py --file /var/log/nginx/access.log
```

### Force format
```bash
python log_parser.py --file access.log --format apache
python log_parser.py --file access.log --format nginx
python log_parser.py --file access.log --format generic
```

### Adjust top-N tables
```bash
python log_parser.py --file access.log --top 20
```

### Security threats only
```bash
python log_parser.py --file access.log --threats-only
```

### Export full analysis as JSON
```bash
python log_parser.py --file access.log --export report.json
```

### Progress reporting for large files
```bash
python log_parser.py --file large.log --progress-every 5000
# stderr: Processed 5000/100000 lines, parsed so far: 4998 (apache)
```

### Disable progress reporting
```bash
python log_parser.py --file access.log --progress-every 0
```

---

## Using as a Library

### Basic analysis
```python
from log_parser import run

with open("access.log", encoding="utf-8") as f:
    text = f.read()

result = run(text, {"format": "apache", "top": 10})
print(result["summary"])
print(result["output"])
```

### Inspect threat findings
```python
threats = [f for f in result["findings"] if f["category"] not in {"parse_failure"}]
high = [f for f in threats if f["severity"] == "high"]
print(f"{len(high)} high-severity alerts")
for alert in high:
    print(f"  [{alert['ip']}] {alert['message']}")
```

### Access structured entries
```python
# All 4xx/5xx entries
errors = [e for e in result["entries"] if e["status"] >= 400]
print(f"{len(errors)} error responses")
```

### Check parse rate
```python
stats = result["stats"]
if stats["unparseable_lines"] > 0:
    print(f"Warning: {stats['unparseable_lines']} lines could not be parsed.")
    print(f"Format: {stats['format']}")
    print("Try --format to specify the correct format manually.")
```

### With progress callback (library use)
```python
import sys

result = run(text, {
    "format": "auto",
    "top": 10,
    "progress_every": 1000,
    "progress_stream": sys.stderr,
})
```

---

## Running Tests

```bash
pip install pytest
pytest test_log_parser.py test_formatter_output.py -v
```

### Specific test groups
```bash
pytest test_log_parser.py -v -k "ip"
pytest test_log_parser.py -v -k "rapid_fire or brute_force"
pytest test_log_parser.py -v -k "parse"
```

---

## Troubleshooting

### All lines show as unparseable
Check `stats["format"]` in the result. If it says `"generic"` but the file is Apache format, the auto-detect sampled lines that didn't match. Use `--format apache` to override.

### No rapid_fire or brute_force alerts despite high traffic
These alerts require valid timestamps that can be parsed into `datetime` objects. If `parse_timestamp()` returns `None` for your log format, the sliding window cannot be computed. Check that timestamps follow Apache Combined Format (`dd/Mon/YYYY:HH:MM:SS ±HHMM`) or ISO 8601.

### Scanner fingerprint false positives
The scanner detection checks for known tool names as substrings in the User-Agent. User agents containing `"nmap"`, `"nikto"` etc. in their legitimate product names would be flagged. Add agent strings to a whitelist in your application layer if needed.

### `ModuleNotFoundError: No module named 'formatter'`
`formatter.py` must be in the same directory as `log_parser.py`. Set `PYTHONPATH` to the directory containing both files if they are in different locations.

### Export file not written
The `--export` path must be writable. The parent directory must exist — the module does not create intermediate directories for export.


---


# Lessons Learned
## App 05 — Log Parser
**DataGuard Group | Document 5 of 5**

---

## Why This Design Was Chosen

The deduplication sets for threat alerts (`rapid_fire_alerted`, `brute_force_alerted`) were the most deliberate design decision in this module. The first version fired an alert for every request that exceeded the threshold — which meant a single IP making 200 requests in 60 seconds would produce 150+ identical findings. The test `test_rapid_fire_alert_once_per_ip` was written to codify the correct behavior: one alert per IP, regardless of how many subsequent requests would re-trigger. The fix was a `set` that an IP is added to after its first alert. This pattern — alert once, deduplicate by key — is reusable in any detection system.

The sliding window cleanup (`[item for item in recent if item >= cutoff]`) came from thinking about what happens to the tracking dict over a long-running analysis. Without pruning, every IP that made even one request would accumulate an unbounded list of timestamps. The pruning step keeps the list bounded to the last 60 seconds of activity, which is all that matters for the rate calculation.

---

## What Was Intentionally Omitted

**GeoIP lookup:** IP addresses are validated for format but not resolved to geographic locations. Adding GeoIP would require a third-party database and library (MaxMind GeoLite2, `geoip2`). The module is intentionally stdlib-only.

**Log rotation handling:** The module assumes a single file with contiguous lines. Log rotation (where a file ends mid-session and a rotated file begins) is not handled. Multi-file analysis would require stitching or sorting by timestamp.

**User-Agent parsing beyond scanner detection:** The agent string is captured but not parsed into browser/OS components. A full UA parser (`user-agents` library) was intentionally excluded to keep the module stdlib-only.

**False positive suppression for security alerts:** Path traversal and SQL injection patterns in URLs will produce findings for legitimate security testing traffic (penetration testers, vulnerability scanners run by the operator themselves). The module docstring explicitly states this is a triage helper, not a security tool. Suppression lists or allowlists were out of scope.

---

## Biggest Weakness

The time-window pruning implementation replaces the tracking list on every request from the same IP:

```python
window_by_ip[ip_address] = [item for item in recent if item >= cutoff]
```

For an IP making thousands of requests, this creates a new list on every line — O(n) allocation per hit. A `collections.deque(maxlen=N)` would be more memory-efficient for a fixed window size, but the exact window duration (60 seconds) requires timestamp comparison rather than count-based eviction. A `deque` with timestamp comparison is the correct long-term implementation; the list comprehension is readable but allocates unnecessarily.

---

## Scaling Considerations

**If files grow to hundreds of millions of lines:** The entire file is read into memory before splitting lines. A line-by-line streaming implementation using `open(path).readline()` or a chunked file reader would reduce peak memory. The `entries` list accumulates all parsed entries — for very large files this could be replaced with a streaming JSON writer that emits entries one at a time.

**If alert rules need to be configurable:** The current thresholds (50 requests/60s for rapid fire, 10 requests/60s for brute force) are hardcoded. Moving them to `config["alert_thresholds"]` would make them operator-tunable without code changes.

**If multi-format files are common:** Some load balancers mix Apache and Nginx format lines in the same file. The current single-format model would fall back to `"generic"` for these files. A per-line format detection (try all three patterns and use the best match) would handle mixed files at the cost of additional regex evaluation per line.

---

## What the Next Refactor Would Be

1. **`deque`-based sliding windows** — replace list comprehension pruning with `deque` + timestamp comparison for better memory efficiency at scale.
2. **Configurable alert thresholds** — move hardcoded 50/10/60 values to `config["thresholds"]`.
3. **Streaming output** — emit entries incrementally rather than accumulating in memory.
4. **Multi-format per-line detection** — try all three patterns per line for mixed-format files.

---

## What This Project Taught

**Alert deduplication is a first-class feature, not an afterthought.** Writing the test before the fix revealed that the first implementation was wrong — not wrong in the sense of crashing, but wrong in the sense of being unusable. A findings list with 150 identical entries for one IP is noise, not signal. The fix — a set that gates on first occurrence — is simple once the problem is clearly stated.

**Heuristic detection requires honest documentation.** The module docstring was added after reflecting on what the threat detection actually guarantees. Regex pattern matching against URLs is not SQL injection detection — it is SQL injection *indicator* detection. A real attacker can bypass it trivially. Writing the caveat into the docstring and the README forces clarity about what the module is and is not. That kind of honest scoping is a system design skill, not a testing skill.

**Shared modules compound value across a group.** By App 05, `formatter.py` is doing real work — the table rendering, ANSI color detection, and JSON/CSV/text dispatch are used by both the output summary and the CLI report. The marginal cost of building one more module that imports from `formatter.py` is near zero, and the consistency benefit across all five DataGuard CLIs is real.

---

*Constitution v2.0 checklist: This document satisfies Article 5 (trade-off documentation) for App 05.*
