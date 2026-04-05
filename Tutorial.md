# Build Guide: Recreate the Log-Parser App

This guide explains how to build the same app as the `Log-Parser` repository from scratch.

The app:
- reads a server access log file
- detects whether it looks like Apache, Nginx, or a generic format
- parses each line with regex
- computes traffic summaries
- flags suspicious patterns such as path traversal probes, SQLi-style URLs, scanner user agents, and bursty request behavior
- prints a text report and can export the full structured result as JSON

---

## 1) What you are building

You are building a Python CLI + library app with these main files:

```text
Log-Parser/
├── log_parser.py
├── formatter.py
├── errors.py
├── requirements.txt
├── Schema/
│   ├── report.schema.json
│   ├── log-entry.schema.json
│   ├── finding.schema.json
│   ├── stats.schema.json
│   ├── metadata.schema.json
│   └── README.md
└── tests/
```

The current repository README describes the app as a server log parser and analyzer that reads Apache/Nginx-style logs or a generic fallback pattern, summarizes traffic, and applies heuristic threat-style checks. The CLI runs with `python log_parser.py --file path/to/access.log`, and `run()` can also be called directly from Python. fileciteturn6file0L1-L1

---

## 2) Prerequisites

Install:
- Python 3.10 or newer
- `pytest` for tests
- optionally `black` and `flake8` for formatting/linting

The repo’s `requirements.txt` currently lists:

```text
pytest>=7.0.0
black>=23.0.0
flake8>=6.0.0
```

fileciteturn11file0L1-L1

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## 3) Create `errors.py`

Start with a very small shared exception module.

The repo uses:
- `DataGuardError`
- `InputError`
- `ParseError`
- `ValidationError`

`InputError` is used by the CLI when the log file cannot be read or decoded. fileciteturn9file0L1-L1

Use this structure:

```python
class DataGuardError(Exception):
    """Base exception for friendly CLI failures."""

class InputError(DataGuardError):
    """Raised when input cannot be read or decoded."""

class ParseError(DataGuardError):
    """Raised when data cannot be parsed."""

class ValidationError(DataGuardError):
    """Raised when validation fails in a non-fatal way."""
```

---

## 4) Create `formatter.py`

This file handles report rendering and output formatting.

According to the repo, `formatter.py` is responsible for:
- ASCII table formatting
- colored terminal output
- text report rendering
- JSON serialization
- CSV serialization

It uses `csv`, `io`, `json`, `os`, and `sys`. fileciteturn8file0L1-L1

### Build it in this order

#### Step 4.1: Add ANSI colors
Create:
- `ANSI_COLORS`
- `SEVERITY_COLORS`

These are used to color findings by severity in terminals that support color. fileciteturn8file0L1-L1

#### Step 4.2: Add `stream_supports_color(stream)`
This should:
- return `False` if the stream is not a TTY
- return `False` if `NO_COLOR` is set
- otherwise return `True`

#### Step 4.3: Add `colorize(text, color, enabled=True)`
Wrap text with ANSI escape codes only when color is enabled.

#### Step 4.4: Add `format_table(headers, rows, borders=False)`
This is the shared helper for rendering aligned plain-text tables.

Your implementation should:
- convert cells to strings
- calculate column widths
- render a header row
- render a divider row
- render all data rows

This function is used by the parser to show top IPs, top URLs, and findings tables. fileciteturn7file0L1-L1

#### Step 4.5: Add `findings_to_rows(findings)`
Convert finding dictionaries into a 2D list with:
- severity
- category
- line
- message

#### Step 4.6: Add `render_report_text(result, color_enabled=True)`
This should print:
- title
- metadata
- stats
- findings
- warnings
- errors
- summary

The repo’s text report is built from those sections. fileciteturn8file0L1-L1

#### Step 4.7: Add `render_report_csv(result)`
Export findings as CSV with columns:
- severity
- category
- line
- message

#### Step 4.8: Add `render_report(result, report_format="text", color_enabled=True)`
Dispatch to:
- JSON
- CSV
- text

#### Step 4.9: Add `write_report(...)`
Write the rendered report to a file or stderr.

#### Step 4.10: Add `serialize_primary_output(output, pipe_format="text")`
This should support:
- `text`
- `json`
- `raw`

The repo uses JSON for dict/list values and plain strings for scalars. fileciteturn8file0L1-L1

---

## 5) Create `log_parser.py`

This is the main app file.

The repository’s `log_parser.py` contains:
- regex patterns for Apache, Nginx, and generic logs
- timestamp parsing
- IP normalization and validation
- response-size parsing
- format detection
- line parsing
- threat collection
- summary rendering
- the `run()` function
- the CLI `main()` function

fileciteturn7file0L1-L1

Build it in the following order.

---

## 6) Add imports

Use:
- `from __future__ import annotations`
- `ipaddress`
- `re`
- `sys`
- `Counter`, `defaultdict`
- `datetime`, `timedelta`
- `format_table` from `formatter`

These are the actual imports used by the repo. fileciteturn7file0L1-L1

---

## 7) Define the regex patterns

Create these compiled regex patterns:

### Apache
A combined-log-style pattern with named groups:
- `ip`
- `timestamp`
- `method`
- `url`
- `status`
- `size`
- optionally `referer`
- optionally `agent`

### Nginx
Very similar to Apache, but with the Nginx default spacing convention.

### Generic
A looser fallback that tries to extract:
- IPv4
- method
- URL
- status
- size

The README confirms the app supports Apache combined, Nginx default, and a generic fallback. fileciteturn6file0L1-L1

---

## 8) Define constants for detection

Create:
- `HTTP_METHODS`
- `SCANNER_SIGNATURES`
- `PATH_TRAVERSAL_PATTERN`
- `SQLI_PATTERN`
- `LOGIN_PATH_PATTERN`

These are the same detection categories the current repo uses. fileciteturn7file0L1-L1

### Suggested values
- `HTTP_METHODS` should include:
  - GET
  - POST
  - PUT
  - DELETE
  - PATCH
  - HEAD
  - OPTIONS

- `SCANNER_SIGNATURES` should include strings like:
  - nikto
  - sqlmap
  - nmap
  - dirbuster
  - acunetix
  - masscan

- `PATH_TRAVERSAL_PATTERN` should detect:
  - `../`
  - encoded traversal such as `..%2f`
  - `/etc/passwd`
  - `/proc/self`

- `SQLI_PATTERN` should detect common SQLi-style strings such as:
  - `union select`
  - `or 1=1`
  - `drop table`
  - `--`

- `LOGIN_PATH_PATTERN` should match:
  - `/login`
  - `/auth`
  - `/signin`
  - `/wp-login`

---

## 9) Write helper functions

### Step 9.1: `parse_timestamp(raw_timestamp)`
Try multiple formats:
- `%d/%b/%Y:%H:%M:%S %z`
- `%Y-%m-%dT%H:%M:%S`
- `%Y-%m-%d %H:%M:%S`

If timezone info is present, remove it before returning.

The repo explicitly does this so timestamps can be compared more easily during sliding-window analysis. fileciteturn7file0L1-L1

### Step 9.2: `normalize_client_ip(raw_ip)`
Strip whitespace.
If the IP is wrapped in brackets like `[2001:db8::1]`, remove the brackets.

The README notes that bracketed IPv6 literals are normalized. fileciteturn6file0L1-L1

### Step 9.3: `valid_ip(ip_address)`
Use `ipaddress.ip_address(...)`.
Return `True` for valid IPv4 or IPv6, otherwise `False`.

### Step 9.4: `parse_response_size(size_field)`
Rules from the repo:
- `-` means size `0`
- negative or invalid integers are treated as malformed
- malformed values are stored as `0` but flagged

fileciteturn6file0L1-L1

### Step 9.5: `detect_format(lines)`
Look at the first few lines and count how many match:
- Apache
- Nginx
- generic

Return the format with the most hits.

The current CLI auto-detects using the first 5 lines. fileciteturn6file0L1-L1

### Step 9.6: `parse_line(line, log_format)`
Select the regex pattern based on `log_format`.
Return the named groups as a dict.
If optional fields are missing, default:
- `referer` → `-`
- `agent` → `-`

### Step 9.7: `add_threat(findings, line_number, category, severity, ip_address, message)`
Append a finding dict with:
- severity
- category
- line
- ip
- message

This matches the report structure used by `run()`. fileciteturn7file0L1-L1

---

## 10) Build `render_output_summary(...)`

This function generates the short human-readable output stored in `result["output"]`.

It should:
- show a “Threat Alerts” table if findings exist
- return early if `threats_only=True`
- otherwise append:
  - Overview
  - Top IPs
  - Top error IPs
  - Top URLs
  - Top error URLs

The repo does exactly this. fileciteturn7file0L1-L1

---

## 11) Build the core `run(input_text, config=None)` function

This is the heart of the app.

### Step 11.1: Read config
Support these config keys:
- `format`
- `top`
- `threats_only`
- `source_name`
- `progress_every`
- `progress_stream`

These config keys are documented in the README. fileciteturn6file0L1-L1

### Step 11.2: Split into lines
Use `input_text.splitlines()`.

### Step 11.3: Detect or force log format
If `config["format"]` is not `"auto"`, use it.
Otherwise, detect it from the first five lines.

### Step 11.4: Initialize all counters and collections
You need:
- `parsed_entries`
- `parse_failures`
- `status_counts`
- `status_bands`
- `ip_counter`
- `error_ip_counter`
- `url_counter`
- `error_url_counter`
- `window_by_ip`
- `login_windows`
- `findings`
- `rapid_fire_alerted`
- `brute_force_alerted`

These are all used in the repo’s implementation. fileciteturn7file0L1-L1

### Step 11.5: Loop through each line
For each line:
1. optionally write progress to stderr
2. parse the line
3. if parsing fails, add it to `parse_failures` and continue
4. extract:
   - IP
   - method
   - URL
   - status
   - size
   - agent
   - timestamp
5. normalize and validate values
6. append a structured parsed entry
7. update counters
8. run threat checks
9. run sliding-window burst checks

---

## 12) Define the parsed entry structure

Each parsed entry should look like this:

```python
{
    "line": 12,
    "ip": "192.168.1.10",
    "timestamp": "2026-04-04T12:34:56",
    "method": "GET",
    "url": "/index.html",
    "status": 200,
    "response_size": 512,
    "agent": "Mozilla/5.0"
}
```

The repo stores the timestamp as ISO text if available, otherwise an empty string. fileciteturn7file0L1-L1

---

## 13) Implement the threat checks

The app is intentionally heuristic-based for triage, not a full security platform. The README says these checks are for exploration and not a replacement for a SIEM, IDS/IPS, WAF, or structured review. fileciteturn6file0L1-L1

Add these checks:

### 13.1 Invalid IP
If `valid_ip(ip_address)` is false:
- add finding category `invalid_ip`
- severity `medium`

### 13.2 Invalid method
If the method is not in `HTTP_METHODS`:
- add `invalid_method`
- severity `medium`

### 13.3 Invalid status
If status is outside 100–599:
- add `invalid_status`
- severity `medium`

The README explicitly says out-of-range status codes are flagged and counted in `other_status`. fileciteturn6file0L1-L1

### 13.4 Malformed response size
If size parsing fails:
- add `malformed_response_size`
- severity `low`

### 13.5 Path traversal probe
If the URL matches `PATH_TRAVERSAL_PATTERN`:
- add `path_traversal`
- severity `high`

### 13.6 SQL injection probe
If the URL matches `SQLI_PATTERN`:
- add `sql_injection_probe`
- severity `high`

### 13.7 Scanner fingerprint
If the user-agent contains one of the scanner signatures:
- add `scanner_fingerprint`
- severity `medium`

---

## 14) Implement time-window detections

The repo includes two burst-style checks using timestamps and 60-second windows. fileciteturn6file0L1-L1

### 14.1 Rapid-fire requests
For each IP:
- keep timestamps from the last 60 seconds
- if there are 50 or more, add:
  - category `rapid_fire`
  - severity `high`

Only alert once per IP per run.

### 14.2 Login-path burst
When the URL matches the login path pattern:
- keep login timestamps from the last 60 seconds
- if there are 10 or more, add:
  - category `brute_force`
  - severity `high`

Only alert once per IP per run.

The README confirms the current thresholds:
- rapid-fire: 50+ requests in 60 seconds
- login burst: 10+ login/auth requests in 60 seconds

fileciteturn6file0L1-L1

---

## 15) Compute summary statistics

After processing all lines, compute:
- parse rate
- error rate
- status bands
- other_status for out-of-range codes

The `stats` object in the repo contains:
- format
- total_lines
- parsed_lines
- unparseable_lines
- parse_rate
- error_rate
- 2xx
- 3xx
- 4xx
- 5xx
- other_status

fileciteturn7file0L1-L1

---

## 16) Add parse-failure findings

The current app records up to 20 parse-failure findings as low-severity items with category `parse_failure`. fileciteturn7file0L1-L1

Example shape:

```python
{
    "severity": "low",
    "category": "parse_failure",
    "line": 99,
    "ip": "",
    "message": "Could not parse line 99."
}
```

---

## 17) Build the returned result object

Return a dict with exactly these keys:

```python
{
    "module_name": "logs",
    "title": "DataGuard Log Analysis Report",
    "output": "...",
    "entries": [...],
    "findings": [...],
    "warnings": [...],
    "errors": [],
    "stats": {...},
    "metadata": {...},
    "summary": "..."
}
```

That is the exact top-level structure currently returned by `run()`. fileciteturn7file0L1-L1

### Metadata shape
Include:
- `source`
- `format`
- `top`

### Warnings
If parse failures exist, add:
- `"N lines could not be parsed."`

### Summary
The repo summary is a short sentence that includes:
- how many lines were parsed
- detected log format
- how many alerts were detected

---

## 18) Build the CLI in `main()`

The CLI uses `argparse` and supports:
- `--file` / `-f`
- `--format`
- `--top`
- `--threats-only`
- `--export PATH`
- `--progress-every N`

This is documented in the README and implemented in `main()`. fileciteturn6file0L1-L1 fileciteturn7file0L1-L1

### CLI behavior to match
- read the log file as UTF-8
- raise `InputError` on unreadable or non-UTF-8 files
- print a startup progress line to stderr when progress reporting is enabled
- run analysis
- optionally export JSON using `render_report(..., report_format="json")`
- render the full text report unless `--threats-only` is set
- exit with code `2` for input-related failures

The README explicitly states the CLI exits with code 2 for input/export failures tied to `InputError`. fileciteturn6file0L1-L1

---

## 19) Add JSON Schema support

To make the app easier for other systems to consume, keep the `Schema/` folder alongside the app.

Recommended files:
- `Schema/report.schema.json`
- `Schema/log-entry.schema.json`
- `Schema/finding.schema.json`
- `Schema/stats.schema.json`
- `Schema/metadata.schema.json`

These validate the exported JSON report structure built by `run()` and the CLI export path.

---

## 20) Add tests

Create a `tests/` folder and add tests for the most important behaviors.

### Minimum test set
1. **Apache line parses successfully**
2. **Nginx line parses successfully**
3. **Generic line parses successfully**
4. **Invalid line becomes parse failure**
5. **`-` response size becomes 0**
6. **Negative or malformed size triggers finding**
7. **Path traversal URL triggers finding**
8. **SQLi-like URL triggers finding**
9. **Scanner user-agent triggers finding**
10. **Rapid-fire threshold triggers once per IP**
11. **Brute-force threshold triggers once per IP**
12. **JSON export matches `report.schema.json`**

Run tests with:

```bash
python -m pytest tests/ -q
```

That is the same command shown in the README. fileciteturn6file0L1-L1

---

## 21) Manual run examples

### Analyze a log file
```bash
python log_parser.py --file access.log
```

### Force Apache format
```bash
python log_parser.py --file access.log --format apache
```

### Show only threat-related output
```bash
python log_parser.py --file access.log --threats-only
```

### Export full JSON
```bash
python log_parser.py --file access.log --export report.json
```

### Reduce progress noise
```bash
python log_parser.py --file access.log --progress-every 0
```

These match the repo’s documented CLI usage. fileciteturn6file0L1-L1

---

## 22) Example library usage

The repo also supports using the parser directly from Python:

```python
from pathlib import Path
from log_parser import run

text = Path("access.log").read_text(encoding="utf-8")
result = run(text, {"format": "auto", "top": 10, "source_name": "access.log"})

print(result["output"])
print(result["findings"])
print(result["entries"])
```

This flow is documented in the README. fileciteturn6file0L1-L1

---

## 23) Why this app structure works

This architecture works well because it separates concerns:

- `log_parser.py` handles parsing, detection, aggregation, and the CLI
- `formatter.py` handles human-readable and machine-readable output
- `errors.py` handles friendly CLI exceptions
- `Schema/` makes JSON output stable for other tools and pipelines

That separation is already reflected in the repository’s current file layout and code map. fileciteturn6file0L1-L1

---

## 24) Recommended improvements if someone rebuilds it

If someone wants to build the same app but make it stronger, these are the first good upgrades:

1. add tests for schema validation and edge-case logs
2. support IPv6 in the generic regex, not just Apache/Nginx patterns
3. add optional JSON Lines input support
4. add configurable thresholds for rapid-fire and brute-force detection
5. add optional output fields for referer and raw line text
6. add benchmark tests for very large log files

---

## 25) Build checklist

Use this checklist when recreating the project:

- [ ] create virtual environment
- [ ] install requirements
- [ ] create `errors.py`
- [ ] create `formatter.py`
- [ ] create `log_parser.py`
- [ ] add regex patterns
- [ ] add helper parsers and validators
- [ ] add threat detection rules
- [ ] add burst detection rules
- [ ] add `run()` result object
- [ ] add CLI `main()`
- [ ] add JSON export
- [ ] add `Schema/` folder
- [ ] add tests
- [ ] run `pytest`
- [ ] test CLI with a real log file

---

## 26) Final note for builders

This app is best thought of as:
- a practical parser
- a lightweight analytics tool
- a heuristic security triage helper

It is not meant to replace a full security monitoring stack. That limitation is part of the current project design and is stated directly in the repo documentation. fileciteturn6file0L1-L1
