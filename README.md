# Server log parser and analyzer

**What it does:** Reads Apache/Nginx-style access logs (or a generic fallback pattern), parses each line with regex, and summarizes traffic (status bands, top IPs/URLs, error-focused tops). It also applies **heuristic** threat-style checks (path traversal–like paths, SQLi-like query strings, scanner-like user agents, rapid requests, login-path bursts). Those checks are for triage and exploration, not a substitute for a SIEM, IDS/IPS, WAF, or structured review.

**Why it matters:** Semi-structured logs are a natural fit for regex, counters, and small sliding windows over timestamps.

**Standalone value:** Point the CLI at a log file, or call `run()` from Python to get structured results plus a text summary.

**Mega-app role:** Intended to align with a `dataguard`/pipeline style (`module_name` / `title` in the result dict); `formatter.py` is the local table/report helper.

---

## Requirements

- Python **3.10+**
- Same directory: `log_parser.py`, `formatter.py`, `errors.py`

Install dev tools (optional):

```bash
pip install -r requirements.txt
```

---

## Command-line interface

Run from the project directory (so `formatter` and `errors` resolve):

```bash
python log_parser.py --file path/to/access.log
```

| Flag | Description |
|------|-------------|
| `--file` / `-f` | **Required.** Path to the log file (read as **UTF-8**). |
| `--format` | `auto` (default), `apache`, `nginx`, or `generic`. Auto uses the first **5** lines to pick a pattern. |
| `--top` | How many rows to show in each “top N” table (default: **10**). |
| `--threats-only` | Print only the threat-oriented summary (no overview stats or top tables). |
| `--export PATH` | Write the **full** result dict as JSON (UTF-8) to `PATH`. |
| `--progress-every N` | Print progress to **stderr** every `N` lines (`0` disables; default: **10000**). |

On unreadable or non–UTF-8 input files (or failed export writes), the CLI prints a message to **stderr** and exits with code **2** (`InputError`).

**Output:** The human report (with ANSI colors on severity when **stdout** is a TTY and `NO_COLOR` is unset) goes to **stdout**. Progress lines go to **stderr**.

---

## Library usage

```python
from pathlib import Path

from log_parser import run

text = Path("access.log").read_text(encoding="utf-8")
result = run(text, {"format": "auto", "top": 10, "source_name": "access.log"})
print(result["output"])       # Short text summary tables
print(result["findings"])     # List of finding dicts
print(result["entries"])      # Parsed rows
```

Optional `config` keys: `format`, `top`, `threats_only`, `source_name`, `progress_every`, `progress_stream` (a text stream for progress lines).

---

## Parsing and behavior

- **Apache combined** and **Nginx default**-style lines use dedicated patterns; **generic** looks for IPv4, method, URL, status, and size on one line.
- **Unparseable** lines are recorded (sample included in findings); they are not silently dropped.
- **Client IP:** Validated with the stdlib `ipaddress` module (**IPv4 and IPv6**). Bracketed IPv6 literals in the IP field are normalized.
- **HTTP methods** outside a small allow-list are flagged.
- **Status codes** outside **100–599** go to an `other_status` bucket and are flagged.
- **Response size:** `-` is treated as **0**; non-integer or negative values are flagged (`malformed_response_size`) and stored as **0** for that row.
- **Rapid-fire** (50+ requests from one IP in 60s) and **login-path bursts** (10+ in 60s) emit **at most one** alert per IP per run to avoid flooding the report.

---

## Output report (full mode)

Sections include overview (parse rate, error rate), **Top IPs**, **Top error IPs (4xx/5xx)**, **Top URLs**, **Top error URLs (4xx/5xx)**, and threat/findings tables. For machine-readable output, use `--export` or `formatter.render_report(result, "json")` / `"csv"`.

---

## Tests

```bash
python -m pytest tests/ -q
```

---

## Tech stack (actual imports)

| Piece | Role |
|-------|------|
| `re`, `ipaddress` | Parsing and IP validation |
| `collections` | `Counter`, `defaultdict` for aggregates and sliding windows |
| `datetime` | Timestamp parsing and windowing |
| `argparse`, `sys`, `pathlib` | CLI |
| `formatter.py` | Tables, colored text report, JSON/CSV serialization |

---

## Code map

Main regex patterns and helpers live in `log_parser.py` (`APACHE_PATTERN`, `NGINX_PATTERN`, `GENERIC_PATTERN`, `parse_line()`, `detect_format()`, `run()`, `main()`). Shared formatting is in `formatter.py`. CLI file I/O failures raise `errors.InputError`.
