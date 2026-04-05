"""Server log parser and analyzer.

Threat-style findings use pattern heuristics for triage and exploration. They are not a substitute for a SIEM,
IDS/IPS, WAF, or structured security review.
"""

# Enable postponed evaluation of type annotations for cleaner typing
from __future__ import annotations

# Import ipaddress for IPv4/IPv6 client validation without false positives on IPv6-heavy logs
import ipaddress
# Import re for regex, Counter/defaultdict for stats, and datetime for time-window analysis
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# Import a utility to render results in a clean, human-readable table format
from formatter import format_table


# Regex for standard Apache Combined Log Format
APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Regex for standard Nginx log format (very similar to Apache but often has minor spacing differences)
NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# A fallback regex to catch basic IP, Method, URL, Status, and Size from non-standard logs
GENERIC_PATTERN = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<url>\S+).*?(?P<status>\d{3}).*?(?P<size>\d+|-)"
)

# Set of standard HTTP methods to validate against non-standard or malicious requests
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
# Common keywords found in the User-Agents of automated vulnerability scanners
SCANNER_SIGNATURES = {"nikto", "sqlmap", "nmap", "dirbuster", "acunetix", "masscan"}
# Pattern to detect Directory Traversal attacks (trying to access sensitive system files)
PATH_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.%2f|/etc/passwd|/proc/self", re.IGNORECASE)
# Pattern to detect common SQL Injection keywords in the URL string
SQLI_PATTERN = re.compile(r"(?:union\s+select|or\s+1=1|drop\s+table|--)", re.IGNORECASE)
# Pattern to identify requests hitting sensitive authentication endpoints
LOGIN_PATH_PATTERN = re.compile(r"/(?:login|auth|signin|wp-login)", re.IGNORECASE)


# Attempt to convert various log timestamp strings into Python datetime objects
def parse_timestamp(raw_timestamp: str) -> datetime | None:
    # Try multiple common formats used by different web servers
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(raw_timestamp, fmt)
            # Strip timezone info to make comparison calculations simpler
            if parsed.tzinfo is not None:
                return parsed.replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    return None


# Normalize client IP from log fields (Apache/Nginx sometimes bracket IPv6 literals)
def normalize_client_ip(raw_ip: str) -> str:
    # Strip whitespace and surrounding brackets used for IPv6 in some access logs
    cleaned = raw_ip.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        return cleaned[1:-1]
    return cleaned


# Basic validation: accept any syntactically valid IPv4 or IPv6 address
def valid_ip(ip_address: str) -> bool:
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


# Parse body size field: dash means zero; non-int or negative values are invalid
def parse_response_size(size_field: str) -> tuple[int, bool]:
    # Return (value, True) when the field is usable; (0, False) when corrupted
    if size_field == "-":
        return 0, True
    try:
        parsed = int(size_field)
        if parsed < 0:
            return 0, False
        return parsed, True
    except ValueError:
        return 0, False


# Sample the first few lines to automatically detect which log format is being used
def detect_format(lines: list[str]) -> str:
    apache_hits = sum(1 for line in lines if APACHE_PATTERN.search(line))
    nginx_hits = sum(1 for line in lines if NGINX_PATTERN.search(line))
    generic_hits = sum(1 for line in lines if GENERIC_PATTERN.search(line))
    # Return the format that matched the most lines in the sample
    if apache_hits >= nginx_hits and apache_hits >= generic_hits:
        return "apache"
    if nginx_hits >= generic_hits:
        return "nginx"
    return "generic"


# Apply the chosen regex pattern to a single log line to extract structured data
def parse_line(line: str, log_format: str) -> dict | None:
    pattern = {
        "apache": APACHE_PATTERN,
        "nginx": NGINX_PATTERN,
        "generic": GENERIC_PATTERN,
    }.get(log_format, APACHE_PATTERN)
    match = pattern.search(line)
    if not match:
        return None
    data = match.groupdict()
    # Ensure optional fields have a default value if missing from the log
    data.setdefault("referer", "-")
    data.setdefault("agent", "-")
    return data


# Helper to log a security-related finding to the central report
def add_threat(findings: list[dict], line_number: int, category: str, severity: str, ip_address: str, message: str) -> None:
    findings.append(
        {
            "severity": severity,
            "category": category,
            "line": line_number,
            "ip": ip_address,
            "message": message,
        }
    )


# Generate the human-readable text report including tables for Top IPs and URLs
def render_output_summary(
    stats: dict,
    top_ips: list[tuple[str, int]],
    top_error_ips: list[tuple[str, int]],
    top_urls: list[tuple[str, int]],
    top_error_urls: list[tuple[str, int]],
    findings: list[dict],
    top_n: int,
    threats_only: bool,
) -> str:
    sections = []
    # If security threats were found, display them in a table at the top
    if findings:
        threat_rows = [[item.get("severity", ""), item.get("category", ""), item.get("ip", ""), item.get("message", "")] for item in findings[: max(top_n, 5)]]
        sections.append("Threat Alerts")
        sections.append(format_table(["Severity", "Category", "IP", "Message"], threat_rows))
    elif threats_only:
        sections.append("No threats detected.")

    # If the user only wants security info, stop here
    if threats_only:
        return "\n\n".join(sections)

    # Otherwise, add general traffic statistics and top-talker tables
    sections.append("")
    sections.append("Overview")
    sections.append(f"Requests parsed: {stats['parsed_lines']}/{stats['total_lines']} ({stats['parse_rate']})")
    sections.append(f"Error rate: {stats['error_rate']}")

    if top_ips:
        sections.append("")
        sections.append("Top IPs")
        sections.append(format_table(["IP", "Requests"], [[ip_address, count] for ip_address, count in top_ips[:top_n]]))

    if top_error_ips:
        sections.append("")
        sections.append("Top error IPs (4xx/5xx)")
        sections.append(format_table(["IP", "Errors"], [[ip_address, count] for ip_address, count in top_error_ips[:top_n]]))

    if top_urls:
        sections.append("")
        sections.append("Top URLs")
        sections.append(format_table(["URL", "Hits"], [[url, count] for url, count in top_urls[:top_n]]))

    if top_error_urls:
        sections.append("")
        sections.append("Top error URLs (4xx/5xx)")
        sections.append(format_table(["URL", "Errors"], [[url, count] for url, count in top_error_urls[:top_n]]))

    return "\n".join(section for section in sections if section is not None)


# Main execution function for log analysis
def run(input_text: str, config: dict | None = None) -> dict:
    config = config or {}
    lines = input_text.splitlines()
    # Allow manual override of format, otherwise auto-detect
    forced_format = config.get("format", "auto")
    log_format = forced_format if forced_format and forced_format != "auto" else detect_format(lines[:5])
    top_n = int(config.get("top", 10))

    # Initialize counters for analytics and security tracking
    parsed_entries = []
    parse_failures = []
    status_counts = Counter()
    status_bands = Counter()
    ip_counter = Counter()
    error_ip_counter = Counter()
    url_counter = Counter()
    error_url_counter = Counter()
    # Dictionaries to track timestamps for rate-limiting detection
    window_by_ip = defaultdict(list)
    login_windows = defaultdict(list)
    findings = []
    # Track which IPs already triggered sliding-window alerts (avoid one alert per line after threshold)
    rapid_fire_alerted: set[str] = set()
    brute_force_alerted: set[str] = set()
    # Optional progress reporting while scanning (CLI sets progress_every / progress_stream)
    progress_every = int(config.get("progress_every") or 0)
    progress_stream = config.get("progress_stream")

    # Process logs line by line
    for line_number, line in enumerate(lines, start=1):
        if progress_every and line_number % progress_every == 0 and progress_stream is not None:
            # Emit a coarse progress line so large files show movement on stderr
            progress_stream.write(
                f"Processed {line_number}/{len(lines)} lines, parsed so far: {len(parsed_entries)} ({log_format})\n"
            )

        entry = parse_line(line, log_format)
        if not entry:
            parse_failures.append({"line": line_number, "raw": line})
            continue

        # Extract core fields from the parsed dictionary
        ip_address = normalize_client_ip(entry["ip"])
        method = entry["method"]
        url = entry["url"]
        try:
            status_code = int(entry["status"])
        except (TypeError, ValueError):
            add_threat(findings, line_number, "malformed_status", "medium", ip_address, f"Non-integer status {entry['status']!r}.")
            continue

        size_field = entry["size"]
        agent = entry.get("agent") or "-"
        timestamp = parse_timestamp(entry.get("timestamp", ""))
        response_size, size_ok = parse_response_size(size_field)
        if not size_ok:
            add_threat(
                findings,
                line_number,
                "malformed_response_size",
                "low",
                ip_address,
                f"Response size field is not a non-negative integer: {size_field!r}.",
            )

        # Store the structured entry
        parsed_entries.append(
            {
                "line": line_number,
                "ip": ip_address,
                "timestamp": timestamp.isoformat() if timestamp else "",
                "method": method,
                "url": url,
                "status": status_code,
                "response_size": response_size,
                "agent": agent,
            }
        )

        # Security Check: Validate IP format
        if not valid_ip(ip_address):
            add_threat(findings, line_number, "invalid_ip", "medium", ip_address, f"Invalid client IP address {ip_address!r}.")

        # Security Check: Detect unusual HTTP methods
        if method not in HTTP_METHODS:
            add_threat(findings, line_number, "invalid_method", "medium", ip_address, f"Non-standard HTTP method {method}.")

        # Security Check: Detect invalid HTTP status codes
        if not 100 <= status_code <= 599:
            add_threat(findings, line_number, "invalid_status", "medium", ip_address, f"Status code {status_code} is outside 100-599.")

        # Analytics: Increment status and IP counters
        status_counts[str(status_code)] += 1
        if 100 <= status_code <= 599:
            status_bands[f"{status_code // 100}xx"] += 1
        else:
            # Keep out-of-range codes out of standard bands so totals stay consistent
            status_bands["other"] += 1
        ip_counter[ip_address] += 1
        url_counter[url] += 1

        # Track error distribution
        if status_code >= 400:
            error_ip_counter[ip_address] += 1
            error_url_counter[url] += 1

        # Security Check: Path Traversal patterns
        if PATH_TRAVERSAL_PATTERN.search(url):
            add_threat(findings, line_number, "path_traversal", "high", ip_address, f"Path traversal probe in URL {url}.")

        # Security Check: SQL Injection patterns
        if SQLI_PATTERN.search(url):
            add_threat(findings, line_number, "sql_injection_probe", "high", ip_address, f"SQL injection probe in URL {url}.")

        # Security Check: Automated scanner signatures
        if any(signature in agent.lower() for signature in SCANNER_SIGNATURES):
            add_threat(findings, line_number, "scanner_fingerprint", "medium", ip_address, f"Scanner-like user agent {agent!r}.")

        # Time-Window Analysis: Detect Rapid-Fire Requests (Potential DoS or scraping)
        if timestamp:
            recent_requests = window_by_ip[ip_address]
            recent_requests.append(timestamp)
            cutoff = timestamp - timedelta(seconds=60)
            # Remove timestamps older than 60 seconds
            window_by_ip[ip_address] = [item for item in recent_requests if item >= cutoff]
            if len(window_by_ip[ip_address]) >= 50 and ip_address not in rapid_fire_alerted:
                add_threat(findings, line_number, "rapid_fire", "high", ip_address, "50+ requests from the same IP inside 60 seconds.")
                rapid_fire_alerted.add(ip_address)

            # Time-Window Analysis: Detect Brute Force attempts on login pages
            if LOGIN_PATH_PATTERN.search(url):
                login_requests = login_windows[ip_address]
                login_requests.append(timestamp)
                login_cutoff = timestamp - timedelta(seconds=60)
                login_windows[ip_address] = [item for item in login_requests if item >= login_cutoff]
                if len(login_windows[ip_address]) >= 10 and ip_address not in brute_force_alerted:
                    add_threat(findings, line_number, "brute_force", "high", ip_address, "10+ login/auth requests inside 60 seconds.")
                    brute_force_alerted.add(ip_address)

    # Calculate final processing statistics
    parse_rate = f"{(len(parsed_entries) / max(len(lines), 1)) * 100:.1f}%"
    error_requests = sum(count for code, count in status_counts.items() if code.startswith("4") or code.startswith("5"))
    error_rate = f"{(error_requests / max(len(parsed_entries), 1)) * 100:.1f}%"

    stats = {
        "format": log_format,
        "total_lines": len(lines),
        "parsed_lines": len(parsed_entries),
        "unparseable_lines": len(parse_failures),
        "parse_rate": parse_rate,
        "error_rate": error_rate,
        "2xx": status_bands["2xx"],
        "3xx": status_bands["3xx"],
        "4xx": status_bands["4xx"],
        "5xx": status_bands["5xx"],
        "other_status": status_bands["other"],
    }

    # Add a limited number of parse failures to the findings report
    findings.extend(
        {
            "severity": "low",
            "category": "parse_failure",
            "line": failure["line"],
            "ip": "",
            "message": f"Could not parse line {failure['line']}.",
        }
        for failure in parse_failures[:20]
    )

    # Build the final output string
    output_text = render_output_summary(
        stats,
        ip_counter.most_common(top_n),
        error_ip_counter.most_common(top_n),
        url_counter.most_common(top_n),
        error_url_counter.most_common(top_n),
        findings,
        top_n,
        bool(config.get("threats_only")),
    )

    # Generate a concise summary of the results
    summary = (
        f"Parsed {len(parsed_entries)} of {len(lines)} log lines as {log_format}. "
        f"Detected {len([item for item in findings if item['category'] != 'parse_failure'])} alerts."
    )

    # Return the full result structure
    return {
        "module_name": "logs",
        "title": "DataGuard Log Analysis Report",
        "output": output_text,
        "entries": parsed_entries,
        "findings": findings,
        "warnings": [f"{len(parse_failures)} lines could not be parsed."] if parse_failures else [],
        "errors": [],
        "stats": stats,
        "metadata": {"source": config.get("source_name", "<input>"), "format": log_format, "top": top_n},
        "summary": summary,
    }


# CLI entry point: read a log file, run analysis, print a report and optionally export JSON
def main(argv: list[str] | None = None) -> int:
    # Deferred imports keep library import cost low when run() is used as a module
    import argparse
    from pathlib import Path

    from errors import InputError
    from formatter import render_report, render_report_text, stream_supports_color

    parser = argparse.ArgumentParser(description="Server log parser and analyzer.")
    parser.add_argument("--file", "-f", required=True, help="Path to the log file to analyze")
    parser.add_argument(
        "--format",
        default="auto",
        choices=("auto", "apache", "nginx", "generic"),
        help="Force a log format or auto-detect from the first 5 lines (default: auto)",
    )
    parser.add_argument("--top", type=int, default=10, help="How many top IPs and URLs to show (default: 10)")
    parser.add_argument(
        "--threats-only",
        action="store_true",
        help="Print only the threat section (no stats overview or top tables)",
    )
    parser.add_argument(
        "--export",
        metavar="PATH",
        help="Write the full analysis result as JSON (UTF-8) to this path",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10000,
        metavar="N",
        help="Write progress to stderr every N lines (0 disables; default: 10000)",
    )
    args = parser.parse_args(argv)

    path = Path(args.file)
    try:
        input_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"Cannot read log file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"Log file is not valid UTF-8 ({path}): {exc}") from exc

    lines_total = len(input_text.splitlines())
    if args.progress_every:
        print(f"Read {lines_total} lines from {path}", file=sys.stderr)

    config = {
        "format": args.format,
        "top": args.top,
        "threats_only": args.threats_only,
        "source_name": str(path),
        "progress_every": max(args.progress_every, 0),
        "progress_stream": sys.stderr,
    }
    result = run(input_text, config)

    if args.export:
        export_path = Path(args.export)
        try:
            export_path.write_text(render_report(result, report_format="json"), encoding="utf-8", newline="\n")
        except OSError as exc:
            raise InputError(f"Cannot write export file {export_path}: {exc}") from exc

    use_color = stream_supports_color(sys.stdout)
    if args.threats_only:
        primary = result["output"]
        sys.stdout.write(primary)
        if not primary.endswith("\n"):
            sys.stdout.write("\n")
    else:
        report_body = render_report_text(result, color_enabled=use_color)
        sys.stdout.write(report_body)
        if not report_body.endswith("\n"):
            sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    from errors import InputError

    try:
        raise SystemExit(main())
    except InputError as err:
        print(err, file=sys.stderr)
        raise SystemExit(2) from err