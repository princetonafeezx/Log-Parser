App: CLI Server Log Parser & Analyzer

What it does: Reads Apache/Nginx-style server logs (or any structured log format). Parses each line with RegEx to extract timestamp, IP, method, URL, status code, and response size. Counts errors by category (4xx, 5xx), identifies the top offending IPs, flags suspicious patterns (brute-force attempts, path traversal), and outputs a clean summary report. 

Why it matters: Log parsing is regex in its natural habitat. Messy, semi-structured, enormous files where validation at scale matters. 

Key skills: RegEx with named capture groups, timestamp parsing and validation, large file processing (line-by-line, not loading entire file into memory), error categorization, and statistical summarization. 

Standalone value: Drop in any server log, get an instant security and error audit.

Mega-app role: dataguard/logs.py — handles log-format data in the pipeline.

Features:
CLI Interface
•	--file flag (required) pointing to the log file
•	--format flag to force a log format or let it auto-detect from the first 5 lines (default: auto)
•	--top flag to set how many top offenders to show (default: 10)
•	--threats-only flag to suppress the full report and only print detected threats
•	--export flag to write the full analysis to a JSON file
•	Prints a line count and parse success rate as it processes

Core Log Parsing
•	Apache Combined Log Format parser — regex extracts IP, timestamp, method, URL, status code, response size, referer, user agent
•	Nginx default format parser — separate regex for Nginx’s default pattern
•	Fallback generic parser — attempts to extract fields from any structured line using common delimiters
•	Unparseable lines tracked separately with raw text and line number, never silently dropped

Validation & Data Integrity
•	IP address validation: checks valid IPv4 format, no octets above 255
•	HTTP method validation: flags non-standard methods not in GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
•	Status code range check: must be 100–599, anything outside flagged as corrupted data
•	Response size validated as a non-negative integer, dashes treated as zero

Error Categorization
•	Groups status codes into bands: 2xx, 3xx, 4xx, 5xx with counts per specific code
•	Error rate calculated as percentage of total requests
•	Time-window grouping to show if errors are spiking or steady

Top Offenders Analysis
•	Top N IPs by total request count, by error count, and by threat alert count
•	Top N most-hit URLs and most-hit error URLs
•	All displayed as formatted terminal tables

Suspicious Pattern Detection
•	Brute-force detection — IPs with 10+ requests to login/auth URLs within a short window
•	Path traversal — scans for ../, ..%2f, /etc/passwd, /proc/self in URLs
•	SQL injection probes — detects OR 1=1, UNION SELECT, DROP TABLE, -- patterns in URLs
•	Scanner fingerprinting — flags user agents containing nikto, sqlmap, nmap, dirbuster
•	Rapid-fire detection — any IP making 50+ requests within 60 seconds
•	Each alert includes: threat type, IP, evidence, line number, severity (low/medium/high)

Output Report
•	Printed to terminal as a structured, section-by-section report with ANSI color-coded severity badges
•	Includes: file overview, status code breakdown, top offenders, threat alerts, parse failure summary
•	--export writes everything to a JSON file with all fields machine-readable

Student-Level Code Style
•	Main regex patterns stored as constants: APACHE_PATTERN, NGINX_PATTERN with line-by-line comments
•	Functions named: parse_line(), check_path_traversal(), check_brute_force(), detect_scanner_agents()
•	Results accumulated in plain dicts: error_counts = {"4xx": 0, "5xx": 0}
•	Uses only: re, argparse, json, collections, datetime, sys, os
Comments like # 10 failed logins in a short window is a common brute-force signature


It converts high-volume, semi-structured server logs into actionable security and operational intelligence.
•	Automated Format Recognition: It uses a "hit-count" sampling method to automatically distinguish between Apache, Nginx, and generic log formats without user intervention.

•	Security Heuristics (Threat Hunting): It scans request paths and parameters for common attack signatures, including:
o	SQL Injection: Detecting keywords like UNION SELECT or OR 1=1.
o	Path Traversal: Identifying attempts to access system files like /etc/passwd.
o	Scanner Identification: Fingerprinting automated tools (e.g., Nikto, Acunetix) via User-Agent headers.

•	Behavioral Rate Limiting: It implements a sliding-window analysis to detect "Rapid-Fire" requests (50+ per minute) and "Brute Force" attempts on authentication endpoints (10+ per minute).

•	Traffic Profiling: Beyond security, it aggregates operational data to identify "Top Talkers" (IPs) and "Hot Paths" (URLs), and calculates real-time error rates (4xx/5xx status codes).

The Tech Stack
Technology	Role in the Project
Python 3.10+	The backbone language, utilizing datetime for precise time-delta calculations.
Regex (re)	The primary tool for "Log Shaving"—extracting specific data fields from complex strings.
collections	Uses Counter for high-speed frequency tracking and defaultdict for time-window grouping.
dataguard.formatter	A custom internal utility used to render results into clean, scannable CLI tables.

1. High-Performance Aggregation
By using collections.Counter, the script can process thousands of log lines per second with minimal CPU overhead. This allows the tool to generate "Top 10" lists for IPs and URLs nearly instantaneously, even on underpowered machines.

2. Stateful Time-Window Tracking
The combination of defaultdict(list) and timedelta allows the script to maintain a "memory" of recent events. This is what enables it to move beyond simple pattern matching and into behavioral analysis, such as identifying a brute-force attack that occurs over 60 seconds.

3. Named Capture Groups
The tech stack relies on Regex "Named Groups" (e.g., (?P<ip>...)). This makes the code highly maintainable and readable; instead of accessing data by index (like match[1]), the developer can access it by name (match.group('ip')), reducing errors during format updates.

4. Deterministic Validation
The stack includes manual IP and Status Code validation. This acts as a "sanity check" to ensure that malformed logs or "log injection" attempts (where an attacker tries to spoof log entries) are caught and flagged as "Invalid" rather than being processed as legitimate data.
