"""Server log parser and analyzer.

Threat-style findings use pattern heuristics for triage and exploration. They are not a substitute for a SIEM,
IDS/IPS, WAF, or structured security review.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import argparse
from pathlib import Path

from formatter import format_table
from errors import InputError

APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

NGINX_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

GENERIC_PATTERN = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<url>\S+).*?(?P<status>\d{3}).*?(?P<size>\d+|-)"
)

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
SCANNER_SIGNATURES = {"nikto", "sqlmap", "nmap", "dirbuster", "acunetix", "masscan"}
PATH_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.%2f|/etc/passwd|/proc/self", re.IGNORECASE)
SQLI_PATTERN = re.compile(r"(?:union\s+select|or\s+1=1|drop\s+table|--)", re.IGNORECASE)
LOGIN_PATH_PATTERN = re.compile(r"/(?:login|auth|signin|wp-login)", re.IGNORECASE)






























def main():
    pass


if __name__ == "__main__":
    from errors import InputError

    try:
        raise SystemExit(main())
    except InputError as err:
        print(err, file=sys.stderr)
        raise SystemExit(2) from err