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



def main():
    pass


if __name__ == "__main__":
    from errors import InputError

    try:
        raise SystemExit(main())
    except InputError as err:
        print(err, file=sys.stderr)
        raise SystemExit(2) from err