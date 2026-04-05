# Schema files

This folder contains JSON Schema definitions for the structured output returned by `log_parser.run()` and by the CLI JSON export path.

## Files

- `report.schema.json` — top-level DataGuard log analysis report
- `log-entry.schema.json` — one parsed log entry
- `finding.schema.json` — one finding / alert item
- `stats.schema.json` — aggregate counts and rates
- `metadata.schema.json` — run metadata such as source, format, and top N

## Intended use

Validate the JSON written by:

```bash
python log_parser.py --file access.log --export report.json
```

Example with Python `jsonschema`:

```python
import json
from pathlib import Path

from jsonschema import validate

schema = json.loads(Path("Schema/report.schema.json").read_text(encoding="utf-8"))
report = json.loads(Path("report.json").read_text(encoding="utf-8"))
validate(instance=report, schema=schema)
```

These schemas describe the current exported structure in this repository and are intentionally strict about required keys.
