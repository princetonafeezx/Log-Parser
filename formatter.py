"""Shared output and report formatting.

Primary stdout serialization is for CLI piping; it is not a security boundary.
"""

# Enable postponed evaluation of annotations to support modern type hinting in Python 3.10+
from __future__ import annotations

# Import the csv module for generating spreadsheet-compatible report files
import csv
# Import io for in-memory text stream buffering
import io
# Import json for structured data serialization (CLI pipes and JSON reports)
import json
# Import os to check environment variables for color configuration
import os
# Import sys to access standard error (stderr) for report writing
import sys


# Define a dictionary of ANSI escape sequences for terminal text coloring
ANSI_COLORS = {
    "reset": "\033[0m",    # Resets terminal color to default
    "red": "\033[31m",      # Used for high-severity findings
    "green": "\033[32m",    # Used for successful operations
    "yellow": "\033[33m",   # Used for medium-severity findings/warnings
    "blue": "\033[34m",     # Used for low-severity findings
    "magenta": "\033[35m",  # Used for critical-severity findings
    "cyan": "\033[36m",     # Used for info-level findings
}

# Map finding severity levels to specific colors from the ANSI_COLORS dict
SEVERITY_COLORS = {
    "critical": "magenta",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "cyan",
}


# Determine if the current output stream (like a terminal) can display colors
def stream_supports_color(stream) -> bool:
    # Check if the stream is an interactive terminal (TTY)
    if not hasattr(stream, "isatty") or not stream.isatty():
        # If piped to a file or another process, disable colors
        return False
    # Honor the industry-standard 'NO_COLOR' environment variable
    if os.environ.get("NO_COLOR"):
        # If the variable is present, disable colors
        return False
    # Otherwise, colors are supported
    return True


# Wrap text in ANSI color codes if coloring is enabled and the color exists
def colorize(text: str, color: str, enabled: bool = True) -> str:
    # Return raw text if disabled or the requested color isn't defined
    if not enabled or color not in ANSI_COLORS:
        # Return text without modification
        return text
    # Inject the color start code and the reset code at the end
    return f"{ANSI_COLORS[color]}{text}{ANSI_COLORS['reset']}"


# Generate a formatted ASCII table string from headers and data rows
def format_table(headers: list[str], rows: list[list[object]], borders: bool = False) -> str:
    # Convert all non-string cell objects (like line numbers) into strings
    string_rows = [[str(cell) for cell in row] for row in rows]
    # Initialize column widths based on the length of the header text
    widths = [len(header) for header in headers]
    # Iterate through every row to find the maximum width needed for each column
    for row in string_rows:
        # Check every cell in the current row
        for index, value in enumerate(row):
            # Update width if the current cell is wider than the previous max
            widths[index] = max(widths[index], len(value))

    # Helper function to align text within columns and optionally add pipe borders
    def render_row(row_values: list[str]) -> str:
        # Pad each value with spaces to match the calculated column width
        cells = [value.ljust(widths[index]) for index, value in enumerate(row_values)]
        # If borders are requested, wrap the row in pipes
        if borders:
            # Return string with pipe separators
            return "| " + " | ".join(cells) + " |"
        # Otherwise, separate columns with two spaces
        return "  ".join(cells)

    # Begin the table with the header row
    lines = [render_row(headers)]
    # Create the horizontal divider line (e.g., "----  ----")
    divider_parts = ["-" * width for width in widths]
    # Format the divider based on whether borders are enabled
    if borders:
        # Create a boxed divider line
        lines.append("|-" + "-|-".join(divider_parts) + "-|")
    # Otherwise, create a simple spaced divider line
    else:
        # Add the spaced divider
        lines.append("  ".join(divider_parts))
    # Add each data row to the final table lines list
    for row in string_rows:
        # Render the current row and append it
        lines.append(render_row(row))
    # Join all lines into a single newline-separated string
    return "\n".join(lines)


# Convert a list of finding dictionaries into a simple 2D list for table rendering
def findings_to_rows(findings: list[dict]) -> list[list[object]]:
    # Initialize the container for rows
    rows = []
    # Extract specific keys from each finding dictionary
    for finding in findings:
        # Append the extracted fields as a new row list
        rows.append(
            [
                finding.get("severity", "info"), # Default to 'info' if missing
                finding.get("category", ""),     # The type of finding (e.g. 'PII')
                finding.get("line", ""),         # The line number in the source
                finding.get("message", ""),      # The descriptive text of the finding
            ]
        )
    # Return the 2D list of findings
    return rows


# Create a human-readable text-based report with stats, findings, and metadata
def render_report_text(result: dict, color_enabled: bool = True) -> str:
    # Initialize the list of lines for the report
    lines = []
    # Determine the report title from the result dictionary
    title = result.get("title") or result.get("module_name", "DataGuard Report")
    # Add the title to the report
    lines.append(title)
    # Add a visual underline equal to the length of the title
    lines.append("=" * len(title))

    # Extract and display the metadata section (e.g., source file path)
    metadata = result.get("metadata", {})
    # If metadata exists, list it key-value style
    if metadata:
        # Iterate through metadata entries
        for key, value in metadata.items():
            # Append formatted metadata line
            lines.append(f"{key}: {value}")

    # Extract and display the statistical summary section
    stats = result.get("stats", {})
    # If stats exist, add a subsection header
    if stats:
        # Add spacing and header
        lines.append("")
        lines.append("Stats")
        lines.append("-----")
        # Iterate through statistical counters
        for key, value in stats.items():
            # Append formatted stat line
            lines.append(f"{key}: {value}")

    # Extract and display the detailed findings table
    findings = result.get("findings", [])
    # If findings are present, format them into a table
    if findings:
        # Add spacing and header
        lines.append("")
        lines.append("Findings")
        lines.append("--------")
        # Initialize rows for the table
        rendered_rows = []
        # Process each finding to apply color to the severity level
        for row in findings_to_rows(findings):
            # Extract the severity string (e.g. 'high')
            severity = row[0]
            # Look up the associated color
            color = SEVERITY_COLORS.get(severity, "cyan")
            # Apply ANSI color codes to the severity cell
            row[0] = colorize(severity, color, color_enabled)
            # Add the colored row to the table list
            rendered_rows.append(row)
        # Generate the ASCII table and add it to the report lines
        lines.append(format_table(["Severity", "Category", "Line", "Message"], rendered_rows))

    # Extract and display general warnings that occurred during processing
    warnings = result.get("warnings", [])
    # If warnings exist, list them as bullet points
    if warnings:
        # Add spacing and header
        lines.append("")
        lines.append("Warnings")
        lines.append("--------")
        # Iterate through warnings
        for warning in warnings:
            # Append as a bulleted list item
            lines.append(f"- {warning}")

    # Extract and display critical errors that occurred during processing
    errors = result.get("errors", [])
    # If errors exist, list them as bullet points
    if errors:
        # Add spacing and header
        lines.append("")
        lines.append("Errors")
        lines.append("------")
        # Iterate through errors
        for error in errors:
            # Append as a bulleted list item
            lines.append(f"- {error}")

    # Add the high-level summary text at the very end
    summary = result.get("summary")
    # If a summary string is provided, append it
    if summary:
        # Add spacing and summary label
        lines.append("")
        lines.append(f"Summary: {summary}")

    # Join all lines and strip unnecessary trailing whitespace
    return "\n".join(lines).strip()


# Convert findings into a comma-separated format for spreadsheet export
def render_report_csv(result: dict) -> str:
    # Create an in-memory string buffer to hold the CSV data
    buffer = io.StringIO()
    # Initialize the CSV writer using the buffer
    writer = csv.writer(buffer)
    # Write the header row for the CSV file
    writer.writerow(["severity", "category", "line", "message"])
    # Iterate through each finding and write a corresponding CSV row
    for finding in result.get("findings", []):
        # Write specific finding keys as a row
        writer.writerow(
            [
                finding.get("severity", "info"),
                finding.get("category", ""),
                finding.get("line", ""),
                finding.get("message", ""),
            ]
        )
    # Return the full contents of the string buffer
    return buffer.getvalue()


# Master function to route report generation based on the requested format
def render_report(result: dict, report_format: str = "text", color_enabled: bool = True) -> str:
    # If JSON is requested, use the standard library to dump the full dictionary
    if report_format == "json":
        # Return indented, Unicode-safe JSON string
        return json.dumps(result, indent=2, ensure_ascii=False)
    # If CSV is requested, call the CSV-specific renderer
    if report_format == "csv":
        # Return CSV string
        return render_report_csv(result)
    # Default to the human-readable text renderer
    return render_report_text(result, color_enabled=color_enabled)


# Logic for deciding where to save the generated report (File vs. Stderr)
def write_report(
    result: dict,
    report_format: str = "text",
    color_enabled: bool = True,
    report_file: str | None = None,
) -> None:
    # Generate the report string in the specified format
    rendered = render_report(result, report_format=report_format, color_enabled=color_enabled)
    # If a file path was provided by the user
    if report_file:
        # Open the file for writing with appropriate encoding and newline handling
        with open(report_file, "w", encoding="utf-8", newline="") as handle:
            # Write the report content to the file
            handle.write(rendered)
            # Ensure the file ends with a newline for POSIX compliance
            if not rendered.endswith("\n"):
                # Append final newline
                handle.write("\n")
        # Stop execution here
        return
    # If no file is specified, write the report to the standard error stream
    sys.stderr.write(rendered)
    # Ensure the stderr output ends with a newline
    if not rendered.endswith("\n"):
        # Append final newline to stderr
        sys.stderr.write("\n")


# Format the primary data returned by a module for the standard output stream
def serialize_primary_output(output, pipe_format: str = "text") -> str:
    """Format module primary output for stdout.

    * ``text`` — Human-oriented default: ``dict`` / ``list`` as indented JSON; other values as ``str()``.
    * ``json`` — Indented JSON for JSON-serializable values; non-serializable values fall back to ``str()``.
    * ``raw`` — Compact single-line JSON for ``dict`` / ``list`` (distinct from ``text``/``json``); strings and
      other scalars as ``str()`` with no added decoration.
    """
    # Check if the user requested 'raw' output (optimized for programmatic processing)
    if pipe_format == "raw":
        # If the output is a complex data structure
        if isinstance(output, (dict, list)):
            try:
                # Return compact JSON with no spaces after separators
                return json.dumps(output, ensure_ascii=False, separators=(",", ":"))
            except (TypeError, ValueError):
                # Fall back to string representation if JSON serialization fails
                return str(output)
        # Return simple scalar values as their basic string representation
        return str(output)
    # Check if the user requested standard indented JSON
    if pipe_format == "json":
        try:
            # Return human-readable indented JSON
            return json.dumps(output, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            # Fall back to string representation if JSON serialization fails
            return str(output)
    # Default 'text' behavior: Indent complex structures as JSON
    if isinstance(output, (dict, list)):
        # Return indented JSON for readability
        return json.dumps(output, indent=2, ensure_ascii=False)
    # Return everything else (strings, numbers) as a plain string
    return str(output)