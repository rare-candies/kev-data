#!/usr/bin/env python3
"""
Generate a KEV changelog entry for CHANGELOG.md, including:
- Live Update (diff of --prev vs --curr)
- Last 14 Days Summary (aggregate diffs over commits that touched KEV files)

Usage (from GitHub Actions):
  python .github/scripts/kev_changelog.py \
    --prev HEAD~1 \
    --curr HEAD \
    --json-path known_exploited_vulnerabilities.json \
    --csv-path known_exploited_vulnerabilities.csv \
    --out CHANGELOG.md \
    --days 14
"""

import argparse
import datetime
import io
import json
import subprocess
from dateutil import tz


# ---------------------------
# Git / JSON helpers
# ---------------------------
def run_cmd(cmd):
    return subprocess.check_output(cmd, text=True)

def read_file_from_rev(rev: str, path: str) -> str:
    """Return the file contents for `path` at git revision `rev` as text."""
    return run_cmd(["git", "show", f"{rev}:{path}"])

def load_json_from_rev(rev: str, path: str) -> dict:
    """Load a JSON document from a given git revision."""
    try:
        return json.loads(read_file_from_rev(rev, path))
    except subprocess.CalledProcessError:
        # If the rev doesn't have the file, return an empty KEV structure
        return {"vulnerabilities": []}

def index_by_cve(items: list) -> dict:
    """Return a dict keyed by cveID for quick lookup."""
    return {item.get("cveID"): item for item in items if "cveID" in item}

def compare_dicts(old: dict, new: dict) -> dict:
    """
    Compare two dictionaries and return a delta:
    { field: {"old": old_value, "new": new_value}, ... } for changed fields.
    """
    delta = {}
    for k in sorted(set(old.keys()).union(new.keys())):
        if old.get(k) != new.get(k):
            delta[k] = {"old": old.get(k), "new": new.get(k)}
    return delta

def et_date_str(dt=None) -> str:
    """Return date in America/New_York as YYYY-MM-DD."""
    if dt is None:
        dt_utc = datetime.datetime.utcnow().replace(tzinfo=tz.tzutc())
    else:
        dt_utc = dt.astimezone(tz.tzutc())
    dt_et = dt_utc.astimezone(tz.gettz("America/New_York"))
    return dt_et.strftime("%Y-%m-%d")

def safe_str(val) -> str:
    """Normalize values for Markdown output."""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)

def render_section(title: str, lines: list) -> str:
    """Render a Markdown section with a title and bullet lines."""
    buf = io.StringIO()
    buf.write(f"### {title}\n")
    if not lines:
        buf.write("- (none)\n\n")
