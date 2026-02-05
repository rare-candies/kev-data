#!/usr/bin/env python3
"""
Generate a KEV changelog entry for CHANGELOG.md, including a dedicated
'Ransomware Tag Changes' section inside the daily entry.

Usage (from GitHub Actions):
  python .github/scripts/kev_changelog.py \
    --prev HEAD~1 \
    --curr HEAD \
    --json-path known_exploited_vulnerabilities.json \
    --csv-path known_exploited_vulnerabilities.csv \
    --out CHANGELOG.md
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
def read_file_from_rev(rev: str, path: str) -> bytes:
    """Return the file contents for `path` at git revision `rev`."""
    try:
        return subprocess.check_output(["git", "show", f"{rev}:{path}"])
    except subprocess.CalledProcessError:
        # Edge case: initial run where previous rev doesn't contain the file.
        # Fall back to current HEAD version to avoid failing the workflow.
        return subprocess.check_output(["git", "show", f"HEAD:{path}"])


def load_json_from_rev(rev: str, path: str) -> dict:
    """Load a JSON document from a given git revision."""
    return json.loads(read_file_from_rev(rev, path))


def index_by_cve(items: list) -> dict:
    """Return a dict keyed by cveID for quick lookup."""
    return {item.get("cveID"): item for item in items if "cveID" in item}


def compare_dicts(old: dict, new: dict) -> dict:
    """
