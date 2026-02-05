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
    else:
        for line in lines:
            buf.write(f"- {line}\n")
        buf.write("\n")
    return buf.getvalue()

def commit_message(rev: str) -> str:
    try:
        return run_cmd(["git", "log", "-1", "--pretty=%B", rev]).strip()
    except subprocess.CalledProcessError:
        return "KEV update"

def short_sha(rev: str) -> str:
    try:
        sha = run_cmd(["git", "rev-parse", rev]).strip()
        return sha[:7], sha
    except subprocess.CalledProcessError:
        return "HEAD", "HEAD"

# ---------------------------
# Diff helpers
# ---------------------------
def compute_diff(prev_json: dict, curr_json: dict):
    """Compute Added/Removed/Modified and ransomware flips from two KEV JSONs."""
    prev_items = prev_json.get("vulnerabilities", [])
    curr_items = curr_json.get("vulnerabilities", [])
    prev = index_by_cve(prev_items)
    curr = index_by_cve(curr_items)

    added_cves = sorted([cve for cve in curr.keys() if cve not in prev])
    removed_cves = sorted([cve for cve in prev.keys() if cve not in curr])

    modified_deltas = []  # list of (cve, delta_dict)
    ransomware_flips = []  # list of (cve, old_value, new_value)

    for cve in sorted(set(prev.keys()).intersection(curr.keys())):
        delta = compare_dicts(prev[cve], curr[cve])
        if delta:
            modified_deltas.append((cve, delta))
            if "knownRansomwareCampaignUse" in delta:
                r_old = safe_str(delta["knownRansomwareCampaignUse"]["old"])
                r_new = safe_str(delta["knownRansomwareCampaignUse"]["new"])
                ransomware_flips.append((cve, r_old, r_new))

    return added_cves, removed_cves, modified_deltas, ransomware_flips, curr

def render_modified_block(modified_deltas):
    """Render the Modified section with field-level diffs."""
    if not modified_deltas:
        return render_section("Modified", [])
    buf = io.StringIO()
    buf.write("### Modified\n")
    for cve, delta in modified_deltas:
        buf.write(f"- {cve}\n")
        for field, values in delta.items():
            old_val = safe_str(values["old"])
            new_val = safe_str(values["new"])
            buf.write(f"  - `{field}`: {old_val} → {new_val}\n")
    buf.write("\n")
    return buf.getvalue()

# ---------------------------
# 14-day commit scan
# ---------------------------
def commits_touching_file_since(days: int, path: str) -> list:
    """
    Return a list of SHAs for commits within the last `days` that touched `path`.
    Ordered from oldest to newest for clean pairwise diffing.
    """
    since_arg = f"{days}.days"
    # --follow to track renames; use --pretty to capture SHA; --reverse for chronological order
    log_cmd = ["git", "log", f"--since={since_arg}", "--pretty=%H", "--reverse", "--", path]
    try:
        out = run_cmd(log_cmd).strip()
        return [line for line in out.splitlines() if line]
    except subprocess.CalledProcessError:
        return []

def aggregate_14_day_summary(days: int, json_path: str):
    """
    Walk commits (last `days`) touching KEV JSON, diff adjacent commits,
    and build aggregate lists for Added / Removed / Modified / Ransomware flips.
    """
    shas = commits_touching_file_since(days, json_path)
    summary_added = []
    summary_removed = []
    summary_modified = []
    summary_ransom_flips = []

    # Pairwise diff across consecutive commits
    for i in range(1, len(shas)):
        prev_rev = shas[i - 1]
        curr_rev = shas[i]
        prev_json = load_json_from_rev(prev_rev, json_path)
        curr_json = load_json_from_rev(curr_rev, json_path)
        added, removed, modified, flips, _ = compute_diff(prev_json, curr_json)

        # Accumulate with de-duplication (keep order)
        for cve in added:
            if cve not in summary_added:
                summary_added.append(cve)
        for cve in removed:
            if cve not in summary_removed:
                summary_removed.append(cve)
        for item in modified:
            if item not in summary_modified:
                summary_modified.append(item)
        for flip in flips:
            if flip not in summary_ransom_flips:
                summary_ransom_flips.append(flip)

    return summary_added, summary_removed, summary_modified, summary_ransom_flips

# ---------------------------
# Main
# ---------------------------
def main():
    ap = argparse.ArgumentParser(description="Generate KEV CHANGELOG.md entry with live and 14-day summaries.")
    ap.add_argument("--prev", required=True, help="Previous git rev (e.g., HEAD~1)")
    ap.add_argument("--curr", required=True, help="Current git rev (e.g., HEAD)")
    ap.add_argument("--json-path", required=True, help="Path to KEV JSON file")
    ap.add_argument("--csv-path", required=True, help="Path to KEV CSV file")
    ap.add_argument("--out", required=True, help="CHANGELOG.md output path")
    ap.add_argument("--days", type=int, default=14, help="Number of days for rolling summary")
    args = ap.parse_args()

    # --- Live Update (prev vs curr) ---
    prev_json = load_json_from_rev(args.prev, args.json_path)
    curr_json = load_json_from_rev(args.curr, args.json_path)
    added, removed, modified, flips, curr_index = compute_diff(prev_json, curr_json)

    # Commit metadata for current entry
    short, full_sha = short_sha(args.curr)
    msg = commit_message(args.curr)
    date_str = et_date_str()

    entry = io.StringIO()
    entry.write(f"## {date_str} ([Commit {short}](https://github.com/cisagov/kev-data))\n")
    entry.write(f"**Source:** {msg}\n\n")

    # Ransomware Tag Changes (live)
    r_lines = [f"{cve}: `knownRansomwareCampaignUse` {old} → {new}" for (cve, old, new) in flips]
    entry.write(render_section("Ransomware Tag Changes (Live Update)", r_lines))

    # Added (live)
    a_lines = []
    for cve in added:
        v = curr_index.get(cve, {})
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        name = v.get("vulnerabilityName", "")
        a_lines.append(f"{cve} — {vendor} {product} ({name})")
    entry.write(render_section("Added (Live Update)", a_lines))

    # Modified (live)
    entry.write(render_modified_block(modified))

    # Removed (live)
    entry.write(render_section("Removed (Live Update)", removed))

    # Files changed (clarity)
    entry.write("### Files\n- `known_exploited_vulnerabilities.json`\n- `known_exploited_vulnerabilities.csv`\n\n")

    # --- Last 14 Days Summary (rolling) ---
    days = args.days
    sum_added, sum_removed, sum_modified, sum_flips = aggregate_14_day_summary(days, args.json_path)

    entry.write(f"### Last {days} Days Summary\n")
    # Ransomware flips (summary)
    if not sum_flips:
        entry.write("- Ransomware Tag Changes: (none)\n")
    else:
        entry.write("- **Ransomware Tag Changes:**\n")
        for (cve, old, new) in sum_flips:
            entry.write(f"  - {cve}: {old} → {new}\n")
    entry.write("\n")

    # Added (summary)
    if not sum_added:
        entry.write("- Added: (none)\n")
    else:
        entry.write("- **Added:**\n")
        for cve in sum_added:
            entry.write(f"  - {cve}\n")
    entry.write("\n")

    # Modified (summary)
    if not sum_modified:
        entry.write("- Modified: (none)\n")
    else:
        entry.write("- **Modified (field-level changes exist):**\n")
        for cve, delta in sum_modified:
            entry.write(f"  - {cve}\n")
            # Optional: suppress noisy fields; here we show all
            for k, v in delta.items():
                entry.write(f"    - {k}: {safe_str(v['old'])} → {safe_str(v['new'])}\n")
    entry.write("\n")

    # Removed (summary)
    if not sum_removed:
        entry.write("- Removed: (none)\n\n")
    else:
        entry.write("- **Removed:**\n")
        for cve in sum_removed:
            entry.write(f"  - {cve}\n")
        entry.write("\n")

    entry.write("---\n\n")

    # Append to CHANGELOG.md
    with open(args.out, "a", encoding="utf-8") as fp:
        fp.write(entry.getvalue())


if __name__ == "__main__":
    main()
