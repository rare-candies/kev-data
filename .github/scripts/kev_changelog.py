#!/usr/bin/env python3
import argparse, json, subprocess, io, datetime, sys
from dateutil import tz

def read_file_from_rev(rev, path):
    try:
        return subprocess.check_output(["git", "show", f"{rev}:{path}"])
    except subprocess.CalledProcessError:
        # If the prior commit doesn't have the file (edge case), read current
        return subprocess.check_output(["git", "show", f"HEAD:{path}"])

def load_json_from_rev(rev, path):
    return json.loads(read_file_from_rev(rev, path))

def index_by_cve(items):
    return {item["cveID"]: item for item in items}

def compare_dicts(old, new):
    delta = {}
    for k in sorted(set(old.keys()).union(new.keys())):
        if old.get(k) != new.get(k):
            delta[k] = {"old": old.get(k), "new": new.get(k)}
    return delta

def et_date_str():
    dt_utc = datetime.datetime.utcnow().replace(tzinfo=tz.tzutc())
    dt_et = dt_utc.astimezone(tz.gettz("America/New_York"))
    return dt_et.strftime("%Y-%m-%d")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prev", required=True)
    ap.add_argument("--curr", required=True)
    ap.add_argument("--json-path", required=True)
    ap.add_argument("--csv-path", required=True)
    ap.add_argument("--changelog", required=True)
    ap.add_argument("--ransomware", required=True)
    args = ap.parse_args()

    # Load JSON (CSV present for completeness; diff is based on JSON)
    prev_json = load_json_from_rev(args.prev, args.json_path)
    curr_json = load_json_from_rev(args.curr, args.json_path)

    prev = index_by_cve(prev_json["vulnerabilities"])
    curr = index_by_cve(curr_json["vulnerabilities"])

    added = sorted([cve for cve in curr if cve not in prev])
    removed = sorted([cve for cve in prev if cve not in curr])

    modified = []
    ransomware_flips = []  # only CVEs where knownRansomwareCampaignUse changed

    for cve in sorted(set(prev.keys()).intersection(curr.keys())):
        d = compare_dicts(prev[cve], curr[cve])
        if d:
            modified.append((cve, d))
            if "knownRansomwareCampaignUse" in d:
                ransomware_flips.append(
                    (cve, d["knownRansomwareCampaignUse"]["old"], d["knownRansomwareCampaignUse"]["new"])
                )

    # Commit metadata
    try:
        commit_hash = subprocess.check_output(["git", "rev-parse", args.curr]).decode().strip()
        commit_msg = subprocess.check_output(["git", "log", "-1", "--pretty=%B", args.curr]).decode().strip()
    except subprocess.CalledProcessError:
        commit_hash = "HEAD"
        commit_msg = "KEV update"

    # Build entry for CHANGELOG.md
    date_str = et_date_str()
    entry = io.StringIO()
    entry.write(f"## {date_str} ([Commit {commit_hash[:7]}](https://github.com/cisagov/kev-data))\n")
    entry.write(f"**Source:** {commit_msg}\n\n")

    # Optional sub-section to highlight ransomware flips within the daily entry
    entry.write("### Ransomware tag changes in this update\n")
    if not ransomware_flips:
        entry.write("- (none)\n\n")
    else:
        for cve, old, new in ransomware_flips:
            entry.write(f"- {cve}: `knownRansomwareCampaignUse` {old} → {new}\n")
        entry.write("\n")

    # Added
    entry.write("### Added\n")
    if not added:
        entry.write("- (none)\n\n")
    else:
        for cve in added:
            v = curr[cve]
            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            name = v.get("vulnerabilityName", "")
            entry.write(f"- {cve} — {vendor} {product} ({name})\n")
        entry.write("\n")

    # Modified w/ field-level diffs
    entry.write("### Modified\n")
    if not modified:
        entry.write("- (none)\n\n")
    else:
        for cve, delta in modified:
            entry.write(f"- {cve}\n")
            for k, v in delta.items():
                entry.write(f"  - `{k}`: {v['old']} → {v['new']}\n")
        entry.write("\n")

    # Removed
    entry.write("### Removed\n")
    if not removed:
        entry.write("- (none)\n\n")
    else:
        for cve in removed:
            entry.write(f"- {cve}\n")
        entry.write("\n")

    entry.write("### Files\n- `known_exploited_vulnerabilities.json`\n- `known_exploited_vulnerabilities.csv`\n\n")

    # Append to CHANGELOG.md
    with open(args.changelog, "a", encoding="utf-8") as fp:
        fp.write(entry.getvalue())

    # Append to ransomware_changes.md (dedicated file)
    ransom_entry = io.StringIO()
    ransom_entry.write(f"## {date_str} ([Commit {commit_hash[:7]}](https://github.com/cisagov/kev-data))\n")
    ransom_entry.write(f"**Source:** {commit_msg}\n\n")
    ransom_entry.write("### Ransomware tag changes\n")
    if not ransomware_flips:
        ransom_entry.write("- (none)\n\n")
    else:
        for cve, old, new in ransomware_flips:
            ransom_entry.write(f"- {cve}: `{old}` → `{new}`\n")
        ransom_entry.write("\n")

    with open(args.ransomware, "a", encoding="utf-8") as rp:
        rp.write(ransom_entry.getvalue())

if __name__ == "__main__":
    main()
