#!/usr/bin/env python3
"""
Build docs/data.json from known_exploited_vulnerabilities.json for the KEV dashboard.

Usage:
  python scripts/build_data_json.py \
    --src known_exploited_vulnerabilities.json \
    --out docs/data.json
"""

import argparse, json, os, sys

def safe_str(val):
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)

def normalize_record(v):
    # Map KEV JSON fields (source of truth) into the dashboard schema.
    # Field names referenced here match cisagov/kev-data’s KEV JSON. [1](https://dev.to/web_dev-usman/20-must-know-javascript-libraries-for-data-visualization-508d)
    return {
        "cveID": v.get("cveID", ""),
        "vendorProject": v.get("vendorProject", ""),
        "product": v.get("product", ""),
        "vulnerabilityName": v.get("vulnerabilityName", ""),
        "dateAdded": v.get("dateAdded", ""),
        "requiredAction": v.get("requiredAction", ""),
        "dueDate": v.get("dueDate", ""),
        "knownRansomwareCampaignUse": safe_str(v.get("knownRansomwareCampaignUse", "")),
        "notes": v.get("notes", ""),
        "cwes": v.get("cwes", []),
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="Path to known_exploited_vulnerabilities.json")
    ap.add_argument("--out", required=True, help="Path to write docs/data.json")
    args = ap.parse_args()

    if not os.path.isfile(args.src):
        print(f"[ERROR] Source file not found: {args.src}", file=sys.stderr)
        sys.exit(1)

    with open(args.src, "r", encoding="utf-8") as f:
        kev = json.load(f)

    vulns = kev.get("vulnerabilities", [])
    out_records = [normalize_record(v) for v in vulns]

    # Ensure output folder exists
    out_dir = os.path.dirname(args.out) or "."
    os.makedirs(out_dir, exist_ok=True)

    with open(args.out, "w", encoding="utf-8") as out:
        json.dump(out_records, out, indent=2, ensure_ascii=False)

    print(f"[OK] Wrote {len(out_records)} records to {args.out}")

if __name__ == "__main__":
    main()
