"""scam-readme-fingerprint: static fingerprint auditor for malicious READMEs.

DEFENSIVE TOOL. Detects the "README-as-attack-payload" pattern via three
signature families, using static string matching ONLY:
  A. loader IOCs      - download-and-execute chains (irm|iex, curl|sh,
                        powershell -enc) and configured signature host strings
  B. AV suppression   - text that instructs users to weaken their antivirus
  C. SEO stuffing     - search-engine-bait structure (Q&A piles, keyword spam)

Hard boundaries (see README "Ethics & Legal Boundaries"):
  - zero network access (no socket, no urllib import anywhere)
  - IOC strings are static signatures for matching, never fetched or contacted
  - reports describe files; it never modifies, executes, or quarantines them
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

# ---------------------------------------------------------------- signatures

# Family A: download-and-execute loader patterns (static regex, no evaluation)
LOADER_PATTERNS = [
    (r"Invoke-Expression", "PowerShell Invoke-Expression"),
    (r"\biex\s*\(", "PowerShell iex invocation"),
    (r"\birm\s+['\"]?https?://", "PowerShell irm with remote URL"),
    (r"curl[^|\n]*\|\s*(ba)?sh", "curl piped to shell"),
    (r"wget[^|\n]*\|\s*(ba)?sh", "wget piped to shell"),
    (r"powershell[^|\n]*-enc(od EDCommand)?\s", "powershell -enc encoded command"),
    (r"(irm|iwr|curl|wget)[^;\n]*;\s*(iex|Invoke-Expression)", "fetch-then-execute chain"),
    (r"https?://\S+\.(ps1|bat|cmd|vbs)\b", "direct script-file URL"),
    (r"\bLoader\.ps1\b|\bloader\.ps1\b", "generic loader script name"),
]
# Family A: configured signature hosts (static strings; NEVER contacted)
SIGNATURE_HOSTS = [
    "ps-ps.cc",  # observed loader host in 2026 batch-abuse campaigns (static IOC string)
]

# Family B: antivirus-suppression language
AV_SUPPRESSION_PATTERNS = [
    (r"disable\s+(your\s+)?(real[- ]time\s+)?(antivirus|antivirus protection|windows defender|defender)",
     "instructs disabling AV/real-time protection"),
    (r"turn\s+off\s+(windows\s+)?defender", "instructs turning off Defender"),
    (r"add\s+an?\s+exclusion", "instructs adding AV exclusion"),
    (r"(antivirus|defender|windows\s+smartscreen)\s+(may|might|will)\s+(flag|block|warn)",
     "pre-emptively reframes AV warnings as false positives"),
    (r"allow\s+this\s+app\s+(through|in)", "instructs allowing app through security prompt"),
    (r"temporarily\s+(disable|turn\s+off)\s+(your\s+)?(antivirus|protection)", "temporary-disable instruction"),
]

# Family C: SEO stuffing heuristics
SEO_QA_HEADER_RE = re.compile(r"^\s*#{2,4}\s.*(what|how|why|is|are|do|can|best|download|free)\b.*\?", re.I)
SEO_KEYWORDS = ["download", "free", "crack", "license key", "activation", "full version",
                "windows 10", "windows 11", "2024", "2025", "2026", "official site", "latest version"]


def scan_text(text: str, seo_threshold: int = 6) -> Dict:
    """Scan one document's text. Returns {family: [hits], score, verdict}."""
    low = text.lower()

    loaders = []
    for pat, label in LOADER_PATTERNS:
        m = re.search(pat, text, re.I)
        if m:
            loaders.append({"rule": label, "match": m.group(0)[:80]})
    for host in SIGNATURE_HOSTS:
        if host in low:
            loaders.append({"rule": "signature host (static IOC string)", "match": host})

    av = [{"rule": label, "match": m.group(0)[:80]}
          for pat, label in AV_SUPPRESSION_PATTERNS
          for m in [re.search(pat, text, re.I)] if m]

    qa_headers = [ln.strip() for ln in text.splitlines() if SEO_QA_HEADER_RE.match(ln)]
    kw_hits = sorted({k for k in SEO_KEYWORDS if k in low})
    stuffing_score = len(qa_headers) + 2 * len(kw_hits)
    seo = {"qa_header_count": len(qa_headers), "keyword_hits": kw_hits,
           "stuffing_score": stuffing_score,
           "threshold": seo_threshold,
           "hit": stuffing_score >= seo_threshold}

    if loaders:
        verdict = "CRITICAL"
    elif av:
        verdict = "HIGH"
    elif seo["hit"]:
        verdict = "MEDIUM"
    else:
        verdict = "CLEAN"
    return {"verdict": verdict,
            "family_A_loader_ioc": loaders,
            "family_B_av_suppression": av,
            "family_C_seo_stuffing": seo}


def scan_file(path: str, seo_threshold: int = 6) -> Dict:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    result = scan_text(text, seo_threshold)
    result["path"] = path
    result["bytes"] = len(text.encode("utf-8", errors="replace"))
    return result


def scan_paths(paths: List[str], seo_threshold: int = 6) -> Dict:
    """Scan files or directories (README*/*.md/*.txt). Never follows symlinks out."""
    results = []
    import os
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    if fn.lower().startswith("readme") or fn.lower().endswith((".md", ".txt")):
                        results.append(scan_file(os.path.join(root, fn), seo_threshold))
        elif os.path.isfile(p):
            results.append(scan_file(p, seo_threshold))
        else:
            results.append({"path": p, "verdict": "NOT_FOUND", "error": "path does not exist"})
    flagged = [r for r in results if r.get("verdict") in ("CRITICAL", "HIGH", "MEDIUM")]
    overall = "CRITICAL" if any(r.get("verdict") == "CRITICAL" for r in results) else \
              "HIGH" if any(r.get("verdict") == "HIGH" for r in results) else \
              "MEDIUM" if any(r.get("verdict") == "MEDIUM" for r in results) else "CLEAN"
    return {"tool": "scam-readme-fingerprint", "scanned": len(results),
            "flagged": len(flagged), "overall": overall,
            "verdicts": {r.get("path", "?"): r.get("verdict") for r in results},
            "results": results}


def format_report(report: Dict) -> str:
    lines = ["scam-readme-fingerprint: scanned=%d flagged=%d overall=%s"
             % (report["scanned"], report["flagged"], report["overall"])]
    for r in report["results"]:
        v = r.get("verdict", "?")
        lines.append("  [%s] %s" % (v, r.get("path", "?")))
        for h in r.get("family_A_loader_ioc", []):
            lines.append("      A/loader: %s -> %r" % (h["rule"], h["match"]))
        for h in r.get("family_B_av_suppression", []):
            lines.append("      B/av:     %s -> %r" % (h["rule"], h["match"]))
        s = r.get("family_C_seo_stuffing")
        if s and (s["hit"] or s["qa_header_count"]):
            lines.append("      C/seo:    score=%d (threshold %d) qa_headers=%d keywords=%s"
                         % (s["stuffing_score"], s["threshold"], s["qa_header_count"], s["keyword_hits"][:6]))
    return "\n".join(lines)
