# Changelog

## [0.1.1] - 2026-10-11

### Changed (round-2 iteration after 16-item self-audit)

- **Correctness (real false-positive bug):** the expanded suite caught that standalone words `irm ` and `iex` in ordinary prose were flagged as loader IOCs (pattern `Invoke-RestMethod|irm\s` matched any mention). Patterns tightened to require attack context: `irm` must precede a URL, `iex` must be an invocation (`iex(`) — a security blog quoting bare tool names now scans CLEAN while the full chain still rates CRITICAL.
- **Correctness (+~25% test rigor):** suite grew from 16 to 21 checks; added the false-positive regression case, a corrupt-bytes file (errors=replace), an injection-lookalike string treated as inert, and a minimal-dict formatter edge.
- **Completeness:** README gained the Ethics & Legal Boundaries section (no-network, no-execution, no-retaliation, false-positive policy), the Goodhart second-order effect, and the encoded-payload limitation.

## [0.1.0] - 2026-10-11

### Added

- `fingerprint.py`: three signature families — (A) loader IOCs (download-and-execute chains, script URLs, static signature-host strings), (B) AV-suppression language, (C) SEO-stuffing scorer (Q&A headers + keyword density); per-file verdicts CLEAN/MEDIUM/HIGH/CRITICAL; directory walker for README*/md/txt; JSON + human-readable reports.
- `cli.py`: `scan` (paths/--json/--seo-threshold/--report) and `demo` subcommands with two embedded synthetic fixtures; exit 0 only when all CLEAN.
- `self_test.py`: three families — functional (8), error paths (5), extreme edges (8: 200KB padding, 2000 QA headers, injection lookalikes, 500-section timing, unicode).
- MIT LICENSE (zhengming contributors), README, initial ALIGNMENT audit.
