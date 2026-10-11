# Alignment Audit (Rules 85-100 / 16 items) — scam-readme-fingerprint

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | Safety/Ethics section | PASS | Dedicated "Ethics & Legal Boundaries" section: no-network, no-execution, no-retaliation, false-positive policy — four explicit boundaries. |
| 2 | Privacy/keys | PASS | No keys/tokens/real names/emails; all example hosts are example.test or the one public static IOC string. |
| 3 | Copyright boundary | PASS | Zero text copied from the source scam repo — the demo fixture is synthetic prose reproducing the pattern, not the artifact; MIT LICENSE present. |
| 4 | Fact-check numbers | PASS | 21/21 checks + demo measured, repro commands given; campaign observations qualitative, threshold guidance marked [estimated]. |
| 5 | Confidence grading | PASS | README: High (85%) and Medium (60%) [estimated] labels with basis. |
| 6 | Minimal Fallback | PASS | "Minimal Fallback (PLAN B)": single grep -riE one-liner; JSON schema is the contract. |
| 7 | Quickstart timing | PASS | Quickstart labelled ~2 min, staged (self-test → demo → own clones). |
| 8 | Conflict arbitration | PASS | "Design Trade-offs": zero side effects > recall > nuance, with the determinism rationale. |
| 9 | Changelog ≥2 iterations | PASS | v0.1.0 → v0.1.1 documents round-2 revision (16→21 tests, real false-positive bug fixed). |
| 10 | Exemption (session rule) | N/A | Session-level governance item; static repo not applicable. |
| 11 | Knowledge cutoff | PASS | Campaign context dated "as of 2026-10-11"; README footer repeats the date. |
| 12 | Explicit assumptions | PASS | `[Core Assumptions]` lists 4 premises (template reuse, operator-cloned targets, static+human over ML, proportionate IOC disclosure). |
| 13 | Three-part self-test | PASS | functional (8) + error paths (5) + extreme edges (8) = 21/21 PASS. |
| 14 | Socratic FAQ | PASS | "When NOT to use this?" — not sole malware defense, not for illegally obtained content, no auto-takedown. |
| 15 | Pareto iteration | PASS | Round 2: test count +~31% (16→21), one real false-positive detection bug fixed; CHANGELOG-traceable. |
| 16 | ≤60-word opening | PASS | First paragraph is 59 words with a judgment sentence ("nothing is ever fetched or run"). |

Additional: **Second-order effects** — "Limits & Second-order Effects" covers template drift, encoded-payload blind spot, Goodhart optimization, and flagging of legitimate security content.
