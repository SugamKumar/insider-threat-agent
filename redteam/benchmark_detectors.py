"""
benchmark_detectors.py

Offline, deterministic benchmark of the input-side controls — no LLM calls.

Measures, over the red-team corpus:
  * v1 detection rate (original 13-phrase substring filter)
  * v2 detection rate (normalising, word-bounded detector)
  * layered rate for direct injection: payload planted in the `location`
    field and passed through schema validation + v2
  * false-positive rate on held-out benign values and, if
    data/mitre_attack.json is present, on all ATT&CK technique/mitigation
    descriptions (the text the RAG layer must pass through untouched)

Usage (from the project root):
    python redteam/benchmark_detectors.py
Writes redteam/results/detector_benchmark.md
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from redteam.corpus import ATTACKS, BENIGN  # noqa: E402
from sanitizer import detect_injection, detect_v1, sanitize_log_entry, SANITIZED_PLACEHOLDER  # noqa: E402
from schema import TAMPER_MARKER  # noqa: E402

RESULTS_DIR = ROOT / "redteam" / "results"
MITRE_PATH = ROOT / "data" / "mitre_attack.json"

_SAMPLE_LOG = {
    "employee_id": "EMP-9001", "username": "jdoe", "department": "Finance",
    "action": "large_data_export", "timestamp": "2026-06-20T02:14:00",
    "files_accessed": 420, "bytes_transferred": 48_000_000,
    "source_ip": "203.0.113.50", "location": "Chicago",
}


def blocked_in_log_field(text: str) -> bool:
    """Plant the payload in `location` and check whether it survives sanitization."""
    cleaned = sanitize_log_entry(dict(_SAMPLE_LOG, location=text))
    return cleaned["location"] in (SANITIZED_PLACEHOLDER, TAMPER_MARKER)


def attck_texts() -> list[str]:
    if not MITRE_PATH.exists():
        return []
    bundle = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    return [
        f"{o.get('name', '')}\n{o.get('description', '')}"
        for o in bundle.get("objects", [])
        if o.get("type") in ("attack-pattern", "course-of-action")
        and not o.get("revoked") and not o.get("x_mitre_deprecated")
    ]


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({n / d:.0%})" if d else "n/a"


def run() -> str:
    by_tech: dict[str, list[tuple[bool, bool, bool]]] = defaultdict(list)
    misses_v2 = []
    for a in ATTACKS:
        v1 = detect_v1(a["text"])
        v2 = detect_injection(a["text"]).flagged
        layered = blocked_in_log_field(a["text"])
        by_tech[a["technique"]].append((v1, v2, layered))
        if not v2:
            misses_v2.append(a)

    lines = ["# Detector benchmark (offline, deterministic)", "",
             "| Technique | n | v1 detected | v2 detected | Log-field: schema + v2 blocked |",
             "|---|---|---|---|---|"]
    tot = [0, 0, 0, 0]
    ex_tot = [0, 0, 0, 0]  # excluding semantic deception
    for tech, rows in by_tech.items():
        n = len(rows)
        s1, s2, s3 = (sum(r[i] for r in rows) for i in range(3))
        lines.append(f"| {tech} | {n} | {s1} | {s2} | {s3} |")
        for agg in (tot, ex_tot) if tech != "semantic_deception" else (tot,):
            agg[0] += n; agg[1] += s1; agg[2] += s2; agg[3] += s3
    lines.append(f"| **All instruction-style attacks** | {ex_tot[0]} | {pct(ex_tot[1], ex_tot[0])} | "
                 f"{pct(ex_tot[2], ex_tot[0])} | {pct(ex_tot[3], ex_tot[0])} |")
    lines.append(f"| **All attacks incl. semantic deception** | {tot[0]} | {pct(tot[1], tot[0])} | "
                 f"{pct(tot[2], tot[0])} | {pct(tot[3], tot[0])} |")

    benign_fp1 = sum(detect_v1(b["text"]) for b in BENIGN)
    benign_fp2 = sum(detect_injection(b["text"]).flagged for b in BENIGN)
    attck = attck_texts()
    attck_fp1 = sum(detect_v1(t) for t in attck)
    attck_fp2 = sum(detect_injection(t).flagged for t in attck)

    lines += ["", "## False positives", "", "| Benign set | n | v1 flagged | v2 flagged |", "|---|---|---|---|",
              f"| Held-out log/API values | {len(BENIGN)} | {pct(benign_fp1, len(BENIGN))} | {pct(benign_fp2, len(BENIGN))} |"]
    if attck:
        lines.append(f"| ATT&CK technique + mitigation descriptions | {len(attck)} | "
                     f"{pct(attck_fp1, len(attck))} | {pct(attck_fp2, len(attck))} |")
    else:
        lines.append("| ATT&CK descriptions | — | data/mitre_attack.json not found | |")

    lines += ["", "## Payloads v2 does not catch", "",
              "These are what the downstream controls (spotlighting, ticket verification, "
              "deterministic guardrail) exist for. Measure them end-to-end with `run_attacks.py`.", ""]
    lines += [f"- `{a['id']}` ({a['technique']}): {a['text'][:90]!r}" for a in misses_v2]
    lines += ["", "_Note: v2's rules were tuned to avoid false positives on the ATT&CK corpus; "
              "the held-out benign set and the attack corpus were not used for tuning._"]
    return "\n".join(lines)


if __name__ == "__main__":
    report = run()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "detector_benchmark.md").write_text(report + "\n", encoding="utf-8")
    print(report)
