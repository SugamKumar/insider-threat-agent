"""
evaluate.py

Scores the agents' verdicts against the synthetic ground truth.

Every generated log entry carries a `risk_flag` label that is withheld from the
agents (see agent.format_logs_for_agent). After a pipeline run, this script
reads the structured findings (output/findings.json, falling back to parsing
the Markdown report) and treats a Critical/High/Medium rating as "flagged" and
Low as "benign", then reports a confusion matrix plus precision, recall,
accuracy and coverage.

Usage (from the project root):
    python src/evaluate.py
"""

import json
import sys
from pathlib import Path
from typing import Any

from report_parser import parse_report_threats

LOG_PATH = Path("data/employee_logs.json")
REPORT_PATH = Path("output/incident_report.md")
FINDINGS_PATH = Path("output/findings.json")
FLAGGED_LEVELS = {"Critical", "High", "Medium"}


def verdicts_from_report(report_text: str) -> dict[str, str]:
    df = parse_report_threats(report_text)
    return dict(zip(df["employee_id"], df["risk_level"])) if not df.empty else {}


def verdicts_from_findings(findings: list[dict[str, Any]]) -> dict[str, str]:
    return {f["employee_id"]: f["risk_level"] for f in findings}


def evaluate(logs: list[dict[str, Any]], report_text: str | None = None,
             verdicts: dict[str, str] | None = None) -> dict[str, Any]:
    """Compare agent risk levels with each log's ground-truth risk_flag."""
    if verdicts is None:
        verdicts = verdicts_from_report(report_text or "")

    tp = fp = tn = fn = missing = 0
    rows = []
    for log in logs:
        emp = log["employee_id"]
        truth = bool(log["risk_flag"])
        level = verdicts.get(emp)
        if level is None or level == "Unknown":
            missing += 1
            rows.append((emp, truth, "missing", None))
            continue
        predicted = level in FLAGGED_LEVELS
        tp += truth and predicted
        fp += (not truth) and predicted
        tn += (not truth) and (not predicted)
        fn += truth and (not predicted)
        rows.append((emp, truth, level, predicted == truth))

    scored = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "total": len(logs),
        "scored": scored,
        "missing": missing,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": (tp + tn) / scored if scored else 0.0,
        "coverage": scored / len(logs) if logs else 0.0,
        "rows": rows,
    }


def main() -> int:
    if not LOG_PATH.exists() or not (FINDINGS_PATH.exists() or REPORT_PATH.exists()):
        print("Need data/employee_logs.json and output/findings.json — run the pipeline first.")
        return 1

    logs = json.loads(LOG_PATH.read_text(encoding="utf-8"))
    if FINDINGS_PATH.exists():
        findings = json.loads(FINDINGS_PATH.read_text(encoding="utf-8"))["findings"]
        result = evaluate(logs, verdicts=verdicts_from_findings(findings))
        print(f"(scored from {FINDINGS_PATH})\n")
    else:
        result = evaluate(logs, REPORT_PATH.read_text(encoding="utf-8"))
        print(f"(scored from {REPORT_PATH})\n")

    print(f"{'Employee':<10} {'Truth':<11} {'Agent verdict':<14} Correct")
    for emp, truth, level, correct in result["rows"]:
        mark = "-" if correct is None else ("yes" if correct else "NO")
        print(f"{emp:<10} {'suspicious' if truth else 'benign':<11} {level:<14} {mark}")

    print(
        f"\nCoverage : {result['scored']}/{result['total']} entries rated in report"
        f"\nConfusion: TP={result['tp']} FP={result['fp']} TN={result['tn']} FN={result['fn']}"
        f"\nPrecision: {result['precision']:.0%}"
        f"\nRecall   : {result['recall']:.0%}"
        f"\nF1       : {result['f1']:.0%}"
        f"\nAccuracy : {result['accuracy']:.0%}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
