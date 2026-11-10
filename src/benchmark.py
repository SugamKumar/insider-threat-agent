"""
benchmark.py

Compares the non-LLM baselines on easy vs hard synthetic data, and adds the
LLM pipeline's score for the current dataset if output/findings.json exists.

Usage (from the project root):
    python src/benchmark.py                 # baselines only, 5 seeds x 50 entries (20% malicious) per difficulty
    python src/benchmark.py --with-llm      # also score the last pipeline run on data/employee_logs.json

Writes output/benchmark_results.md
"""

import argparse
import json
from pathlib import Path
from statistics import mean

from baselines import context_rules, isolation_forest, naive_rules, score
from evaluate import evaluate, verdicts_from_findings
from log_generator import generate_logs

OUT = Path("output/benchmark_results.md")
SEEDS = [11, 22, 33, 44, 55]


def run_baselines(difficulty: str, n_sus: int = 10, n_norm: int = 40) -> dict[str, dict[str, float]]:
    agg: dict[str, list[dict[str, float]]] = {"Naive SIEM rules": [], "Isolation Forest (true prevalence)": [],
                                               "Context-aware rules": []}
    for seed in SEEDS:
        logs, tickets = generate_logs(n_sus, n_norm, difficulty, seed=seed, return_tickets=True)
        truth = [bool(l["risk_flag"]) for l in logs]
        agg["Naive SIEM rules"].append(score(naive_rules(logs), truth))
        agg["Isolation Forest (true prevalence)"].append(score(isolation_forest(logs, contamination=n_sus / (n_sus + n_norm), seed=seed), truth))
        agg["Context-aware rules"].append(score(context_rules(logs, tickets), truth))
    return {name: {k: mean(r[k] for r in runs) for k in ("precision", "recall", "f1", "accuracy")}
            for name, runs in agg.items()}


def llm_row() -> tuple[str, dict[str, float]] | None:
    logs_p, findings_p = Path("data/employee_logs.json"), Path("output/findings.json")
    if not (logs_p.exists() and findings_p.exists()):
        return None
    logs = json.loads(logs_p.read_text(encoding="utf-8"))
    run = json.loads(findings_p.read_text(encoding="utf-8"))
    res = evaluate(logs, verdicts=verdicts_from_findings(run["findings"]))
    difficulty = "hard" if any(str(l.get("scenario", "")).startswith(("benign_", "malicious_")) for l in logs) else "easy"
    label = f"LLM agents ({run.get('model', '?')}, n={res['scored']}, {difficulty} data)"
    return label, res


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-llm", action="store_true")
    args = parser.parse_args()

    lines = ["# Detection benchmark", "",
             f"Baselines averaged over {len(SEEDS)} seeded datasets of 50 entries at 20% prevalence "
             "(10 malicious / 40 benign).", ""]
    for difficulty in ("easy", "hard"):
        lines += [f"## {difficulty.capitalize()} data", "",
                  "| Detector | Precision | Recall | F1 | Accuracy |", "|---|---|---|---|---|"]
        for name, m in run_baselines(difficulty).items():
            lines.append(f"| {name} | {m['precision']:.0%} | {m['recall']:.0%} | {m['f1']:.0%} | {m['accuracy']:.0%} |")
        lines.append("")

    if args.with_llm:
        row = llm_row()
        if row:
            label, m = row
            lines += ["## LLM pipeline (last run)", "", "| Detector | Precision | Recall | F1 | Accuracy |",
                      "|---|---|---|---|---|",
                      f"| {label} | {m['precision']:.0%} | {m['recall']:.0%} | {m['f1']:.0%} | {m['accuracy']:.0%} |", ""]
        else:
            lines += ["_No output/findings.json found — run the pipeline first._", ""]

    lines += ["_Easy data is cleanly separable by design; hard data contains benign-but-unusual and "
              "malicious-but-quiet scenarios (see src/log_generator.py)._"]
    report = "\n".join(lines)
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(report + "\n", encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
