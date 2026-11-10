"""
baselines.py

Non-LLM detectors the agents must beat to justify their cost:

  naive_rules        - a typical SIEM correlation rule: suspicious action name,
                       off-hours activity, or a large transfer.
  context_rules      - the guardrail's evidence score (adds destination,
                       resource ownership and ticket verification) ≥ threshold.
  isolation_forest   - unsupervised anomaly detection on numeric features
                       (bytes, files, hour, off-hours, suspicious-action flag).

All take a list of log dicts and return a list of booleans (True = flagged).
"""

from datetime import datetime
from typing import Any

from guardrails import SIGNAL_REVIEW_THRESHOLD, signal_score, ticket_verdicts_for
from schema import SUSPICIOUS_ACTIONS

LARGE_TRANSFER_BYTES = 10_000_000


def _hour(log: dict[str, Any]) -> int:
    try:
        return datetime.fromisoformat(str(log["timestamp"])).hour
    except (KeyError, ValueError):
        return 12


def naive_rules(logs: list[dict[str, Any]]) -> list[bool]:
    out = []
    for log in logs:
        h = _hour(log)
        out.append(
            log.get("action") in SUSPICIOUS_ACTIONS
            or h >= 22 or h < 6
            or int(log.get("bytes_transferred") or 0) >= LARGE_TRANSFER_BYTES
        )
    return out


def context_rules(logs: list[dict[str, Any]], tickets: list[dict[str, Any]]) -> list[bool]:
    verdicts = ticket_verdicts_for(logs, tickets)
    return [signal_score(l, logs, verdicts)[0] >= SIGNAL_REVIEW_THRESHOLD for l in logs]


def isolation_forest(logs: list[dict[str, Any]], contamination: float | str = "auto",
                     seed: int = 0) -> list[bool]:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    X = np.array([[
        np.log1p(int(l.get("bytes_transferred") or 0)),
        np.log1p(int(l.get("files_accessed") or 0)),
        _hour(l),
        float(_hour(l) >= 22 or _hour(l) < 6),
        float(l.get("action") in SUSPICIOUS_ACTIONS),
    ] for l in logs])
    model = IsolationForest(contamination=contamination, random_state=seed).fit(X)
    return [p == -1 for p in model.predict(X)]


def score(pred: list[bool], truth: list[bool]) -> dict[str, float]:
    tp = sum(p and t for p, t in zip(pred, truth))
    fp = sum(p and not t for p, t in zip(pred, truth))
    fn = sum(t and not p for p, t in zip(pred, truth))
    tn = sum(not p and not t for p, t in zip(pred, truth))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1,
            "accuracy": (tp + tn) / len(truth) if truth else 0.0,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}
