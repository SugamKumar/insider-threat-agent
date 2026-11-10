"""
guardrails.py

Output-side controls (OWASP ASI09 - Human-Agent Trust Exploitation; also the
last line of defence against ASI01 goal hijack).

The Threat Analyst must return structured findings (AnalysisResult). Before
anything is reported they pass through two checks that do not involve an LLM:

  1. Validation - every input employee must be covered exactly once, no
     invented employee IDs, technique IDs must exist in ATT&CK, risk level
     must be one of four values.

  2. Deterministic cross-check - an independent, rule-based signal score is
     computed from the raw evidence (action, hour, volume vs peers, destination,
     resource ownership, tampering markers, ticket verification). If the LLM
     rates an entry Low while the signals are elevated, or drops an entry, the
     finding is marked NEEDS HUMAN REVIEW instead of being silently accepted.

Why this matters: an injection that slips past every input filter usually
shows up as exactly this - a confident "Low" on an entry whose hard evidence
says otherwise. The cross-check cannot be talked out of its score.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from schema import DEPT_SHARES, PERSONAL_DOMAINS, SENSITIVE_SHARES, SUSPICIOUS_ACTIONS

RiskLevel = Literal["Critical", "High", "Medium", "Low"]
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SIGNAL_REVIEW_THRESHOLD = 3


# ── Structured output schema (used as CrewAI output_pydantic) ────────────────
class Finding(BaseModel):
    employee_id: str = Field(description="Employee ID exactly as in the log, e.g. EMP-0485")
    action: str = Field(description="The logged action")
    technique_id: str = Field(description="ATT&CK technique ID such as T1041, or 'None' if benign")
    technique_name: str = Field(description="ATT&CK technique name, or 'None'")
    risk_level: RiskLevel
    reasoning: str = Field(description="One or two sentences citing the evidence and tool results")


class AnalysisResult(BaseModel):
    findings: list[Finding]


# ── Deterministic evidence score ──────────────────────────────────────────────
def signal_score(log: dict[str, Any], all_logs: list[dict[str, Any]],
                 ticket_verdicts: dict[str, bool] | None = None) -> tuple[int, list[str]]:
    """Rule-based risk evidence for one entry. Independent of any LLM output."""
    score, reasons = 0, []

    if log.get("action") in SUSPICIOUS_ACTIONS:
        score += 2; reasons.append(f"suspicious action ({log.get('action')})")

    try:
        hour = datetime.fromisoformat(str(log.get("timestamp"))).hour
        if hour >= 22 or hour < 6:
            score += 1; reasons.append(f"off-hours ({hour:02d}:00)")
    except ValueError:
        pass

    peers = [int(p.get("bytes_transferred") or 0) for p in all_logs
             if p.get("department") == log.get("department") and p.get("employee_id") != log.get("employee_id")
             and isinstance(p.get("bytes_transferred"), int)]
    vol = log.get("bytes_transferred")
    if peers and isinstance(vol, int) and (avg := sum(peers) / len(peers)) > 0:
        mult = vol / avg
        if mult >= 5:
            score += 2; reasons.append(f"volume {mult:.0f}x peer average")
        elif mult >= 2:
            score += 1; reasons.append(f"volume {mult:.1f}x peer average")

    dest = str(log.get("destination") or "internal")
    if dest in PERSONAL_DOMAINS:
        score += 2; reasons.append(f"data sent to personal domain ({dest})")
    elif dest != "internal":
        score += 1; reasons.append(f"external destination ({dest})")

    resource = str(log.get("resource") or "")
    own_share = DEPT_SHARES.get(str(log.get("department")), "")
    if any(resource.startswith(s) for s in SENSITIVE_SHARES) and not resource.startswith(own_share):
        score += 3; reasons.append(f"access to another department's sensitive share ({resource})")
    elif resource.startswith("\\\\") and own_share and not resource.startswith(own_share):
        score += 1; reasons.append("access outside own department share")

    if log.get("integrity_warning"):
        score += 3; reasons.append("record tampering detected by sanitizer")

    ticket = log.get("ticket_id")
    if ticket and ticket_verdicts is not None:
        if ticket_verdicts.get(ticket):
            score -= 2; reasons.append(f"verified change ticket {ticket}")
        else:
            score += 3; reasons.append(f"cited ticket {ticket} not found in registry")

    return score, reasons


# ── Validation + cross-check ──────────────────────────────────────────────────
@dataclass
class ReviewedFinding:
    employee_id: str
    llm_risk: str
    technique_id: str
    technique_valid: bool
    signal_score: int
    signal_reasons: list[str]
    needs_review: bool
    review_reason: str = ""


@dataclass
class GuardrailReport:
    reviewed: list[ReviewedFinding] = field(default_factory=list)
    missing_employees: list[str] = field(default_factory=list)
    hallucinated_employees: list[str] = field(default_factory=list)
    duplicate_employees: list[str] = field(default_factory=list)

    @property
    def review_queue(self) -> list[ReviewedFinding]:
        return [r for r in self.reviewed if r.needs_review]

    def as_markdown(self) -> str:
        lines = ["## Guardrail Verification (deterministic, non-LLM)", "",
                 "| Employee | Agent risk | Technique | Technique valid | Evidence score | Status |",
                 "|---|---|---|---|---|---|"]
        for r in self.reviewed:
            status = f"⚠️ NEEDS HUMAN REVIEW - {r.review_reason}" if r.needs_review else "✅ consistent"
            lines.append(f"| {r.employee_id} | {r.llm_risk} | {r.technique_id} | "
                         f"{'yes' if r.technique_valid else 'NO'} | {r.signal_score} | {status} |")
        if self.hallucinated_employees:
            lines += ["", f"Discarded findings for employees not in the input: {', '.join(self.hallucinated_employees)}"]
        lines += ["", f"_{len(self.review_queue)} of {len(self.reviewed)} findings routed to human review._"]
        return "\n".join(lines)


def review_findings(result: AnalysisResult, logs: list[dict[str, Any]],
                    valid_technique_ids: set[str] | None = None,
                    ticket_verdicts: dict[str, bool] | None = None) -> GuardrailReport:
    """Validate structured findings against the input logs and the evidence score."""
    report = GuardrailReport()
    by_emp: dict[str, Finding] = {}
    for f in result.findings:
        if f.employee_id in by_emp:
            report.duplicate_employees.append(f.employee_id)
            continue
        by_emp[f.employee_id] = f

    input_ids = [l.get("employee_id") for l in logs]
    report.hallucinated_employees = [e for e in by_emp if e not in input_ids]

    for log in logs:
        emp = log.get("employee_id")
        score, reasons = signal_score(log, logs, ticket_verdicts)
        f = by_emp.get(emp)
        if f is None:
            report.missing_employees.append(emp)
            report.reviewed.append(ReviewedFinding(emp, "MISSING", "None", False, score, reasons, True,
                                                   "agent omitted this entry"))
            continue

        tid = f.technique_id.strip().upper()
        if tid in ("NONE", "N/A", ""):
            tech_ok = True
        else:
            tech_ok = bool(_TECH_RE.match(tid)) and (valid_technique_ids is None or tid in valid_technique_ids)

        review, why = False, ""
        if f.risk_level == "Low" and score >= SIGNAL_REVIEW_THRESHOLD:
            review, why = True, f"rated Low but evidence score {score} ({'; '.join(reasons)})"
        elif not tech_ok:
            review, why = True, f"technique {f.technique_id} is not a valid ATT&CK ID"
        elif log.get("integrity_warning") and f.risk_level in ("Low", "Medium"):
            review, why = True, "tampered record rated below High"

        report.reviewed.append(ReviewedFinding(emp, f.risk_level, f.technique_id, tech_ok,
                                               score, reasons, review, why))
    return report


def ticket_verdicts_for(logs: list[dict[str, Any]], registry: list[dict[str, Any]]) -> dict[str, bool]:
    """Map each cited ticket ID to whether it is approved for that employee."""
    approved = {(t["ticket_id"], t["employee_id"]) for t in registry if t.get("status") == "approved"}
    return {l["ticket_id"]: (l["ticket_id"], l.get("employee_id")) in approved
            for l in logs if l.get("ticket_id")}
