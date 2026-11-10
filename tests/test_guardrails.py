from guardrails import AnalysisResult, Finding, review_findings, signal_score, ticket_verdicts_for

LOUD = {"employee_id": "EMP-9001", "department": "Finance", "action": "large_data_export",
        "timestamp": "2026-06-20T02:14:00", "files_accessed": 420, "bytes_transferred": 48_000_000,
        "destination": "gmail.com", "resource": r"\\fin-share\ledgers"}
PEER = {"employee_id": "EMP-9002", "department": "Finance", "action": "email_sent",
        "timestamp": "2026-06-20T10:00:00", "files_accessed": 2, "bytes_transferred": 1_500_000,
        "destination": "internal", "resource": r"\\fin-share\ledgers"}


def _f(emp, risk, tid="T1041"):
    return Finding(employee_id=emp, action="x", technique_id=tid, technique_name="n",
                   risk_level=risk, reasoning="r")


def test_low_rating_on_strong_evidence_goes_to_review():
    report = review_findings(AnalysisResult(findings=[_f("EMP-9001", "Low"), _f("EMP-9002", "Low", "None")]),
                             [LOUD, PEER])
    flagged = {r.employee_id for r in report.review_queue}
    assert flagged == {"EMP-9001"}


def test_missing_and_hallucinated_employees():
    report = review_findings(AnalysisResult(findings=[_f("EMP-9001", "High"), _f("EMP-1234", "High")]),
                             [LOUD, PEER])
    assert report.missing_employees == ["EMP-9002"]
    assert report.hallucinated_employees == ["EMP-1234"]


def test_invalid_technique_id_flagged():
    report = review_findings(AnalysisResult(findings=[_f("EMP-9001", "High", "T9999"), _f("EMP-9002", "Low", "None")]),
                             [LOUD, PEER], valid_technique_ids={"T1041"})
    assert report.reviewed[0].needs_review and not report.reviewed[0].technique_valid


def test_cross_department_sensitive_access_scores_high():
    log = dict(PEER, department="Engineering", action="file_read", resource=r"\\hr-share\payroll\2026")
    score, reasons = signal_score(log, [log, PEER])
    assert score >= 3 and any("sensitive share" in r for r in reasons)


def test_ticket_verification_changes_score():
    log = dict(PEER, ticket_id="CHG-1000")
    registry = [{"ticket_id": "CHG-1000", "employee_id": "EMP-9002", "status": "approved"}]
    verified = signal_score(log, [log], ticket_verdicts_for([log], registry))[0]
    forged = signal_score(log, [log], ticket_verdicts_for([log], []))[0]
    assert forged - verified == 5
