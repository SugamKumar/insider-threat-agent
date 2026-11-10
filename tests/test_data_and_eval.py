from baselines import context_rules, naive_rules, score
from evaluate import evaluate
from log_generator import generate_logs
from report_parser import parse_report_threats
from schema import validate_log_entry


def test_generator_is_reproducible_and_schema_valid():
    a = generate_logs(10, 10, "hard", seed=5)
    assert a == generate_logs(10, 10, "hard", seed=5)
    for log in a:
        assert validate_log_entry(log)[1] == []


def test_hard_mode_contains_ambiguous_scenarios():
    logs = generate_logs(10, 10, "hard", seed=1)
    scenarios = {l["scenario"] for l in logs}
    assert {"benign_approved_maintenance", "malicious_low_and_slow_email", "malicious_forged_ticket"} <= scenarios


def test_naive_rules_degrade_on_hard_data():
    easy = generate_logs(10, 40, "easy", seed=2)
    hard, tickets = generate_logs(10, 40, "hard", seed=2, return_tickets=True)
    truth = lambda logs: [l["risk_flag"] for l in logs]  # noqa: E731
    assert score(naive_rules(easy), truth(easy))["f1"] == 1.0
    assert score(naive_rules(hard), truth(hard))["f1"] < 0.6
    assert score(context_rules(hard, tickets), truth(hard))["f1"] > score(naive_rules(hard), truth(hard))["f1"]


def test_report_parser_handles_llm_formatting():
    report = ("| # | Employee | Action | Technique | Risk |\n|---|---|---|---|---|\n"
              "| 1 | **EMP\u20110485** (ryan38) | VPN | **T1133 \u2013 External Remote Services** | **Critical** |\n")
    row = parse_report_threats(report).iloc[0]
    assert row["employee_id"] == "EMP-0485"
    assert row["technique_id"] == "T1133"
    assert row["technique_name"] == "External Remote Services"
    assert row["risk_level"] == "Critical"


def test_evaluate_counts_missing_and_errors():
    logs = [{"employee_id": "EMP-0001", "risk_flag": True}, {"employee_id": "EMP-0002", "risk_flag": False}]
    res = evaluate(logs, verdicts={"EMP-0001": "High"})
    assert res["tp"] == 1 and res["missing"] == 1 and res["coverage"] == 0.5
