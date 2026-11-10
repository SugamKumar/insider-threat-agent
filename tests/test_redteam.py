from redteam.corpus import ATTACKS
from redteam.run_attacks import run_case


def _run(attack_id, vector, cfg, scenario):
    attack = next(a for a in ATTACKS if a["id"] == attack_id)
    return run_case(attack, vector, cfg, "worst-case", use_real_rag=False, scenario=scenario)


def test_undefended_pipeline_is_hijacked_on_every_vector():
    for vector in ("log_field", "tool_output", "rag"):
        assert _run("plain-01", vector, "off", "loud")["undetected"], vector


def test_defenses_block_instruction_style_attacks():
    for vector in ("log_field", "tool_output", "rag"):
        rec = _run("homoglyph-01", vector, "on", "quiet")
        assert rec["delivered"] and not rec["exposed"] and not rec["hijacked"], vector


def test_guardrail_catches_deception_on_loud_target():
    rec = _run("deceive-01", "tool_output", "on", "loud")
    assert rec["hijacked"] and rec["caught_by_guardrail"] and not rec["undetected"]


def test_known_residual_risk_quiet_target_semantic_deception():
    # Documented limitation: plausible lies in API data about a low-evidence insider
    rec = _run("deceive-01", "tool_output", "on", "quiet")
    assert rec["undetected"]
