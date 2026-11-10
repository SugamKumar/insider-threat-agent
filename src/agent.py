"""
agent.py

Multi-agent insider threat detection pipeline (CrewAI).

    raw logs
      │  schema validation + injection detection      (sanitizer.py / schema.py)
      ▼
    Threat Analyst  ── tools: IP reputation, geolocation, volume anomaly,
      │                ticket verification, ATT&CK RAG search + lookup
      │  structured findings (AnalysisResult JSON)
      ▼
    Guardrail (no LLM): coverage, valid ATT&CK IDs, evidence cross-check  (guardrails.py)
      │  validated findings + human-review queue
      ▼
    IR Advisor ── tool: ATT&CK mitigation RAG search
      ▼
    Report Writer ── no tools
      ▼
    output/incident_report.md + output/findings.json

Untrusted data (logs, tool output, retrieved documents) is wrapped in
delimiters and agents are told it is data, never instructions ("spotlighting").
Every control can be toggled through config.DefenseConfig for red-teaming.
"""
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

import json
import os
import re
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from crewai import LLM, Agent, Crew, Process, Task

import config
import threat_intel as ti
from config import DefenseConfig
from guardrails import AnalysisResult, GuardrailReport, review_findings, ticket_verdicts_for
from logging_utils import get_audit_logger
from prompting import SECURITY_RULES, format_logs_for_agent
from sanitizer import sanitize_logs
from tools import (
    check_data_volume_anomaly,
    check_ip_reputation,
    geolocate_ip,
    lookup_mitre_technique,
    search_mitre_mitigations,
    search_mitre_techniques,
    verify_change_ticket,
)

load_dotenv()

# ── Patch: Groq compatibility + retry on rate limits ──────────────────────────
import litellm  # noqa: E402

litellm.drop_params = True
_original_completion = litellm.completion


def _patched_completion(*args, **kwargs):
    for msg in kwargs.get("messages", []):
        msg.pop("cache_breakpoint", None)
        msg.pop("cache_control", None)

    # Strip <|channel|> token leakage from tool call names (gpt-oss-120b / Groq bug)
    for tool in kwargs.get("tools", []) or []:
        if "function" in tool and "name" in tool["function"]:
            tool["function"]["name"] = tool["function"]["name"].split("<")[0].strip()

    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            return _original_completion(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            err = str(e)
            last = attempt == max_attempts - 1
            if "Request too large" in err:
                # Waiting cannot shrink a single oversized request - fail with a clear hint
                raise RuntimeError(
                    "A single LLM request exceeded the provider's tokens-per-minute limit. "
                    "Lower ANALYSIS_BATCH_SIZE (e.g. set ANALYSIS_BATCH_SIZE=2) and re-run.") from e
            if "rate_limit_exceeded" in err and "tokens per day" in err.replace("\n", " "):
                # Daily quota: retrying within this run is pointless - stop with a clear message
                hint = re.search(r"try again in ((?:\d+h)?(?:\d+m)?[\d.]+s)", err)
                raise RuntimeError(
                    "Groq daily token quota (TPD) for this model is used up"
                    + (f"; it refills in about {hint.group(1)}" if hint else "")
                    + ". Re-run later, use fewer log entries, or set GROQ_MODEL in .env to another model.") from e
            if "rate_limit_exceeded" in err and not last:
                hint = re.search(r"try again in (?:(\d+)m)?([\d.]+)s", err)
                wait = (int(hint.group(1) or 0) * 60 + float(hint.group(2)) + 2) if hint else 20 * (attempt + 1)
                print(f"[Rate limit] Waiting {wait:.0f}s before retry {attempt + 2}/{max_attempts}...")
                time.sleep(wait)
            elif "output_parse_failed" in err and not last:
                # Groq could not parse the model's output (intermittent with gpt-oss models) - resample
                print(f"[Output parse failure] Retrying request (attempt {attempt + 2}/{max_attempts})...")
                time.sleep(3)
            elif "tool_use_failed" in err and "'JSON'" in err:
                raise  # final answer sent as a fake tool call - salvaged by run_analysis
            elif "tool_use_failed" in err and not last:
                print(f"[Tool name leak] Retrying tool call (attempt {attempt + 2}/3)...")
                time.sleep(3)
            else:
                raise


litellm.completion = _patched_completion

# ── Constants ──────────────────────────────────────────────────────────────────
Path("output").mkdir(exist_ok=True)
logger = get_audit_logger("agent", "agent_audit.log")

LOG_DATA_PATH = Path("data/employee_logs.json")
TICKETS_PATH = Path("data/change_tickets.json")
REPORT_OUTPUT_PATH = Path("output/incident_report.md")
FINDINGS_OUTPUT_PATH = Path("output/findings.json")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
BATCH_SIZE = int(os.getenv("ANALYSIS_BATCH_SIZE", "3"))
BATCH_PAUSE_SECONDS = int(os.getenv("ANALYSIS_BATCH_PAUSE", "20"))
LLM_NAME = f"groq/{GROQ_MODEL}"
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))  # low temperature: more consistent, well-formed output


def make_llm() -> LLM:
    return LLM(model=LLM_NAME, temperature=LLM_TEMPERATURE)

# ── Data preparation ───────────────────────────────────────────────────────────
def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        if default is not None:
            return default
        raise FileNotFoundError(f"{path} not found. Run `python src/log_generator.py` first.")
    return json.loads(path.read_text(encoding="utf-8"))


# ── Agents ─────────────────────────────────────────────────────────────────────
def _backstory(text: str, cfg: DefenseConfig) -> str:
    return f"{text}\n\n{SECURITY_RULES}" if cfg.spotlighting else text


def build_analyst(cfg: DefenseConfig) -> Agent:
    return Agent(
        role="Threat Intelligence Analyst",
        goal=(
            "Assess every employee log entry for insider-threat indicators. For each entry: check the "
            "source IP with the IP Reputation and IP Geolocation tools, validate the transfer size with "
            "the Data Volume Anomaly tool, verify any cited change ticket with the Change Ticket "
            "Verification tool, consider context (destination, resource ownership, time), then map the "
            "behavior to an ATT&CK technique with the semantic search and confirm it with the lookup."
        ),
        backstory=_backstory(
            "You are a senior threat intelligence analyst with 10 years of insider-threat experience at "
            "financial institutions. You apply MITRE ATT&CK rigorously and verify findings with tools "
            "before drawing conclusions. You know that most unusual activity is benign and most "
            "insider exfiltration looks ordinary, so you weigh context, not just keywords.", cfg),
        tools=[check_ip_reputation, geolocate_ip, check_data_volume_anomaly, verify_change_ticket,
               search_mitre_techniques, lookup_mitre_technique],
        llm=make_llm(),
        verbose=True,
    )


def build_analysis_task(analyst: Agent, formatted_logs: str, n_entries: int) -> Task:
    return Task(
        description=(
            f"Analyze the following employee activity logs for insider threat indicators.\n\n"
            f"{formatted_logs}\n\n"
            f"There are exactly {n_entries} log entries. Produce exactly one finding per entry - do not "
            "skip any and do not invent employees. For each entry give: the employee ID, the action, "
            "the most relevant ATT&CK technique ID and name ('None' if benign), a risk level "
            "(Critical / High / Medium / Low) and one or two sentences of reasoning citing the evidence.\n\n"
            "When you have finished using tools, give your final answer as plain JSON text (not as a tool "
            "call), exactly in this shape and with nothing else:\n"
            '{"findings": [{"employee_id": "EMP-0000", "action": "...", "technique_id": "T1041", '
            '"technique_name": "...", "risk_level": "High", "reasoning": "..."}]}'
        ),
        # Structured output is validated by us (extract_analysis + Pydantic) rather than CrewAI's
        # output_pydantic, which on Groq makes the model emit a call to a non-existent "JSON" tool.
        expected_output='Plain JSON: {"findings": [...]} with one finding per log entry.',
        agent=analyst,
    )


def build_response_agents(cfg: DefenseConfig) -> tuple[Agent, Agent]:
    ir_advisor = Agent(
        role="Incident Response Advisor",
        goal=("Recommend specific, actionable containment and remediation steps for each validated "
              "finding, grounded in official MITRE mitigations and NIST SP 800-61."),
        backstory=_backstory(
            "You are a senior incident responder who has handled hundreds of insider-threat cases and "
            "turns findings into concrete steps a SOC can act on immediately.", cfg),
        tools=[search_mitre_mitigations],
        llm=make_llm(),
        verbose=True,
    )
    report_writer = Agent(
        role="Security Report Writer",
        goal=("Compile validated findings and recommendations into a clear incident report for "
              "security engineers and executives."),
        backstory="You write precise cybersecurity incident reports that balance depth with clarity.",
        tools=[],
        llm=make_llm(),
        verbose=True,
    )
    return ir_advisor, report_writer


def build_response_tasks(ir_advisor: Agent, report_writer: Agent, context: str) -> list[Task]:
    mitigation_task = Task(
        description=(
            "Below are the analyst's findings after automated validation, including any findings routed "
            f"to human review.\n\n{context}\n\n"
            "For each finding rated Medium or above, and for every finding marked NEEDS HUMAN REVIEW:\n"
            "1. Recommend immediate containment steps\n2. Suggest longer-term remediation\n"
            "3. Reference the relevant MITRE mitigation (use the search tool) and NIST SP 800-61 phase\n"
            "Group findings that share a technique and keep the whole plan under about 500 words."
        ),
        expected_output="A mitigation plan with containment and remediation steps per finding.",
        agent=ir_advisor,
    )
    report_task = Task(
        description=(
            "Using the validated findings and the mitigation plan, write a Markdown incident report with:\n"
            "1. Executive Summary\n2. Incident Details (scope, affected employees)\n"
            "3. Threat Findings (per-employee)\n"
            "4. MITRE ATT&CK Mapping Table with exactly these columns, one row per employee:\n"
            "   | Employee ID | Action | Technique ID | Technique Name | Risk Level |\n"
            "5. Items Requiring Human Review (copy every NEEDS HUMAN REVIEW item and its reason)\n"
            "6. Recommended Actions\n7. Severity Overview\n\n"
            "This system only detects and recommends: phrase every action as a recommendation and never "
            "claim it was carried out. Do not invent facts that are not in the findings or tool results.\n\n"
            f"Validated findings:\n{context}\n\n(The mitigation plan is provided as context.)"
        ),
        expected_output="A complete, professional incident report in Markdown.",
        agent=report_writer,
        context=[mitigation_task],
    )
    return [mitigation_task, report_task]


# ── Helpers ────────────────────────────────────────────────────────────────────
def parse_findings_json(text: str) -> AnalysisResult | None:
    """Parse model text into AnalysisResult: tolerates code fences, prose around the JSON,
    and a {"name": ..., "arguments": {...}} tool-call wrapper."""
    if not text:
        return None
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and "findings" not in data and isinstance(data.get("arguments"), dict):
        data = data["arguments"]
    try:
        return AnalysisResult(**data)
    except Exception:  # noqa: BLE001 - schema mismatch
        return None


def extract_analysis(task: Task) -> AnalysisResult | None:
    """Get structured findings from a finished task."""
    out = getattr(task, "output", None)
    if out is None:
        return None
    if getattr(out, "pydantic", None) is not None:
        return out.pydantic
    if getattr(out, "json_dict", None):
        try:
            return AnalysisResult(**out.json_dict)
        except Exception:  # noqa: BLE001
            pass
    return parse_findings_json(getattr(out, "raw", "") or "")


def salvage_from_error(exc: BaseException) -> AnalysisResult | None:
    """
    Groq rejects a final answer the model wrongly sends as a tool call ("tool_use_failed") but
    includes the model's text as `failed_generation`. If that text holds valid findings, use it.
    """
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        match = re.search(r'"failed_generation":"((?:[^"\\]|\\.)*)"', str(exc))
        if match:
            try:
                return parse_findings_json(json.loads(f'"{match.group(1)}"'))
            except json.JSONDecodeError:
                return None
        exc = exc.__cause__ or exc.__context__
    return None


def run_analysis(raw_logs: list[dict[str, Any]], cfg: DefenseConfig) -> tuple[AnalysisResult | None, str, list[dict]]:
    """
    Sanitize logs and run only the Threat Analyst. Returns (structured result,
    raw model output, sanitized logs). Used by the pipeline and the red-team harness.
    """
    config.set_active(cfg)
    clean_logs = sanitize_logs(raw_logs, cfg.schema_validation, cfg.injection_detection)
    ti.set_log_context(clean_logs)  # volume baseline = the whole dataset, not just one batch

    # Analyse in small batches, each with a fresh agent context. Tool results accumulate
    # in the conversation, so one context for 20 entries exceeds Groq's free-tier
    # 8K tokens-per-minute request size; batches of a few entries stay well under it.
    findings, raws = [], []
    batches = [clean_logs[i:i + BATCH_SIZE] for i in range(0, len(clean_logs), BATCH_SIZE)]
    for n, batch in enumerate(batches, 1):
        logger.info("Analysis batch %d/%d (%d entries)", n, len(batches), len(batch))
        print(f"\n🔎 Analysis batch {n}/{len(batches)} ({len(batch)} entries)")
        result, raw = None, ""
        for attempt in (1, 2):  # one retry per batch
            formatted = format_logs_for_agent(batch, spotlight=cfg.spotlighting)
            analyst = build_analyst(cfg)
            task = build_analysis_task(analyst, formatted, len(batch))
            try:
                Crew(agents=[analyst], tasks=[task], process=Process.sequential, verbose=True).kickoff()
                result = extract_analysis(task)
                raw = getattr(getattr(task, "output", None), "raw", "") or ""
            except Exception as e:  # noqa: BLE001
                if "daily token quota" in str(e) or any("daily token quota" in str(x) for x in
                                                        (e.__cause__, e.__context__) if x):
                    raise
                result = salvage_from_error(e)
                raw = str(e)[:4000]
                logger.warning("Batch %d attempt %d raised %s - salvaged=%s", n, attempt, type(e).__name__,
                               result is not None)
            if result is not None:
                break
            logger.warning("Batch %d attempt %d gave no parseable findings - %s", n, attempt,
                           "retrying" if attempt == 1 else "giving up")
            time.sleep(BATCH_PAUSE_SECONDS)
        raws.append(raw)
        if result is None:
            logger.error("Batch %d returned no parseable findings", n)
            return None, "\n".join(raws), clean_logs
        findings.extend(result.findings)
        if n < len(batches):
            time.sleep(BATCH_PAUSE_SECONDS)  # let the per-minute token budget refill

    return AnalysisResult(findings=findings), "\n".join(raws), clean_logs


def compact_context(result: AnalysisResult, guard: GuardrailReport | None) -> str:
    """One line per finding - keeps the response agents' prompts small (provider token limits)."""
    review = {r.employee_id: r.review_reason for r in guard.review_queue} if guard else {}
    lines = ["Employee | Action | Technique | Risk | Reasoning"]
    for f in result.findings:
        line = (f"{f.employee_id} | {f.action} | {f.technique_id} {f.technique_name} | {f.risk_level} | "
                f"{f.reasoning[:160]}")
        if f.employee_id in review:
            line += f" | NEEDS HUMAN REVIEW: {review[f.employee_id][:120]}"
        lines.append(line)
    if guard and guard.missing_employees:
        lines.append(f"Entries the analyst omitted (NEEDS HUMAN REVIEW): {', '.join(guard.missing_employees)}")
    return "\n".join(lines)


def guardrail_review(result: AnalysisResult, clean_logs: list[dict], tickets: list[dict]) -> GuardrailReport:
    try:
        valid_ids = ti.valid_technique_ids() if ti.MITRE_DATA_PATH.exists() else None
    except Exception:  # noqa: BLE001
        valid_ids = None
    return review_findings(result, clean_logs, valid_ids, ticket_verdicts_for(clean_logs, tickets))


# ── Full pipeline ──────────────────────────────────────────────────────────────
def run_pipeline(cfg: DefenseConfig | None = None) -> None:
    cfg = cfg or DefenseConfig.from_env()
    raw_logs = load_json(LOG_DATA_PATH)
    tickets = load_json(TICKETS_PATH, default=[])
    logger.info("Pipeline start | %d raw entries | model=%s | %s", len(raw_logs), LLM_NAME, cfg.describe())
    print(f"\n🚀 Starting insider threat detection pipeline ({cfg.describe()})\n")

    # Stage 1 - sanitize + analyse
    result, raw, clean_logs = run_analysis(raw_logs, cfg)
    tampered = sum("integrity_warning" in l for l in clean_logs)
    logger.info("Sanitization | %d entries | %d flagged as tampered", len(clean_logs), tampered)
    if result is None:
        logger.error("Analyst did not return parseable structured findings")
        raise RuntimeError("Threat Analyst output could not be parsed as structured findings:\n" + raw[:2000])
    logger.info("Analyst returned %d findings", len(result.findings))

    # Stage 2 - deterministic guardrail
    if cfg.output_guardrail:
        guard = guardrail_review(result, clean_logs, tickets)
        for r in guard.reviewed:
            logger.info("Guardrail | %s | agent=%s | evidence=%d | review=%s %s", r.employee_id, r.llm_risk,
                        r.signal_score, r.needs_review, r.review_reason)
        guard_md = guard.as_markdown()
    else:
        guard, guard_md = None, "_Output guardrail disabled for this run._"

    context = compact_context(result, guard)

    # Stage 3 - response planning + report
    ir_advisor, report_writer = build_response_agents(cfg)
    tasks = build_response_tasks(ir_advisor, report_writer, context)
    report = Crew(agents=[ir_advisor, report_writer], tasks=tasks, process=Process.sequential,
                  verbose=True).kickoff()

    REPORT_OUTPUT_PATH.write_text(
        f"# Insider Threat Incident Report\n**Generated:** {datetime.now():%Y-%m-%d %H:%M:%S} · "
        f"**Model:** {LLM_NAME} · **Controls:** {cfg.describe()}\n\n{report}\n\n---\n\n{guard_md}\n",
        encoding="utf-8",
    )
    FINDINGS_OUTPUT_PATH.write_text(json.dumps({
        "generated": datetime.now().isoformat(timespec="seconds"),
        "model": LLM_NAME,
        "defenses": asdict(cfg),
        "findings": result.model_dump()["findings"],
        "guardrail": [asdict(r) for r in guard.reviewed] if guard else None,
    }, indent=2), encoding="utf-8")

    logger.info("Report saved to %s; findings saved to %s", REPORT_OUTPUT_PATH, FINDINGS_OUTPUT_PATH)
    n_review = len(guard.review_queue) if guard else 0
    print(f"\n✅ Pipeline complete - {len(result.findings)} findings, {n_review} routed to human review."
          f"\n   Report: {REPORT_OUTPUT_PATH}\n   Findings: {FINDINGS_OUTPUT_PATH}")


if __name__ == "__main__":
    run_pipeline()
