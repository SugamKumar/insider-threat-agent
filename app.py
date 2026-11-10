"""
app.py - Insider Threat Detection System · Streamlit UI
"""

import json
import sys
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent / "src"))

from evaluate import evaluate, verdicts_from_findings  # noqa: E402
from report_parser import parse_report_threats  # noqa: E402

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Insider Threat Detection",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Constants ──────────────────────────────────────────────────────────────────
LOG_PATH         = Path("data/employee_logs.json")
TICKETS_PATH     = Path("data/change_tickets.json")
REPORT_PATH      = Path("output/incident_report.md")
FINDINGS_PATH    = Path("output/findings.json")
BENCHMARK_PATH   = Path("output/benchmark_results.md")
REDTEAM_DIR      = Path("redteam/results")
AUDIT_LOG_PATH   = Path("logs/agent_audit.log")
SANITIZER_LOG    = Path("logs/sanitizer.log")

RISK_COLORS = {
    "Critical": "#e63946",
    "High":     "#f4a261",
    "Medium":   "#e9c46a",
    "Low":      "#2a9d8f",
    "Normal":   "#8ecae6",
}

# ── Helpers ────────────────────────────────────────────────────────────────────

def load_logs():
    if LOG_PATH.exists():
        return json.loads(LOG_PATH.read_text(encoding="utf-8"))
    return None

def load_findings():
    return json.loads(FINDINGS_PATH.read_text(encoding="utf-8")) if FINDINGS_PATH.exists() else None

def load_report():
    return REPORT_PATH.read_text(encoding="utf-8") if REPORT_PATH.exists() else None

def load_text(path):
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else "Not found. Run pipeline first."

def run_script(*args):
    import os
    import subprocess
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parent / "src")
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env,
                          cwd=str(Path(__file__).parent))

def run_pipeline():
    import os
    import subprocess
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parent / "src")
    env["LITELLM_CACHE"] = "False"
    return subprocess.run(
        [sys.executable, "src/agent.py"],  # same interpreter/venv as Streamlit
        capture_output=True, text=True, env=env,
        cwd=str(Path(__file__).parent)
    )

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 Insider Threat\nDetection System")
    st.caption("Powered by CrewAI · MITRE ATT&CK · Groq")
    st.divider()

    st.subheader("⚙️ Log Generation")
    difficulty   = st.radio("Difficulty", ["easy", "hard"], horizontal=True,
                                help="Hard adds benign-but-unusual and malicious-but-quiet scenarios")
    n_suspicious = st.slider("Suspicious entries", 3, 15, 7)
    n_normal     = st.slider("Normal entries",     1, 10, 3)
    seed         = st.number_input("Seed (0 = random)", min_value=0, value=0, step=1)
    st.divider()

    logs = load_logs()
    if logs:
        sus = sum(1 for entry in logs if entry["risk_flag"])
        st.metric("Total logs loaded", len(logs))
        st.metric("🚨 Suspicious", sus)
        st.metric("✅ Normal", len(logs) - sus)

    st.divider()
    if st.button("🗑️ Reset Everything", use_container_width=True, type="secondary"):
        for p in [LOG_PATH, TICKETS_PATH, REPORT_PATH, FINDINGS_PATH, AUDIT_LOG_PATH, SANITIZER_LOG]:
            p.unlink(missing_ok=True)
        st.success("✅ Reset complete. Ready for a fresh run.")
        st.rerun()

# ── Tabs ───────────────────────────────────────────────────────────────────────
tab_run, tab_dash, tab_logs, tab_report, tab_audit, tab_sec = st.tabs([
    "🚀 Run Pipeline",
    "📊 Dashboard",
    "📋 Logs Viewer",
    "📄 Incident Report",
    "🛡️ Audit Trail",
    "🧪 Security Evaluation",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 - Run Pipeline
# ══════════════════════════════════════════════════════════════════════════════
with tab_run:
    st.header("Run Detection Pipeline")
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Step 1 - Generate Logs")
        st.caption("Synthesize employee activity logs with realistic suspicious and normal patterns.")
        if st.button("🔄 Generate New Logs", use_container_width=True):
            from log_generator import generate_logs, save_dataset
            with st.spinner("Generating logs..."):
                logs, tickets = generate_logs(n_suspicious=n_suspicious, n_normal=n_normal,
                                              difficulty=difficulty, seed=int(seed) or None,
                                              return_tickets=True)
                save_dataset(logs, tickets)
                FINDINGS_PATH.unlink(missing_ok=True)
            st.success(f"✅ {len(logs)} {difficulty} entries generated "
                       f"({n_suspicious} suspicious, {n_normal} normal, {len(tickets)} approved tickets)")
            st.rerun()

    with col2:
        st.subheader("Step 2 - Run Agents")
        st.caption("Launch: Threat Analyst → IR Advisor → Report Writer. Takes 2-4 minutes.")

        if not LOG_PATH.exists():
            st.warning("⚠️ Generate logs first.")

        if st.button("🤖 Run Detection Pipeline", disabled=not LOG_PATH.exists(),
                     use_container_width=True, type="primary"):
            prog  = st.progress(0)
            status = st.empty()
            status.info("🧹 Sanitizing logs...")
            prog.progress(15)
            time.sleep(0.5)
            status.info("🤖 Agents running - this takes 2-4 minutes...")
            prog.progress(30)

            result = run_pipeline()
            prog.progress(100)
            status.empty()

            if result.returncode == 0:
                st.success("✅ Pipeline complete! Check the **Dashboard** and **Incident Report** tabs.")
                st.balloons()
            else:
                st.error("❌ Pipeline failed.")
                st.code(result.stderr, language="bash")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 - Dashboard
# ══════════════════════════════════════════════════════════════════════════════
with tab_dash:
    st.header("📊 Threat Dashboard")

    logs    = load_logs()
    report  = load_report()

    if not logs:
        st.info("No data yet. Generate logs and run the pipeline first.")
    else:

        df_logs = pd.DataFrame(logs)

        # ── KPI row ──────────────────────────────────────────────────────────────
        total       = len(df_logs)
        suspicious  = int(df_logs["risk_flag"].sum())
        normal      = total - suspicious
        total_bytes = int(df_logs["bytes_transferred"].sum())

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Total Log Entries",    total)
        k2.metric("🚨 Suspicious",        suspicious)
        k3.metric("✅ Normal",            normal)
        k4.metric("📦 Total Data Moved",  f"{total_bytes / 1_000_000:.1f} MB")

        st.divider()

        # ── Row 1: Risk by dept  +  Action frequency ─────────────────────────────
        r1c1, r1c2 = st.columns(2)

        with r1c1:
            st.subheader("Suspicious Entries by Department")
            dept_counts = (
                df_logs[df_logs["risk_flag"]]
                .groupby("department")
                .size()
                .reset_index(name="count")
            )
            fig_dept = px.bar(
                dept_counts, x="department", y="count",
                color="department",
                color_discrete_sequence=["#e63946", "#f4a261", "#e9c46a", "#2a9d8f"],
                labels={"department": "Department", "count": "Suspicious Entries"},
            )
            fig_dept.update_layout(showlegend=False, plot_bgcolor="rgba(0,0,0,0)",
                                   paper_bgcolor="rgba(0,0,0,0)", margin=dict(t=10, b=10))
            st.plotly_chart(fig_dept, use_container_width=True)

        with r1c2:
            st.subheader("Top Suspicious Actions")
            action_counts = (
                df_logs[df_logs["risk_flag"]]["action"]
                .value_counts()
                .reset_index()
            )
            action_counts.columns = ["action", "count"]
            fig_action = px.bar(
                action_counts, x="count", y="action", orientation="h",
                color="count",
                color_continuous_scale=["#2a9d8f", "#e9c46a", "#e63946"],
                labels={"action": "", "count": "Count"},
            )
            fig_action.update_layout(showlegend=False, coloraxis_showscale=False,
                                     plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                     margin=dict(t=10, b=10))
            st.plotly_chart(fig_action, use_container_width=True)

        # ── Row 2: Data exfiltration volume + Timeline ────────────────────────────
        r2c1, r2c2 = st.columns(2)

        with r2c1:
            st.subheader("Data Volume: Suspicious vs Normal (MB)")
            vol_df = df_logs.copy()
            vol_df["mb"]    = vol_df["bytes_transferred"] / 1_000_000
            vol_df["label"] = vol_df["risk_flag"].map({True: "🚨 Suspicious", False: "✅ Normal"})
            vol_sum = vol_df.groupby("label")["mb"].sum().reset_index()
            fig_vol = px.pie(
                vol_sum, names="label", values="mb",
                color="label",
                color_discrete_map={"🚨 Suspicious": "#e63946", "✅ Normal": "#2a9d8f"},
                hole=0.45,
            )
            fig_vol.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                  margin=dict(t=10, b=10))
            st.plotly_chart(fig_vol, use_container_width=True)

        with r2c2:
            st.subheader("Activity Timeline")
            tl_df = df_logs.copy()
            tl_df["timestamp"] = pd.to_datetime(tl_df["timestamp"])
            tl_df["date"]      = tl_df["timestamp"].dt.date
            tl_df["label"]     = tl_df["risk_flag"].map({True: "Suspicious", False: "Normal"})
            daily = tl_df.groupby(["date", "label"]).size().reset_index(name="count")
            fig_tl = px.line(
                daily, x="date", y="count", color="label",
                color_discrete_map={"Suspicious": "#e63946", "Normal": "#2a9d8f"},
                markers=True,
                labels={"date": "Date", "count": "Events", "label": "Type"},
            )
            fig_tl.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                 margin=dict(t=10, b=10))
            st.plotly_chart(fig_tl, use_container_width=True)

        # ── Row 3: MITRE ATT&CK breakdown (from report) ───────────────────────────
        if report:
            st.divider()
            st.subheader("🛡️ MITRE ATT&CK Technique Frequency")

            # ── Agent verdicts vs ground truth (risk_flag is hidden from agents) ──
            findings = load_findings()
            ev = (evaluate(logs, verdicts=verdicts_from_findings(findings["findings"]))
                  if findings else evaluate(logs, report))
            st.subheader("🎯 Agent Accuracy vs Ground Truth")
            st.caption("Critical/High/Medium = flagged, Low = benign. The risk_flag label is never shown to the agents.")
            e1, e2, e3, e4 = st.columns(4)
            e1.metric("Coverage",  f"{ev['scored']}/{ev['total']}")
            e2.metric("Precision", f"{ev['precision']:.0%}")
            e3.metric("Recall",    f"{ev['recall']:.0%}")
            e4.metric("Accuracy",  f"{ev['accuracy']:.0%}")

            if findings and findings.get("guardrail"):
                queue = [g for g in findings["guardrail"] if g["needs_review"]]
                st.subheader(f"🧑‍⚖️ Human Review Queue ({len(queue)})")
                st.caption("Findings the deterministic guardrail refused to accept as-is "
                           "(e.g. rated Low despite strong evidence, invalid ATT&CK ID, omitted entry).")
                if queue:
                    st.dataframe(pd.DataFrame(queue)[["employee_id", "llm_risk", "signal_score", "review_reason"]],
                                 use_container_width=True, hide_index=True)
                else:
                    st.success("All agent findings are consistent with the deterministic evidence.")
            st.divider()

            df_threats = (pd.DataFrame(findings["findings"]) if findings
                          else parse_report_threats(report))
            if not df_threats.empty and "technique_id" in df_threats.columns:
                tech_counts = (
                    df_threats[df_threats["technique_id"] != "None"]
                    .groupby(["technique_id", "technique_name"])
                    .size()
                    .reset_index(name="count")
                )
                tech_counts["label"] = tech_counts["technique_id"] + ": " + tech_counts["technique_name"]

                fig_mitre = px.bar(
                    tech_counts, x="count", y="label", orientation="h",
                    color="count",
                    color_continuous_scale=["#457b9d", "#e63946"],
                    labels={"label": "", "count": "Occurrences"},
                    text="count",
                )
                fig_mitre.update_traces(textposition="outside")
                fig_mitre.update_layout(
                    coloraxis_showscale=False,
                    plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                    margin=dict(t=10, b=10), height=350,
                    yaxis=dict(autorange="reversed"),
                )
                st.plotly_chart(fig_mitre, use_container_width=True)

            # Risk level donut
            st.subheader("Risk Level Distribution (from Report)")
            if not df_threats.empty and "risk_level" in df_threats.columns:
                risk_counts = df_threats["risk_level"].value_counts().reset_index()
                risk_counts.columns = ["risk_level", "count"]
                fig_risk = px.pie(
                    risk_counts, names="risk_level", values="count",
                    hole=0.5,
                    color="risk_level",
                    color_discrete_map=RISK_COLORS,
                )
                fig_risk.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                                       margin=dict(t=10, b=10))
                col_risk, col_pad = st.columns([1, 1])
                with col_risk:
                    st.plotly_chart(fig_risk, use_container_width=True)
        else:
            st.info("Run the pipeline to see MITRE ATT&CK and risk visualizations.")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 - Logs Viewer
# ══════════════════════════════════════════════════════════════════════════════
with tab_logs:
    st.header("Employee Activity Logs")
    logs = load_logs()

    if logs is None:
        st.info("No logs found. Generate logs first.")
    else:
        suspicious = [l for l in logs if l["risk_flag"]]
        normal     = [l for l in logs if not l["risk_flag"]]

        m1, m2, m3 = st.columns(3)
        m1.metric("Total",        len(logs))
        m2.metric("🚨 Suspicious", len(suspicious))
        m3.metric("✅ Normal",     len(normal))
        st.divider()

        show = st.radio("Filter", ["All", "Suspicious only", "Normal only"], horizontal=True)
        filtered = logs if show == "All" else (suspicious if "Suspicious" in show else normal)

        for log in filtered:
            flag  = "🚨" if log["risk_flag"] else "✅"
            label = "SUSPICIOUS" if log["risk_flag"] else "NORMAL"
            with st.expander(
                f"{flag} {log['employee_id']} ({log['username']}) · {log['action']} · {log['department']}"
            ):
                ca, cb = st.columns(2)
                with ca:
                    st.write(f"**Employee ID:** {log['employee_id']}")
                    st.write(f"**Username:** {log['username']}")
                    st.write(f"**Department:** {log['department']}")
                    st.write(f"**Action:** `{log['action']}`")
                    st.write(f"**Risk Flag:** `{label}`")
                with cb:
                    st.write(f"**Timestamp:** {log['timestamp']}")
                    st.write(f"**Source IP:** {log['source_ip']}")
                    st.write(f"**Location:** {log['location']}")
                    st.write(f"**Files Accessed:** {log['files_accessed']}")
                    st.write(f"**Bytes Transferred:** {log['bytes_transferred']:,}")
                    if "destination" in log:
                        st.write(f"**Destination:** {log.get('destination')} · **Ticket:** {log.get('ticket_id') or '-'}")
                        st.write(f"**Resource:** `{log.get('resource')}`")
                    if "scenario" in log:
                        st.caption(f"Ground-truth scenario (hidden from agents): {log['scenario']}")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 - Incident Report
# ══════════════════════════════════════════════════════════════════════════════
with tab_report:
    st.header("Incident Report")
    report = load_report()

    if report is None:
        st.info("No report yet. Run the pipeline first.")
    else:
        st.download_button("⬇️ Download Report (.md)", data=report,
                           file_name="incident_report.md", mime="text/markdown")
        st.divider()
        st.markdown(report)

# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 - Audit Trail
# ══════════════════════════════════════════════════════════════════════════════
with tab_audit:
    st.header("Audit Trail")
    st.caption("Every pipeline step and every redacted injection attempt is logged with a timestamp - supports non-repudiation (STRIDE) and post-incident review of agent behaviour.")

    ca, cb = st.columns(2)
    with ca:
        st.subheader("🤖 Agent Audit Log")
        st.code(load_text(AUDIT_LOG_PATH), language="log")
    with cb:
        st.subheader("🧹 Sanitizer Log")
        st.code(load_text(SANITIZER_LOG), language="log")

# ══════════════════════════════════════════════════════════════════════════════
# TAB 6 - Security Evaluation
# ══════════════════════════════════════════════════════════════════════════════
with tab_sec:
    st.header("🧪 Security Evaluation")
    st.caption("Offline results need no API key. LLM red-team runs: `python redteam/run_attacks.py --mode llm`.")

    def _run_and_refresh(label, *args):
        with st.spinner(label):
            res = run_script(*args)
        if res.returncode:
            st.error(res.stderr[-3000:])
        else:
            st.rerun()

    b1, b2, b3 = st.columns(3)
    if b1.button("Run detector benchmark", use_container_width=True):
        _run_and_refresh("Scoring the injection detectors...", "redteam/benchmark_detectors.py")
    if b2.button("Run red-team (worst-case)", use_container_width=True):
        _run_and_refresh("Running 588 simulated attacks...",
                         "redteam/run_attacks.py", "--mode", "worst-case", "--all", "--fresh")
    if b3.button("Run detection baselines", use_container_width=True):
        _run_and_refresh("Benchmarking baselines on easy and hard data...", "src/benchmark.py", "--with-llm")

    sections = [
        ("Red team - real LLM", REDTEAM_DIR / "llm_summary.md"),
        ("Red team - worst-case (non-LLM guarantees)", REDTEAM_DIR / "worst-case_summary.md"),
        ("Injection detector benchmark", REDTEAM_DIR / "detector_benchmark.md"),
        ("Detection baselines vs LLM", BENCHMARK_PATH),
    ]
    for title, path in sections:
        with st.expander(title, expanded=path.exists()):
            st.markdown(path.read_text(encoding="utf-8") if path.exists() else "_Not run yet._")
