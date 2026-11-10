"""
report_parser.py

Extracts structured findings (employee, technique, risk level) from the
LLM-generated Markdown incident report.

LLM output is not perfectly regular: it may bold IDs (**EMP-0485**), use
non-ASCII hyphens (EMP‑0485 with U+2011), merge the technique ID and name into
one cell ("T1133 - External Remote Services"), or reorder columns. The parser
therefore normalises the text and reads every Markdown table row that contains
an employee ID, instead of relying on one exact column layout.
"""

import re

import pandas as pd

RISK_LEVELS = ("Critical", "High", "Medium", "Low")

_HYPHENS = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015\u2212"), "-")
_EMP_RE = re.compile(r"\bEMP-\d{3,}\b")
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RISK_RE = re.compile(r"^(Critical|High|Medium|Low)\b", re.IGNORECASE)


def normalise(text: str) -> str:
    """Replace Unicode dashes with '-' and drop Markdown emphasis markers."""
    return text.translate(_HYPHENS).replace("**", "").replace("*", "")


def _technique_name(cell: str, tech_id: str) -> str:
    """Pull a readable technique name out of a cell like 'T1133 - External Remote Services (VPN)'."""
    name = cell.split(tech_id, 1)[-1]
    name = re.sub(r"^\s*[-:|]\s*", "", name)
    name = re.sub(r"\s*\(.*?\)\s*$", "", name)
    return name.strip()


def parse_report_threats(report_text: str) -> pd.DataFrame:
    """
    Return one row per employee found in the report's Markdown tables, with
    columns: employee_id, action, technique_id, technique_name, risk_level.
    """
    findings: dict[str, dict] = {}

    for raw_line in normalise(report_text).splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue

        cells = [c.strip() for c in line.strip("|").split("|")]
        emp_cell = next((c for c in cells if _EMP_RE.search(c)), None)
        if emp_cell is None:
            continue
        emp_id = _EMP_RE.search(emp_cell).group(0)

        # Rows listing several employees (e.g. severity summary) are not per-employee findings
        if len(_EMP_RE.findall(line)) > 1:
            continue

        risk = next(
            (_RISK_RE.match(c).group(1).capitalize() for c in cells if _RISK_RE.match(c)),
            None,
        )
        tech_cell = next((c for c in cells if _TECH_RE.search(c)), None)
        tech_id = _TECH_RE.search(tech_cell).group(0) if tech_cell else "None"

        # Technique name: a separate column right after the ID, or the remainder of the ID cell
        tech_name = ""
        if tech_cell:
            tech_name = _technique_name(tech_cell, tech_id)
            idx = cells.index(tech_cell)
            if not tech_name and idx + 1 < len(cells):
                tech_name = cells[idx + 1]

        emp_idx = cells.index(emp_cell)
        action = cells[emp_idx + 1] if emp_idx + 1 < len(cells) else ""

        entry = findings.setdefault(emp_id, {
            "employee_id": emp_id, "action": action,
            "technique_id": "None", "technique_name": "", "risk_level": "Unknown",
        })
        if entry["risk_level"] == "Unknown" and risk:
            entry["risk_level"] = risk
        if entry["technique_id"] == "None" and tech_id != "None":
            entry["technique_id"], entry["technique_name"] = tech_id, tech_name

    return pd.DataFrame(list(findings.values()))
