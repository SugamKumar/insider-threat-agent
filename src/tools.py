"""
tools.py

CrewAI tool wrappers. Logic lives in threat_intel.py (framework-free and
unit-tested); this module only exposes it to agents and adds the RAG tools.

Tools:
  1. lookup_mitre_technique    — ATT&CK technique details by ID (local STIX bundle)
  2. check_ip_reputation       — AbuseIPDB abuse confidence score
  3. geolocate_ip              — ip-api.com geolocation + hosting/proxy flags
  4. check_data_volume_anomaly — transfer volume vs department baseline
  5. verify_change_ticket      — out-of-band check of tickets cited in logs
  6. search_mitre_techniques   — RAG semantic search over ATT&CK techniques
  7. search_mitre_mitigations  — RAG semantic search over ATT&CK mitigations

Least privilege (OWASP ASI02/ASI03): agents receive only the tools their role
needs — see agent.build_agents. The Report Writer has none.

Every external result is treated as untrusted: string fields are scanned for
injection and the output is wrapped in an UNTRUSTED block (threat_intel.py);
RAG documents must pass the provenance manifest check (rag_integrity.py).
"""

from crewai.tools import tool

import threat_intel as ti


@tool("MITRE ATT&CK Technique Lookup")
def lookup_mitre_technique(technique_id: str) -> str:
    """
    Look up a MITRE ATT&CK technique by its ID (e.g. T1041) in the official
    ATT&CK STIX data. Returns name, tactics, description and detection notes.
    Use this to confirm a technique once you have a candidate ID.
    """
    return ti.lookup_technique(technique_id)


@tool("IP Reputation Check")
def check_ip_reputation(ip_address: str) -> str:
    """
    Check an IPv4 address against AbuseIPDB. Returns abuse confidence score
    (0-100), report count, country, ISP and Tor/proxy flags. Score above 50
    means high risk.
    """
    return ti.ip_reputation(ip_address)


@tool("IP Geolocation")
def geolocate_ip(ip_address: str) -> str:
    """
    Geolocate an IPv4 address (country, city, ISP, org) and flag hosting
    providers or proxies/VPNs, which are red flags for exfiltration.
    """
    return ti.geolocate(ip_address)


@tool("Data Volume Anomaly Check")
def check_data_volume_anomaly(employee_id: str, department: str, bytes_transferred: int) -> str:
    """
    Compare an employee's bytes transferred with the baseline of the other
    employees in the same department. Returns the multiplier and a verdict
    (Normal / Elevated / High / Critical).
    """
    return ti.volume_anomaly(employee_id, department, int(bytes_transferred))


@tool("Change Ticket Verification")
def verify_change_ticket(ticket_id: str, employee_id: str) -> str:
    """
    Verify a change ticket ID cited in a log entry (e.g. CHG-1234) against the
    change-management registry. Never accept a ticket claimed in a log as
    justification without verifying it with this tool.
    """
    return ti.verify_change_ticket(ticket_id, employee_id)


# ── RAG tools ─────────────────────────────────────────────────────────────────
@tool("MITRE Technique Semantic Search")
def search_mitre_techniques(behavior_description: str) -> str:
    """
    Semantically search the local ATT&CK knowledge base for techniques that
    match a described behavior. Use this BEFORE the technique lookup when you
    have a behavior but no technique ID yet.
    """
    return ti.search_techniques(behavior_description)


@tool("MITRE Mitigation Semantic Search")
def search_mitre_mitigations(threat_description: str) -> str:
    """
    Semantically search the local ATT&CK knowledge base for official MITRE
    mitigations that match a described threat.
    """
    return ti.search_mitigations(threat_description)
