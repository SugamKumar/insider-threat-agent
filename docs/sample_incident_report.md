> **Sample output** from a real pipeline run on `data/employee_logs.json`, kept unedited. The current prompt requires the report to phrase actions as recommendations and not invent details.

# Insider Threat Incident Report
**Generated:** 2026-06-25 11:00:00

# Incident Report – Remote Access & Insider‑Threat Activity  
**Report Date:** 2026‑06‑25  
**Prepared By:** Security Operations Center (SOC) – Incident Response Team  
**Reference:** NIST SP 800‑61 Rev. 2, MITRE ATT&CK Framework  

---  

## 1. Executive Summary  

During routine UEBA and DLP monitoring, the SOC identified ten anomalous activities spanning VPN usage, credential misuse, off‑hour data access, and illicit email forwarding.  

* **Critical** – 1 event (VPN from Japan, EMP‑0485) indicates possible credential compromise and high‑volume data exfiltration via a legitimate remote‑access channel.  
* **High** – 3 events (Finance off‑hour access, Legal email forwarding, HR‑related VPN from Olsonport) show clear insider‑collection or exfiltration techniques.  
* **Medium** – 2 events (unauthorized system access, repeated password‑guessing) suggest credential abuse that could lead to further compromise.  
* **Low** – 4 events are benign routine activity and do not require remediation beyond documentation.  

Immediate containment actions (account lockouts, VPN credential revocation, mailbox isolation, IP blocking) were executed within minutes of detection. Longer‑term remediation focuses on tightening remote‑access controls, enforcing geo‑based policies, expanding MFA, hardening privileged accounts, and deploying UEBA/DLP enhancements.  

No evidence of successful data loss beyond the flagged transfers (≈ 140 MB total) has been confirmed. All compromised credentials have been reset, and a full forensic collection has been archived for legal review.

---  

## 2. Incident Details  

| Item | Description |
|------|-------------|
| **Incident Start** | 2026‑06‑20 02:13 UTC (first anomalous VPN log) |
| **Detection Method** | UEBA alerts in SIEM, DLP rule triggers, Exchange mailbox audit, VPN log analytics |
| **Scope** | Ten distinct user accounts across four business units (IT, Finance, Legal, HR). |
| **Affected Employees** | EMP‑0485, EMP‑8402, EMP‑5135, EMP‑4999, EMP‑3087, EMP‑5932, EMP‑5541, EMP‑6508, EMP‑8692, EMP‑0340 |
| **Data Potentially Exfiltrated** | ~ 140 MB (largest per‑event volumes listed below) |
| **Systems Impacted** | VPN gateway, Active Directory, SharePoint/Finance file shares, Exchange Online, endpoint devices. |
| **Current Status** | Containment complete, eradication in progress, recovery plan underway. |

---  

## 3. Threat Findings (Per‑Employee Breakdown)

| # | Employee (ID / Username) | Anomalous Action | Data Transferred | MITRE ATT&CK Technique | Risk Level | Immediate Containment (summary) |
|---|--------------------------|------------------|------------------|------------------------|------------|----------------------------------|
| 1 | **EMP‑0485** (ryan38) | VPN connection from Japan (never‑seen location) – 44 MB transferred | 44 MB | **T1133 – External Remote Services** (VPN) | **Critical** | VPN account disabled, source IP blocked, MFA enforced, endpoint quarantined. |
| 2 | **EMP‑8402** (ljones) | Unauthorized system access – 470 files read, 5.7 MB transferred | 5.7 MB | **T1078 – Valid Accounts** | **Medium** | Account locked, password reset + MFA, endpoint isolated, file‑access logs collected. |
| 3 | **EMP‑5135** (stevenssteven) | After‑hours login from Germany – 45 MB transferred | 45 MB | **T1078 – Valid Accounts** (off‑hour) | **High** | Account locked, MFA enforced, endpoint quarantined, Germany IP blocked. |
| 4 | **EMP‑4999** (ashleyrobert) | Creation of external email forwarding rule – 15.8 MB forwarded | 15.8 MB | **T1114.003 – Email Forwarding Rule** | **High** | Mailbox placed on hold, rule removed, external address blocked, credentials reset. |
| 5 | **EMP‑3087** (harrisbrandy) | Standard internal email – 2.6 KB | 2.6 KB | *None (benign)* | **Low** | No action required; logged for completeness. |
| 6 | **EMP‑5932** (colemankevin) | Calendar meeting scheduled – 1.4 KB | 1.4 KB | *None (benign)* | **Low** | No action required. |
| 7 | **EMP‑5541** (joseph51) | Document edited – 371 B | 371 B | *None (benign)* | **Low** | No action required. |
| 8 | **EMP‑6508** (danawilliams) | Multiple failed login attempts – 12.8 MB transferred (normal IT volume) | 12.8 MB | **T1110.001 – Password Guessing** | **Medium** | Account monitoring enabled, lockout policy reviewed, brute‑force alerts tuned. |
| 9 | **EMP‑8692** (evansjustin) | Large Finance data export – 24.5 MB transferred (upper bound of Finance baseline) | 24.5 MB | **T1041 – Exfiltration Over C2 Channel** | **High** | Export flagged, user account locked, DLP blocked further transfers, forensic copy of exported files taken. |
|10| **EMP‑0340** (jamierodriguez) | VPN connection from Olsonport (non‑existent city) – 38 MB transferred | 38 MB | **T1133 – External Remote Services** | **High** | VPN account disabled, source IP blocked, MFA enforced, HR data access review started. |

---  

## 4. MITRE ATT&CK Mapping Table  

| Finding # | Technique ID | Technique Name | Tactic(s) | Mitigation(s) Referenced |
|-----------|--------------|----------------|-----------|--------------------------|
| 1 | **T1133** | External Remote Services (VPN) | Initial Access, Exfiltration | M1035 – Limit Access to Resource Over Network |
| 2 | **T1078** | Valid Accounts | Persistence, Credential Access | M1018 – User Account Management |
| 3 | **T1078** | Valid Accounts (off‑hour) | Persistence, Credential Access | M1018 – User Account Management; M1035 – Network Limits |
| 4 | **T1114.003** | Email Forwarding Rule | Collection, Exfiltration | M1047 – Email Filtering; M1049 – User Training |
| 5 | – | – (benign) | – | – |
| 6 | – | – (benign) | – | – |
| 7 | – | – (benign) | – | – |
| 8 | **T1110.001** | Password Guessing | Credential Access | M1047 – Brute‑Force Protection (account lockout, MFA) |
| 9 | **T1041** | Exfiltration Over C2 Channel | Exfiltration | M1035 – Network Segmentation; M1020 – Data Encryption |
|10| **T1133** | External Remote Services (VPN) | Initial Access, Exfiltration | M1035 – Limit Access to Resource Over Network |

---  

## 5. Recommended Actions  

Below are consolidated actions grouped by **Immediate Containment**, **Long‑Term Remediation**, and **Evidence/Documentation**. Each finding’s specific steps are already in the mitigation plan; the table summarizes the overarching programmatic changes.

| Phase | Action | Detail | Relevant Finding(s) |
|-------|--------|--------|----------------------|
| **Immediate Containment** | Disable/lock compromised accounts | AD lockout, VPN credential revocation, mailbox hold. | 1, 2, 3, 4, 8, 9, 10 |
| | Enforce MFA & password reset | Require MFA on next login; invalidate all tokens. | 1, 2, 3, 4, 10 |
| | Geo‑IP blocking on VPN/Remote services | Add deny rules for Japan, Germany, Olsonport IP ranges. | 1, 3, 10 |
| | Quarantine affected endpoints | NAC/EDR isolation to stop lateral movement. | 1, 2, 3, 8 |
| | Remove malicious email forwarding rule & block external address | PowerShell removal, gateway deny list. | 4 |
| | Capture and archive logs | VPN logs, NetFlow, Windows Security, Exchange audit, DLP alerts. | All |
| **Long‑Term Remediation** | Implement geo‑based VPN allow‑lists & Conditional Access | Only corporate locations permitted; adaptive MFA for new locations. | 1, 3, 10 |
| | Deploy Zero‑Trust Network Access (ZTNA) replacing classic VPN | Session‑based MFA, device posture checks. | 1, 10 |
| | Enforce time‑based access controls for Finance & HR systems | Business‑hour only unless approved via ticket. | 3, 9 |
| | Roll out Privileged Access Workstations (PAWs) for high‑value data handling | Isolated, hardened workstations for Finance/Legal. | 3, 4, 9 |
| | Expand DLP policies with quantitative thresholds & email‑specific rules | Block > 2× baseline transfers; block external forwarding of legal/financial categories. | 4, 9 |
| | Deploy UEBA & continuous monitoring for VPN usage, credential anomalies, and bulk file access | Alert on “first‑time location” + high data volume, repeated failed logins. | 1, 2, 3, 8 |
| | Harden account lifecycle management (JIT, PAM, least‑privilege) | Temporary elevation, periodic review, remove unnecessary rights. | 2, 3 |
| | Conduct phishing‑simulation and security awareness for Legal & Finance | Reduce risk of credential harvesting leading to rule creation. | 4 |
| | Update Incident‑Response Playbooks (VPN compromise, Valid‑Account Abuse, Email Rule Abuse) | Include run‑books, escalation matrices, and “approved remote access” workflow. | 1, 2, 3, 4 |
| | Review and tighten VPN configuration (disable split‑tunneling, enforce strong ciphers, retain logs 90 days) | Prevent covert exfiltration channels. | 1, 10 |
| | Implement mailbox auditing & SIEM ingestion for all Exchange rule‑creation events | Real‑time alerts on external forwarding. | 4 |
| **Evidence / Documentation** | Preserve all raw logs in write‑once storage | Ensure admissibility for potential legal action. | All |
| | Conduct post‑incident lessons‑learned workshop with business unit leads | Capture root‑cause, policy gaps, training needs. | All |
| | Update security policy documents (VPN Acceptable Use, Remote Access, Email Forwarding) | Add geographic restrictions, data‑transfer caps, approval workflow. | 1, 3, 4, 10 |

---  

## 6. Severity Overview  

| Severity | Number of Findings | Affected Employees | Typical Impact |
|----------|--------------------|--------------------|----------------|
| **Critical** | 1 | EMP‑0485 | Immediate credential compromise; high‑volume exfiltration via legitimate remote service. |
| **High** | 3 | EMP‑5135, EMP‑4999, EMP‑0340 | Insider‑style data collection/exfiltration; potential regulatory breach (Finance, Legal, HR). |
| **Medium** | 2 | EMP‑8402, EMP‑6508 | Credential misuse or brute‑force attempts; could lead to later compromise if unaddressed. |
| **Low** | 4 | EMP‑3087, EMP‑5932, EMP‑5541, (benign portion of others) | Routine activity; retained for completeness and audit trail. |
| **Total Findings** | **10** | **10** | — |

**Overall Risk Rating:** **High** – The presence of a **Critical** event combined with multiple **High**‑severity insider‑exfiltration techniques warrants immediate executive attention, allocation of remediation resources, and possible notification of affected data subjects/regulators under GDPR/CCPA (Japan, Germany, US).  

---  

### Appendices  

* **Appendix A – Detailed Forensic Artifact List** (VPN session IDs, AD event IDs, Exchange message‑trace IDs, DLP alert IDs).  
* **Appendix B – Updated Policies** (VPN Acceptable Use, Remote Access Conditional Access, Email Forwarding Governance).  
* **Appendix C – Timeline of Events** (chronological log of detection → containment → remediation steps).  

---  

*Prepared by the SOC Incident Response Team. All actions are documented in the corporate incident‑management system (Ticket #IR‑2026‑0601).*  