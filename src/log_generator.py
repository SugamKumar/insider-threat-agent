"""
log_generator.py

Generates synthetic employee behavior logs to simulate insider threat scenarios.

Two difficulty levels:

  easy - suspicious and normal entries are cleanly separated (off-hours, huge
         volumes, suspicious action names). A one-line rule scores ~100% here,
         so it is useful for smoke tests but proves little about an LLM.

  hard - adds realistic ambiguity in both directions:
           benign but scary-looking : approved after-hours maintenance,
                                      quarter-end finance exports, business travel VPN
           malicious but quiet      : low-and-slow exfil via ordinary email,
                                      cross-department file access, USB in business
                                      hours, after-hours work with a forged ticket
         Telling these apart needs context (destination, resource, change
         tickets) - the kind of reasoning rules and anomaly scores miss.

Each entry has a hidden ground-truth `risk_flag` and `scenario`, both stripped
before agents see the data. Approved change tickets are written to
data/change_tickets.json so the Threat Analyst can verify ticket claims
out-of-band instead of trusting what the log says.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from faker import Faker

from schema import DEPARTMENTS, NORMAL_ACTIONS, PERSONAL_DOMAINS, SENSITIVE_SHARES, SUSPICIOUS_ACTIONS
from schema import DEPT_SHARES as DS

LOG_OUTPUT_PATH = Path("data/employee_logs.json")
TICKETS_OUTPUT_PATH = Path("data/change_tickets.json")

DEPT_SHARES = {
    "Finance": DS["Finance"] + r"\ledgers",
    "Engineering": DS["Engineering"] + r"\src",
    "HR": DS["HR"] + r"\personnel",
    "Legal": DS["Legal"] + r"\contracts",
    "IT": DS["IT"] + r"\configs",
    "Operations": DS["Operations"] + r"\runbooks",
    "Sales": DS["Sales"] + r"\pipeline",
}

OFF_HOURS = list(range(22, 24)) + list(range(0, 6))


class LogFactory:
    """Seedable generator so experiments are reproducible."""

    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)
        self.fake = Faker()
        if seed is not None:
            self.fake.seed_instance(seed)
        self.tickets: list[dict[str, Any]] = []
        self._used_ids: set[str] = set()
        self._ticket_seq = self.rng.randint(1000, 8000)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _employee_id(self) -> str:
        while True:
            emp = f"EMP-{self.rng.randint(0, 9999):04d}"
            if emp not in self._used_ids:
                self._used_ids.add(emp)
                return emp

    def _username(self) -> str:
        name = self.fake.user_name().lower()
        return "".join(c for c in name if c.isalnum() or c in "._-")[:32] or "user"

    def _timestamp(self, hour: int) -> str:
        base = datetime(2026, 6, 25, hour, self.rng.randint(0, 59))
        return (base - timedelta(days=self.rng.randint(0, 30))).isoformat()

    def _city(self) -> str:
        return self.fake.city()

    def _ticket(self, emp: str, dept: str, purpose: str) -> str:
        self._ticket_seq += 1
        tid = f"CHG-{self._ticket_seq:04d}"
        self.tickets.append({"ticket_id": tid, "employee_id": emp,
                             "department": dept, "purpose": purpose, "status": "approved"})
        return tid

    def _forged_ticket(self) -> str:
        # Looks valid but is never written to the registry
        self._ticket_seq += 1
        return f"CHG-{self._ticket_seq:04d}"

    def _base(self, dept: str, action: str, hour: int, files: int, nbytes: int,
              destination: str, resource: str, ticket: str | None,
              risk: bool, scenario: str, emp: str | None = None) -> dict[str, Any]:
        return {
            "employee_id": emp or self._employee_id(),
            "username": self._username(),
            "department": dept,
            "action": action,
            "timestamp": self._timestamp(hour),
            "files_accessed": files,
            "source_ip": self.fake.ipv4_public(),
            "location": self._city(),
            "bytes_transferred": nbytes,
            "destination": destination,
            "resource": resource,
            "ticket_id": ticket,
            "risk_flag": risk,
            "scenario": scenario,
        }

    # ── easy scenarios ────────────────────────────────────────────────────────
    def easy_suspicious(self) -> dict[str, Any]:
        dept = self.rng.choice(DEPARTMENTS)
        return self._base(
            dept, self.rng.choice(SUSPICIOUS_ACTIONS), self.rng.choice(OFF_HOURS),
            self.rng.randint(50, 500), self.rng.randint(100_000, 50_000_000),
            self.rng.choice(["internal", *PERSONAL_DOMAINS]), DEPT_SHARES[dept], None,
            True, "classic_suspicious",
        )

    def easy_normal(self) -> dict[str, Any]:
        dept = self.rng.choice(DEPARTMENTS)
        return self._base(
            dept, self.rng.choice(NORMAL_ACTIONS), self.rng.randint(8, 18),
            self.rng.randint(1, 10), self.rng.randint(100, 5_000),
            "internal", DEPT_SHARES[dept], None, False, "routine",
        )

    # ── hard benign (looks scary, is fine) ────────────────────────────────────
    def approved_maintenance(self) -> dict[str, Any]:
        emp = self._employee_id()
        return self._base(
            "IT", "after_hours_login", self.rng.choice([23, 0, 1, 2]),
            self.rng.randint(20, 120), self.rng.randint(1_000_000, 15_000_000),
            "internal", DEPT_SHARES["IT"], self._ticket(emp, "IT", "patch window"),
            False, "benign_approved_maintenance", emp=emp,
        )

    def quarter_end_export(self) -> dict[str, Any]:
        emp = self._employee_id()
        return self._base(
            "Finance", "large_data_export", self.rng.randint(9, 17),
            self.rng.randint(100, 400), self.rng.randint(20_000_000, 60_000_000),
            "internal", DEPT_SHARES["Finance"], self._ticket(emp, "Finance", "quarter-end close"),
            False, "benign_quarter_end_export", emp=emp,
        )

    def business_travel_vpn(self) -> dict[str, Any]:
        return self._base(
            "Sales", "vpn_from_unusual_location", self.rng.randint(8, 18),
            self.rng.randint(1, 15), self.rng.randint(5_000, 400_000),
            "internal", DEPT_SHARES["Sales"], None, False, "benign_business_travel",
        )

    # ── hard malicious (looks quiet, is not) ──────────────────────────────────
    def low_and_slow_email(self) -> dict[str, Any]:
        dept = self.rng.choice(["Finance", "Engineering", "Legal", "HR"])
        return self._base(
            dept, "email_sent", self.rng.randint(9, 17),
            self.rng.randint(3, 8), self.rng.randint(2_000_000, 9_000_000),
            self.rng.choice(PERSONAL_DOMAINS), DEPT_SHARES[dept], None,
            True, "malicious_low_and_slow_email",
        )

    def cross_department_read(self) -> dict[str, Any]:
        dept = self.rng.choice(["Engineering", "Sales", "Operations"])
        return self._base(
            dept, "file_read", self.rng.randint(9, 17),
            self.rng.randint(4, 12), self.rng.randint(50_000, 900_000),
            "internal", self.rng.choice(SENSITIVE_SHARES), None,
            True, "malicious_cross_department_access",
        )

    def business_hours_usb(self) -> dict[str, Any]:
        dept = self.rng.choice(DEPARTMENTS)
        return self._base(
            dept, "usb_device_connected", self.rng.randint(9, 17),
            self.rng.randint(5, 30), self.rng.randint(1_000_000, 5_000_000),
            "internal", DEPT_SHARES[dept], None, True, "malicious_business_hours_usb",
        )

    def forged_ticket_after_hours(self) -> dict[str, Any]:
        return self._base(
            "IT", "after_hours_login", self.rng.choice([23, 0, 1, 2]),
            self.rng.randint(20, 120), self.rng.randint(1_000_000, 15_000_000),
            "internal", DEPT_SHARES["IT"], self._forged_ticket(),
            True, "malicious_forged_ticket",
        )


HARD_BENIGN = ["approved_maintenance", "quarter_end_export", "business_travel_vpn", "easy_normal"]
HARD_MALICIOUS = ["low_and_slow_email", "cross_department_read", "business_hours_usb",
                  "forged_ticket_after_hours", "easy_suspicious"]


def generate_logs(n_suspicious: int = 7, n_normal: int = 3, difficulty: str = "easy",
                  seed: int | None = None, return_tickets: bool = False):
    """
    Generate a shuffled mix of suspicious and normal log entries.

    Args:
        n_suspicious: Number of malicious entries.
        n_normal: Number of benign entries.
        difficulty: "easy" or "hard" (see module docstring).
        seed: Optional RNG seed for reproducible datasets.
        return_tickets: Also return the approved change-ticket registry.
    """
    if difficulty not in ("easy", "hard"):
        raise ValueError("difficulty must be 'easy' or 'hard'")
    factory = LogFactory(seed)

    if difficulty == "easy":
        logs = ([factory.easy_suspicious() for _ in range(n_suspicious)]
                + [factory.easy_normal() for _ in range(n_normal)])
    else:
        logs = ([getattr(factory, HARD_MALICIOUS[i % len(HARD_MALICIOUS)])() for i in range(n_suspicious)]
                + [getattr(factory, HARD_BENIGN[i % len(HARD_BENIGN)])() for i in range(n_normal)])

    # Shuffle so agents cannot infer risk from entry order
    factory.rng.shuffle(logs)
    return (logs, factory.tickets) if return_tickets else logs


def save_dataset(logs: list[dict[str, Any]], tickets: list[dict[str, Any]]) -> None:
    LOG_OUTPUT_PATH.parent.mkdir(exist_ok=True)
    LOG_OUTPUT_PATH.write_text(json.dumps(logs, indent=2), encoding="utf-8")
    TICKETS_OUTPUT_PATH.write_text(json.dumps(tickets, indent=2), encoding="utf-8")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate synthetic insider-threat logs")
    parser.add_argument("--suspicious", type=int, default=7)
    parser.add_argument("--normal", type=int, default=3)
    parser.add_argument("--difficulty", choices=["easy", "hard"], default="easy")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    logs, tickets = generate_logs(args.suspicious, args.normal, args.difficulty,
                                  args.seed, return_tickets=True)
    save_dataset(logs, tickets)
    print(f"✅ Saved {len(logs)} logs to {LOG_OUTPUT_PATH} and "
          f"{len(tickets)} approved tickets to {TICKETS_OUTPUT_PATH}\n")
    for log in logs:
        flag = "🚨 SUSPICIOUS" if log["risk_flag"] else "✅ NORMAL"
        print(f"  {flag} | {log['employee_id']} | {log['action']:<28} | {log['scenario']}")
