"""
config.py

Defense toggles. Every control can be switched off individually so the
red-team harness can measure what each layer actually contributes
(defenses on vs off, or one layer at a time).

Set DEFENSES=off in the environment to disable all of them.
"""

import os
from dataclasses import asdict, dataclass, fields


@dataclass
class DefenseConfig:
    schema_validation: bool = True      # allowlist each log field's shape        (ASI01)
    injection_detection: bool = True    # normalising pattern detector           (ASI01 / AML.T0051)
    spotlighting: bool = True           # delimit untrusted data + tell agents    (ASI01)
    sanitize_tool_outputs: bool = True  # scan API responses before agents see them (indirect injection)
    rag_provenance: bool = True         # only serve RAG docs whose hash is in the build manifest (ASI06)
    output_guardrail: bool = True       # validate findings + deterministic cross-check (ASI09)

    @classmethod
    def all_off(cls) -> "DefenseConfig":
        return cls(**{f.name: False for f in fields(cls)})

    @classmethod
    def from_env(cls) -> "DefenseConfig":
        return cls.all_off() if os.getenv("DEFENSES", "on").lower() in ("off", "0", "false") else cls()

    def describe(self) -> str:
        on = [k for k, v in asdict(self).items() if v]
        return "all defenses off" if not on else "defenses: " + ", ".join(on)


# Process-wide active configuration (tools read this at call time)
ACTIVE = DefenseConfig.from_env()


def set_active(cfg: DefenseConfig) -> None:
    global ACTIVE
    ACTIVE = cfg


def active() -> DefenseConfig:
    return ACTIVE
