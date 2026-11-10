"""
logging_utils.py

Per-module audit loggers.

logging.basicConfig() only takes effect the first time it is called in a
process, so when several modules each call it, every module ends up writing to
whichever file was configured first. This helper gives each component its own
dedicated log file instead, which keeps the audit trail separable:

  logs/agent_audit.log  - pipeline / agent decisions
  logs/sanitizer.log    - prompt-injection detections
  logs/rag.log          - vector store build / load events
"""

import logging
import os
from pathlib import Path

LOG_DIR = Path(os.getenv("ITA_LOG_DIR", "logs"))  # overridable, e.g. by the test suite
_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%dT%H:%M:%S"


def get_audit_logger(name: str, filename: str) -> logging.Logger:
    """
    Return a logger that writes to logs/<filename>, creating it if needed.

    Calling this more than once with the same name is safe: the handler is
    only attached the first time.
    """
    LOG_DIR.mkdir(exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # keep third-party root logging out of our audit files

    target = (LOG_DIR / filename).resolve()
    already_attached = any(
        isinstance(h, logging.FileHandler) and Path(h.baseFilename) == target
        for h in logger.handlers
    )
    if not already_attached:
        handler = logging.FileHandler(target, encoding="utf-8")
        handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
        logger.addHandler(handler)

    return logger
