"""Shared test setup: import paths and an isolated directory for audit logs."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

# Keep test runs out of the real project audit logs
os.environ.setdefault("ITA_LOG_DIR", tempfile.mkdtemp(prefix="ita-test-logs-"))
