"""
rag_integrity.py

Provenance control for the RAG knowledge base (OWASP ASI06 - Memory & Context
Poisoning; MITRE ATLAS AML.T0070 - RAG Poisoning).

At build time rag.py records the SHA-256 of every document it ingested from the
official ATT&CK bundle in data/rag_manifest.json - a file kept outside the
vector database. At query time, retrieved documents whose content hash is not
in the manifest are dropped and audit-logged. An attacker who can write to the
vector store (insert or edit an embedding's text) therefore cannot get that
text in front of an agent without also controlling the manifest.

Assumption (documented in docs/THREAT_MODEL.md): the manifest is stored with
stricter write permissions than the vector store, or is version-controlled.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from logging_utils import get_audit_logger

MANIFEST_PATH = Path("data/rag_manifest.json")
logger = get_audit_logger("rag", "rag.log")


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_manifest(contents: Iterable[str], source: str, path: Path = MANIFEST_PATH) -> int:
    hashes = sorted({content_hash(c) for c in contents})
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"source": source, "count": len(hashes), "sha256": hashes}, indent=1),
                    encoding="utf-8")
    logger.info("RAG manifest written | %d document hashes | source=%s", len(hashes), source)
    return len(hashes)


_cache: dict[Path, set[str]] = {}


def load_manifest(path: Path = MANIFEST_PATH) -> set[str] | None:
    if path not in _cache:
        if not path.exists():
            return None
        _cache[path] = set(json.loads(path.read_text(encoding="utf-8"))["sha256"])
    return _cache[path]


def filter_verified(docs: list[Any], path: Path = MANIFEST_PATH) -> tuple[list[Any], int, bool]:
    """
    Keep only documents whose page_content hash appears in the manifest.

    Returns (kept_docs, n_dropped, manifest_present). Without a manifest
    (store built before this control existed) nothing can be verified: all
    documents are returned and the caller is told so.
    """
    manifest = load_manifest(path)
    if manifest is None:
        logger.warning("No RAG manifest found - provenance cannot be verified. Rebuild with `python src/rag.py`.")
        return docs, 0, False
    kept = [d for d in docs if content_hash(d.page_content) in manifest]
    dropped = len(docs) - len(kept)
    if dropped:
        logger.warning("RAG provenance check dropped %d unverified document(s)", dropped)
    return kept, dropped, True
