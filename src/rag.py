"""
rag.py

Builds and loads a RAG (Retrieval-Augmented Generation) knowledge base
from the MITRE ATT&CK Enterprise dataset.

Two document collections are extracted from the same source file:
  - Attack Techniques (attack-pattern): Used by the Threat Analyst agent
  - Mitigations (course-of-action): Used by the IR Advisor agent

Techniques and mitigations are embedded into a local ChromaDB vector store.
At query time, the retriever surfaces the most semantically relevant documents.
"""

import json
from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

from logging_utils import get_audit_logger
from rag_integrity import write_manifest

# ── Logging setup ──────────────────────────────────────────────────────────────
logger = get_audit_logger("rag", "rag.log")

# ── Constants ──────────────────────────────────────────────────────────────────
MITRE_DATA_PATH = Path("data/mitre_attack.json")
CHROMA_PERSIST_DIR = "chroma_db"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Number of relevant documents to retrieve per query
TOP_K_RESULTS = 3


def _extract_techniques(mitre_data: dict[str, Any]) -> list[Document]:
    """
    Extract attack techniques (attack-pattern) from MITRE ATT&CK JSON.
    Deprecated and revoked techniques are skipped.

    Args:
        mitre_data: Parsed MITRE ATT&CK JSON content.

    Returns:
        List of Document objects, one per active technique.
    """
    documents = []

    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        technique_id = "UNKNOWN"
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "UNKNOWN")
                break

        name = obj.get("name", "Unnamed Technique")
        description = obj.get("description", "No description available.")
        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
        ]

        content = (
            f"Technique ID: {technique_id}\n"
            f"Name: {name}\n"
            f"Tactics: {', '.join(tactics)}\n"
            f"Description: {description}"
        )

        documents.append(Document(
            page_content=content,
            metadata={
                "type": "technique",
                "technique_id": technique_id,
                "name": name,
                "tactics": ", ".join(tactics)
            }
        ))

    return documents


def _extract_mitigations(mitre_data: dict[str, Any]) -> list[Document]:
    """
    Extract mitigations (course-of-action) from MITRE ATT&CK JSON.
    These are MITRE's recommended defensive measures mapped to techniques.

    Args:
        mitre_data: Parsed MITRE ATT&CK JSON content.

    Returns:
        List of Document objects, one per mitigation.
    """
    documents = []

    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "course-of-action":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        mitigation_id = "UNKNOWN"
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitigation_id = ref.get("external_id", "UNKNOWN")
                break

        name = obj.get("name", "Unnamed Mitigation")
        description = obj.get("description", "No description available.")

        content = (
            f"Mitigation ID: {mitigation_id}\n"
            f"Name: {name}\n"
            f"Description: {description}"
        )

        documents.append(Document(
            page_content=content,
            metadata={
                "type": "mitigation",
                "mitigation_id": mitigation_id,
                "name": name
            }
        ))

    return documents


def build_vector_store() -> Chroma:
    """
    Load MITRE ATT&CK data, extract techniques and mitigations, embed them,
    and persist the combined vector store to disk.

    Runs once — subsequent calls should use load_vector_store() instead.

    Returns:
        A Chroma vector store instance ready for retrieval.

    Raises:
        FileNotFoundError: If the MITRE ATT&CK JSON file is missing.
        ValueError: If no documents are extracted.
    """
    if not MITRE_DATA_PATH.exists():
        raise FileNotFoundError(
            f"MITRE ATT&CK data not found at {MITRE_DATA_PATH}. "
            "See the Setup section of the README for the download command."
        )

    logger.info("Loading MITRE ATT&CK data from %s", MITRE_DATA_PATH)

    with open(MITRE_DATA_PATH, "r", encoding="utf-8") as f:
        mitre_data = json.load(f)

    techniques = _extract_techniques(mitre_data)
    mitigations = _extract_mitigations(mitre_data)
    all_documents = techniques + mitigations

    if not all_documents:
        raise ValueError("No documents extracted from MITRE ATT&CK data.")

    logger.info(
        "Extracted %d techniques and %d mitigations (%d total)",
        len(techniques), len(mitigations), len(all_documents)
    )
    print(f"📚 Extracted {len(techniques)} techniques + {len(mitigations)} mitigations")
    print("⏳ Embedding into ChromaDB — this takes 3–5 minutes on first run...")

    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)

    vector_store = Chroma.from_documents(
        documents=all_documents,
        embedding=embeddings,
        persist_directory=CHROMA_PERSIST_DIR
    )

    # Provenance manifest, stored outside the vector DB (see rag_integrity.py)
    write_manifest((d.page_content for d in all_documents), source=str(MITRE_DATA_PATH))

    logger.info("Vector store built and persisted to %s", CHROMA_PERSIST_DIR)
    print(f"✅ Vector store saved to {CHROMA_PERSIST_DIR}/ (+ provenance manifest)")

    return vector_store


def load_vector_store() -> Chroma:
    """
    Load an already-persisted ChromaDB vector store from disk.

    Returns:
        A Chroma vector store instance ready for retrieval.

    Raises:
        FileNotFoundError: If the ChromaDB directory does not exist.
    """
    if not Path(CHROMA_PERSIST_DIR).exists():
        raise FileNotFoundError(
            f"No vector store found at '{CHROMA_PERSIST_DIR}'. "
            "Run build_vector_store() first."
        )

    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)

    vector_store = Chroma(
        persist_directory=CHROMA_PERSIST_DIR,
        embedding_function=embeddings
    )

    logger.info("Vector store loaded from %s", CHROMA_PERSIST_DIR)
    return vector_store


def get_retriever(doc_type: str | None = None, k: int = TOP_K_RESULTS):
    """
    Return a retriever over the persisted vector store.
    Builds the store on first run, loads from disk on subsequent runs.

    Args:
        doc_type: "technique" or "mitigation" to restrict results to one
            collection type (metadata filter), or None for both.
        k: Number of documents to return.
    """
    if Path(CHROMA_PERSIST_DIR).exists():
        vector_store = load_vector_store()
    else:
        vector_store = build_vector_store()

    search_kwargs: dict[str, Any] = {"k": k}
    if doc_type:
        search_kwargs["filter"] = {"type": doc_type}
    return vector_store.as_retriever(search_kwargs=search_kwargs)


if __name__ == "__main__":
    import shutil
    import sys

    if "--manifest-only" in sys.argv:
        # Document text is deterministic from the ATT&CK bundle, so an existing
        # store can be given a manifest without re-embedding everything.
        with open(MITRE_DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        docs = _extract_techniques(data) + _extract_mitigations(data)
        n = write_manifest((d.page_content for d in docs), source=str(MITRE_DATA_PATH))
        sys.exit(f"✅ Wrote provenance manifest for {n} documents (store not rebuilt)")

    # Full rebuild so the provenance manifest matches the store
    if Path(CHROMA_PERSIST_DIR).exists():
        if "--yes" not in sys.argv and input(f"Rebuild '{CHROMA_PERSIST_DIR}'? [y/N] ").strip().lower() != "y":
            sys.exit("Aborted.")
        shutil.rmtree(CHROMA_PERSIST_DIR)

    build_vector_store()

    print("\n🔍 Technique query: 'employee downloading large amounts of data after hours'")
    for i, doc in enumerate(get_retriever("technique").invoke(
            "employee downloading large amounts of data after hours"), 1):
        print(f"  {i}. {doc.metadata.get('technique_id')} — {doc.metadata.get('name')}")

    print("\n🔍 Mitigation query: 'prevent unauthorized data exfiltration'")
    for i, doc in enumerate(get_retriever("mitigation").invoke(
            "how to prevent unauthorized data exfiltration"), 1):
        print(f"  {i}. {doc.metadata.get('mitigation_id')} — {doc.metadata.get('name')}")

    print("\n✅ RAG knowledge base ready")
