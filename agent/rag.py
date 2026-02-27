"""
RAG (Retrieval-Augmented Generation) component.

Loads the CVE knowledge base into a FAISS vector store and exposes a
retrieval function that the agent calls as a tool.

Demonstrates:
  • Document loading and chunking
  • Embedding generation (OpenAI or HuggingFace fallback)
  • FAISS vector similarity search
  • Retrieval-augmented generation pattern
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"


def _load_cve_documents() -> list[Document]:
    """Load CVE entries from the JSON knowledge base as LangChain Documents."""
    cve_path = KNOWLEDGE_DIR / "cve_database.json"
    with open(cve_path) as f:
        cve_data = json.load(f)

    docs: list[Document] = []
    for entry in cve_data:
        content_parts = [
            f"ID: {entry['id']}",
            f"Name: {entry['name']}",
            f"Severity: {entry['severity']} (CVSS {entry['cvss']})",
            f"Affected: {entry['affected']}",
            f"Description: {entry['description']}",
            f"Exploitation: {entry['exploitation']}",
            f"Detection: {entry['detection']}",
            f"Remediation: {entry['remediation']}",
        ]
        docs.append(
            Document(
                page_content="\n".join(content_parts),
                metadata={"cve_id": entry["id"], "name": entry["name"]},
            )
        )
    return docs


class CVEKnowledgeBase:
    """Wraps the FAISS vector store for CVE lookups."""

    def __init__(self) -> None:
        self._embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        docs = _load_cve_documents()
        self._store = FAISS.from_documents(docs, self._embeddings)

    def search(self, query: str, k: int = 3) -> str:
        """Return the top-k most relevant CVE entries as formatted text."""
        results = self._store.similarity_search(query, k=k)
        if not results:
            return "No relevant CVE information found."

        sections: list[str] = []
        for i, doc in enumerate(results, 1):
            sections.append(
                f"--- Result {i} ({doc.metadata.get('cve_id', 'N/A')}) ---\n"
                f"{doc.page_content}"
            )
        return "\n\n".join(sections)
