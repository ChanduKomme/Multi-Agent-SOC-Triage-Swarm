"""Lightweight RAG store over past incident writeups.

Deliberately dependency-free (stdlib TF-IDF + cosine) so the project runs offline and
every step is inspectable. Swap in chromadb or pgvector later -- the retrieve()
signature is the only contract the Enrichment Agent depends on.

Security relevance: this store is *shared context*. Anything an attacker gets written
into a past-incident writeup becomes retrievable instruction-shaped text for every
future triage run. See "shared-context poisoning" in the README.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "is", "was",
    "were", "be", "been", "that", "this", "it", "as", "at", "by", "from", "not", "are",
}


def tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_.\\-]{3,}", text.lower()) if t not in STOPWORDS]


@dataclass
class Doc:
    doc_id: str
    text: str
    tf: Counter


@dataclass
class Hit:
    doc_id: str
    score: float
    excerpt: str


class IncidentRagStore:
    """TF-IDF retrieval over data/past_incidents/*.md."""

    def __init__(self, corpus_dir: Path):
        self.docs: list[Doc] = []
        for path in sorted(corpus_dir.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            self.docs.append(Doc(path.stem, text, Counter(tokenize(text))))
        if not self.docs:
            raise RuntimeError(f"no incident writeups found under {corpus_dir}")
        self.idf = self._build_idf()

    def _build_idf(self) -> dict[str, float]:
        n = len(self.docs)
        df: Counter = Counter()
        for doc in self.docs:
            df.update(set(doc.tf))
        return {term: math.log((n + 1) / (count + 1)) + 1.0 for term, count in df.items()}

    def _vector(self, tf: Counter) -> dict[str, float]:
        vec = {t: (1 + math.log(c)) * self.idf.get(t, 1.0) for t, c in tf.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {t: v / norm for t, v in vec.items()}

    def retrieve(self, query: str, k: int = 3, min_score: float = 0.02) -> list[Hit]:
        qv = self._vector(Counter(tokenize(query)))
        scored: list[Hit] = []
        for doc in self.docs:
            dv = self._vector(doc.tf)
            score = sum(w * dv.get(t, 0.0) for t, w in qv.items())
            if score >= min_score:
                scored.append(Hit(doc.doc_id, round(score, 4), self._excerpt(doc.text)))
        scored.sort(key=lambda h: h.score, reverse=True)
        return scored[:k]

    @staticmethod
    def _excerpt(text: str, limit: int = 900) -> str:
        body = " ".join(text.split())
        return body[:limit] + (" ..." if len(body) > limit else "")


def alert_to_query(alert: dict) -> str:
    """Build a retrieval query from the structured (not free-text) parts of an alert.

    Free-text analyst notes are excluded on purpose: letting attacker-controlled text
    steer retrieval is a cheap way to pull a chosen 'precedent' into the context.
    """
    fields = ("rule", "source", "host", "user", "src_ip", "dest_ip")
    values = [alert.get(field) for field in fields]
    return " ".join(value[:120] for value in values if isinstance(value, str))
