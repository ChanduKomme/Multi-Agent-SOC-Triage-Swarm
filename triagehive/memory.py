"""Incident memory: BM25 retrieval over past incident reviews.

Author: Chandu Komme

Each past incident review (``data/memory/*.md``) is a document with a header line
holding its verdict, severity and ATT&CK techniques. Retrieval ranks documents
with Okapi BM25 and adds a bonus for every technique shared with the alert,
because "same technique" is the strongest precedent signal an analyst uses.

Retrieved text is reference material written by humans, but it still reaches the
agents through the same guard as alert text (memory can be poisoned too).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

__author__ = "Chandu Komme"

DEFAULT_MEMORY = Path(__file__).resolve().parent.parent / "data" / "memory"
_TOKEN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")
_STOP = set("the a an and or of to in on for with from by is was were be as at it its this that then than "
            "into after before within not no any".split())
_HEADER = re.compile(r"verdict:\s*(\w+)\s*\|\s*severity:\s*(\w+)\s*\|\s*techniques:\s*(.+)", re.I)


def tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


@dataclass(frozen=True)
class Precedent:
    doc_id: str
    title: str
    verdict: str
    severity: str
    techniques: tuple[str, ...]
    score: float
    lesson: str


class IncidentMemory:
    k1, b = 1.4, 0.75

    def __init__(self, root: str | Path = DEFAULT_MEMORY) -> None:
        self.docs = []
        for path in sorted(Path(root).glob("*.md")):
            text = path.read_text(encoding="utf-8")
            title = text.splitlines()[0].lstrip("# ").strip()
            head = _HEADER.search(text)
            verdict, severity, techniques = ("unknown", "unknown", ())
            if head:
                verdict, severity = head.group(1).lower(), head.group(2).lower()
                techniques = tuple(t.strip() for t in head.group(3).split(","))
            lesson = text.split("Lesson:")[-1].strip().split("\n")[0] if "Lesson:" in text else ""
            toks = tokens(text)
            self.docs.append({"id": path.stem.split("-")[0] + "-" + "-".join(path.stem.split("-")[1:3]),
                              "title": title, "verdict": verdict, "severity": severity, "techniques": techniques,
                              "tf": Counter(toks), "len": len(toks), "lesson": lesson})
        self.avg_len = sum(d["len"] for d in self.docs) / max(len(self.docs), 1)
        df = Counter(t for d in self.docs for t in d["tf"])
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def search(self, query: str, techniques: tuple[str, ...] = (), k: int = 2, min_score: float = 1.5) -> list[Precedent]:
        q = tokens(query)
        ranked = []
        for doc in self.docs:
            score = 0.0
            for term in q:
                f = doc["tf"].get(term, 0)
                if f:
                    norm = f + self.k1 * (1 - self.b + self.b * doc["len"] / self.avg_len)
                    score += self.idf[term] * f * (self.k1 + 1) / norm
            shared = {t.split(".")[0] for t in techniques} & {t.split(".")[0] for t in doc["techniques"]}
            score += 2.0 * len(shared)
            if score >= min_score:
                ranked.append(Precedent(doc["id"], doc["title"], doc["verdict"], doc["severity"],
                                        doc["techniques"], round(score, 2), doc["lesson"]))
        ranked.sort(key=lambda p: -p.score)
        return ranked[:k]
