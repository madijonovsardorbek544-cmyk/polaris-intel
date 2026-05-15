from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class IntelItem:
    title: str
    summary: str
    category: str
    risk_score: int
    risk_level: str
    source: str
    tags: list[str]
    created_at: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
