from datetime import datetime
from typing import Optional

from sqlmodel import Field, SQLModel


class FeedSource(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    url: str = Field(unique=True, index=True)
    category: str = Field(default="cyber")
    enabled: bool = Field(default=True)
    last_checked_at: Optional[datetime] = None


class IntelItem(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source_name: str = Field(index=True)
    title: str
    link: str = Field(unique=True, index=True)
    summary: str = ""
    category: str = Field(default="cyber", index=True)
    published_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    severity: str = Field(default="medium", index=True)
    risk_score: int = Field(default=50, index=True)
    tags: str = Field(default="")
