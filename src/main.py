import os
import feedparser
from datetime import datetime

from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session


# -----------------------------
# App + Templates
# -----------------------------
app = FastAPI(title="POLARIS Intel", version="1.0.0")
templates = Jinja2Templates(directory="src/templates")


# -----------------------------
# Database (Postgres on Railway)
# -----------------------------
DATABASE_URL = os.getenv("DATABASE_URL")

# Fallback: local run uchun SQLite (agar DATABASE_URL yo'q bo'lsa)
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./polaris.db"

# SQLite uchun special arg
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Risk(Base):
    __tablename__ = "risks"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    category = Column(String, nullable=True)       # Cyber / Geopolitics / Economic / Conflict
    risk_score = Column(Integer, nullable=True)    # 0-100
    risk_level = Column(String, nullable=True)     # Low/Medium/High/Critical
    source = Column(String, nullable=True)
    tags = Column(Text, nullable=True)             # comma-separated
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------
# Routes
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health", response_class=JSONResponse)
def health():
    return {"status": "ok", "app": "polaris-intel"}


@app.get("/api/latest", response_class=JSONResponse)
def api_latest(db: Session = Depends(get_db)):
    risks = db.query(Risk).order_by(Risk.created_at.desc()).limit(30).all()
    return [
        {
            "title": r.title,
            "summary": r.summary or "",
            "category": r.category or "",
            "risk_score": r.risk_score if r.risk_score is not None else 0,
            "risk_level": r.risk_level or "",
            "source": r.source or "",
            "tags": [t.strip() for t in (r.tags or "").split(",") if t.strip()],
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in risks
    ]


# (Optional) Demo data qo'shish: 1 marta chaqirasan, keyin UI da chiqadi
@app.post("/api/seed", response_class=JSONResponse)
def seed(db: Session = Depends(get_db)):
    # Agar DB bo'sh bo'lsa seed qiladi
    exists = db.query(Risk).first()
    if exists:
        return {"ok": True, "seeded": False, "reason": "already_has_data"}

    demo = [
        Risk(
            title="Sample cyber threat detected",
            summary="Suspicious activity indicates possible credential abuse. Investigate logs and alerts.",
            category="Cyber",
            risk_score=78,
            risk_level="High",
            source="https://example.com/cyber-alert",
            tags="phishing,credentials,ioc",
        ),
        Risk(
            title="Geopolitical tension rising in region",
            summary="Diplomatic friction and increased rhetoric suggest elevated escalation risk.",
            category="Geopolitics",
            risk_score=65,
            risk_level="Medium",
            source="https://example.com/geopolitics-brief",
            tags="diplomacy,trade,monitor",
        ),
    ]
    db.add_all(demo)
    db.commit()
    return {"ok": True, "seeded": True, "count": len(demo)}
# -----------------------------
# SIMPLE RISK SCORING ENGINE
# -----------------------------
KEYWORD_WEIGHTS = {
    "war": 25,
    "conflict": 20,
    "attack": 20,
    "cyber": 15,
    "missile": 25,
    "nuclear": 40,
    "sanction": 15,
    "military": 20,
    "invasion": 35,
    "escalation": 30,
    "tension": 15,
    "retaliation": 25,
}


def calculate_risk_score(text: str):
    score = 0
    text_lower = text.lower()

    for word, weight in KEYWORD_WEIGHTS.items():
        if word in text_lower:
            score += weight

    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return min(score, 100), level


# -----------------------------
# RSS COLLECTOR
# -----------------------------
RSS_FEEDS = [
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://www.reutersagency.com/feed/?best-topics=politics",
]


@app.post("/api/collect")
def collect_rss(db: Session = Depends(get_db)):
    new_items = 0

    for feed_url in RSS_FEEDS:
        feed = feedparser.parse(feed_url)

        for entry in feed.entries[:10]:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            link = entry.get("link", "")

            combined_text = f"{title} {summary}"

            # Duplicate check
            existing = db.query(Risk).filter(Risk.source == link).first()
            if existing:
                continue

            score, level = calculate_risk_score(combined_text)

            risk = Risk(
                title=title,
                summary=summary[:500],
                category="Geopolitics",
                risk_score=score,
                risk_level=level,
                source=link,
                tags="rss,auto",
            )

            db.add(risk)
            new_items += 1

    db.commit()

    return {"collected": new_items}