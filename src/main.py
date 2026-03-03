from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime
import feedparser
import re

app = FastAPI(title="POLARIS Intel", version="1.0.0")

templates = Jinja2Templates(directory="src/templates")

# RSS manbalar (xohlasang keyin ko'paytiramiz)
RSS_FEEDS = [
    # Geopolitics / world
    "https://www.aljazeera.com/xml/rss/all.xml",
    "http://feeds.bbci.co.uk/news/world/rss.xml",
    "http://feeds.bbci.co.uk/news/technology/rss.xml",
    # Cyber-ish sources
    "https://www.cisa.gov/uscert/ncas/alerts.xml",
]

# --- RISK SCORING (0-100) ---
RISK_LEVELS = [
    (80, "Critical"),
    (60, "High"),
    (30, "Medium"),
    (0,  "Low"),
]

KEYWORDS = {
    30: ["airstrike", "missile", "drone strike", "bombing", "invasion", "hostage", "killed", "dead"],
    20: ["attack", "explosion", "clash", "escalation", "military", "terror", "evacuation"],
    12: ["sanctions", "border", "mobilization", "warning", "threat", "tension", "rhetoric"],

    30: ["ransomware", "zero-day", "0day", "data breach", "critical infrastructure"],
    20: ["malware", "exploit", "ddos", "leak", "stolen", "credential", "phishing campaign"],
    12: ["phishing", "ioc", "vulnerability", "incident", "compromised"],
}

def compute_risk(title: str, summary: str) -> tuple[int, str, list[str]]:
    text = f"{title} {summary}".lower().strip()

    if len(text) < 10:
        return 0, "Low", ["empty"]

    score = 10  # baseline: 0 bo'lib qolmasin
    signals = []

    for weight, words in KEYWORDS.items():
        for w in words:
            if w in text:
                score += weight
                signals.append(w)

    # bonuslar
    if re.search(r"\b(killed|dead|injured|casualties)\b", text):
        score = int(score * 1.15)
        signals.append("impact")

    if re.search(r"\b(breaking|urgent|live)\b", text):
        score += 7
        signals.append("urgent")

    score = max(0, min(100, score))

    level = "Low"
    for threshold, name in RISK_LEVELS:
        if score >= threshold:
            level = name
            break

    return score, level, signals

def guess_category(title: str, summary: str) -> str:
    t = f"{title} {summary}".lower()
    cyber_words = ["ransomware", "malware", "phishing", "zero-day", "breach", "ddos", "exploit", "vulnerability", "ioc"]
    war_words = ["war", "attack", "airstrike", "missile", "drone", "invasion", "sanctions", "military", "ceasefire"]
    if any(w in t for w in cyber_words):
        return "Cyber"
    if any(w in t for w in war_words):
        return "Geopolitics"
    return "General"

def fetch_rss_items(limit: int = 20):
    items = []
    for url in RSS_FEEDS:
        feed = feedparser.parse(url)
        for e in feed.entries[:10]:
            title = (e.get("title") or "").strip()
            summary = (e.get("summary") or e.get("description") or "").strip()
            link = e.get("link") or url

            risk_score, risk_level, signals = compute_risk(title, summary)
            category = guess_category(title, summary)

            items.append({
                "title": title[:180],
                "summary": re.sub(r"\s+", " ", summary)[:220],
                "category": category,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "source": link,
                "tags": list(set(signals[:6] + ["rss", "auto"])),
                "created_at": datetime.utcnow().isoformat(),
            })

    # risk bo'yicha saralash (eng xavfli yuqoriga)
    items.sort(key=lambda x: x["risk_score"], reverse=True)
    return items[:limit]

# UI
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Health
@app.get("/health", response_class=JSONResponse)
def health():
    return {"status": "ok", "app": "polaris-intel"}

# Latest
@app.get("/api/latest", response_class=JSONResponse)
def api_latest():
    return fetch_rss_items(limit=20)