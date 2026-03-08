from __future__ import annotations
import asyncio
import html
import os
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

# =========================================================
# CONFIG
# =========================================================

APP_NAME = "POLARIS Intel"
APP_VERSION = "3.0.0"

MAX_ITEMS = 60
AUTO_REFRESH_SECONDS = 900
HTTP_TIMEOUT = 15.0

FEEDS = [
    "https://www.cisa.gov/news-events/cybersecurity-advisories.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.reutersagency.com/feed/?best-topics=world&post_type=best",
]

# =========================================================
# DATA MODEL
# =========================================================

@dataclass
class IntelItem:
    title: str
    summary: str
    category: str
    risk_score: int
    risk_level: str
    source: str
    tags: List[str]
    created_at: str

app = FastAPI(title=APP_NAME, version=APP_VERSION)

_STORE: List[IntelItem] = []
_LAST_REFRESH = 0
_LOCK = asyncio.Lock()

# =========================================================
# UTILITIES
# =========================================================

TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def strip_html(text: str):
    if not text:
        return ""
    text = html.unescape(text)
    text = TAG_RE.sub(" ", text)
    text = WS_RE.sub(" ", text)
    return text.strip()

def shorten(text: str, limit=250):
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"

def host(url: str):
    try:
        return urlparse(url).netloc
    except:
        return ""

# =========================================================
# CATEGORY
# =========================================================

def classify(title, summary):
    t = f"{title} {summary}".lower()

    cyber = any(x in t for x in [
        "cve", "exploit", "ransomware", "malware",
        "phishing", "breach", "leak", "patch", "zero-day"
    ])

    geo = any(x in t for x in [
        "war", "missile", "drone", "strike",
        "conflict", "military", "sanction",
        "election", "border", "attack"
    ])

    if cyber and geo:
        return "Hybrid"
    if cyber:
        return "Cyber"
    if geo:
        return "Geopolitics"
    return "General"

# =========================================================
# RISK ENGINE
# =========================================================

def score_risk(title, summary, category):
    text = f"{title} {summary}".lower()
    score = 20

    weights = {
        "critical": 25,
        "zero-day": 25,
        "ransomware": 20,
        "cve": 15,
        "exploit": 15,
        "breach": 15,
        "missile": 20,
        "war": 18,
        "attack": 12,
        "drone": 15,
        "nuclear": 25,
    }

    for k, v in weights.items():
        if k in text:
            score += v

    if category == "Hybrid":
        score += 10

    score = max(20, min(score, 100))
    return score

def risk_level(score):
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"

# =========================================================
# RSS PARSER
# =========================================================

def parse_rss(xml, fallback):
    items = re.findall(r"<item.*?>.*?</item>", xml, re.S)
    out = []
    for block in items[:MAX_ITEMS]:
        title = re.search(r"<title>(.*?)</title>", block, re.S)
        desc = re.search(r"<description>(.*?)</description>", block, re.S)
        link = re.search(r"<link>(.*?)</link>", block, re.S)

        title = strip_html(title.group(1)) if title else ""
        summary = strip_html(desc.group(1)) if desc else ""
        link = link.group(1).strip() if link else fallback

        out.append({
            "title": title,
            "summary": summary,
            "link": link
        })
    return out

# =========================================================
# FETCH
# =========================================================

async def fetch_feed(client, url):
    try:
        r = await client.get(url, timeout=HTTP_TIMEOUT)
        entries = parse_rss(r.text, url)

        result = []
        for e in entries:
            title = e["title"]
            summary = shorten(e["summary"])
            category = classify(title, summary)
            score = score_risk(title, summary, category)
            level = risk_level(score)

            result.append(
                IntelItem(
                    title=title,
                    summary=summary,
                    category=category,
                    risk_score=score,
                    risk_level=level,
                    source=e["link"],
                    tags=[],
                    created_at=now_iso()
                )
            )
        return result
    except:
        return []

async def refresh():
    global _STORE, _LAST_REFRESH
    async with _LOCK:
        now = time.time()
        if now - _LAST_REFRESH < AUTO_REFRESH_SECONDS and _STORE:
            return

        async with httpx.AsyncClient() as client:
            tasks = [fetch_feed(client, f) for f in FEEDS]
            results = await asyncio.gather(*tasks)

        merged = []
        for r in results:
            merged.extend(r)

        merged.sort(key=lambda x: x.risk_score, reverse=True)
        _STORE = merged[:MAX_ITEMS]
        _LAST_REFRESH = time.time()

@app.on_event("startup")
async def startup():
    asyncio.create_task(refresh())

# =========================================================
# API
# =========================================================

@app.get("/api/latest")
async def latest():
    async with _LOCK:
        return JSONResponse([asdict(x) for x in _STORE])

@app.post("/api/refresh")
async def force_refresh():
    await refresh()
    return {"ok": True}

# =========================================================
# UI
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    await refresh()

    async with _LOCK:
        items = list(_STORE)

    cards = ""
    for i in items:
        cards += f"""
        <div class="card">
          <h3>{html.escape(i.title)}</h3>
          <p>{html.escape(i.summary)}</p>
          <div class="meta">
            <span class="pill {i.risk_level.lower()}">{i.risk_level} ({i.risk_score})</span>
            <span class="pill ghost">{i.category}</span>
          </div>
          <a href="{html.escape(i.source)}" target="_blank">Source</a>
        </div>
        """

    return HTMLResponse(f"""
<!doctype html>
<html>
<head>
<title>{APP_NAME}</title>
<style>
body{{background:#0b1220;color:white;font-family:sans-serif;padding:30px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px}}
.card{{background:#101a30;padding:20px;border-radius:14px}}
.pill{{padding:6px 10px;border-radius:999px;font-size:12px}}
.low{{background:#1c3d6e}}
.medium{{background:#6e5a1c}}
.high{{background:#6e2c2c}}
.critical{{background:#8c1f1f}}
.ghost{{background:#222}}
</style>
</head>
<body>
<h1>{APP_NAME}</h1>
<div class="grid">{cards}</div>
</body>
</html>
""")