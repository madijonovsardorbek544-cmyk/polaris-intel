
from __future__ import annotations

import os
import re
import time
import json
import hashlib
import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
import feedparser
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware


APP_NAME = "POLARIS Intel"
APP_VERSION = "1.0.0"

# -----------------------------
# Config (ENV)
# -----------------------------
# Comma-separated RSS urls:
# example:
# RSS_URLS="https://www.cisa.gov/news.xml,https://www.aljazeera.com/xml/rss/all.xml"
RSS_URLS = os.getenv("RSS_URLS", "").strip()

# default sources (if env not provided)
DEFAULT_RSS_URLS = [
    # Geopolitics / world news
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    # Cyber / security (some feeds are heavy; keep 1-2)
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
]

MAX_ITEMS = int(os.getenv("MAX_ITEMS", "60"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "12"))
FETCH_EVERY_SECONDS = int(os.getenv("FETCH_EVERY_SECONDS", "180"))  # cache TTL
USER_AGENT = os.getenv(
    "USER_AGENT",
    "POLARIS-Intel/1.0 (+portfolio; contact: github.com)",
).strip()

# -----------------------------
# Risk scoring keywords
# -----------------------------
# You can tune these later.
CYBER_CRITICAL = [
    "zero-day", "0day", "rce", "remote code execution", "wormable",
    "active exploitation", "actively exploited", "in the wild",
    "critical infrastructure", "ics", "scada", "ransomware",
    "mass exploitation", "botnet", "supply chain", "backdoor",
]
CYBER_HIGH = [
    "exploit", "credential", "phishing", "breach", "leak", "malware",
    "ddos", "cve-", "vulnerability", "patch now", "mitigation",
    "privilege escalation", "lateral movement", "data exfiltration",
]
GEO_CRITICAL = [
    "invasion", "airstrike", "missile", "nuclear", "chemical", "biological",
    "mobilization", "state of war", "martial law", "genocide",
]
GEO_HIGH = [
    "attack", "sanctions", "ceasefire", "hostage", "border clash",
    "drone", "strike", "terror", "military", "escalation",
]

TAG_RULES = {
    # cyber
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "ransomware": r"\bransomware\b",
    "phishing": r"\bphishing\b",
    "credentials": r"\bcredential(s)?\b",
    "exploit": r"\bexploit(ation)?\b",
    "leak": r"\bleak(ed)?\b|\bdata leak\b",
    "ddos": r"\bddos\b",
    "zero-day": r"\bzero[- ]day\b|\b0day\b",
    # geopolitics
    "sanctions": r"\bsanction(s)?\b",
    "ceasefire": r"\bceasefire\b",
    "strike": r"\bstrike(s)?\b|\bairstrike(s)?\b",
    "diplomacy": r"\bdiplomac(y|ic)\b",
    "trade": r"\btrade\b|\btariff(s)?\b",
    "monitor": r"\bmonitor\b|\bwatch\b|\balarm\b",
}


# -----------------------------
# Helpers
# -----------------------------
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def stable_id(title: str, source: str) -> str:
    h = hashlib.sha256((title + "||" + source).encode("utf-8", errors="ignore")).hexdigest()
    return h[:16]

def strip_html(text: str) -> str:
    if not text:
        return ""
    # remove tags
    text = re.sub(r"<script.*?>.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style.*?>.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    # decode basic entities without external libs
    text = (
        text.replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", '"')
            .replace("&#39;", "'")
    )
    text = re.sub(r"\s+", " ", text).strip()
    return text

def guess_category(title: str, summary: str, url: str) -> str:
    t = f"{title} {summary} {url}".lower()
    cyber_hits = sum(1 for w in CYBER_HIGH + CYBER_CRITICAL if w in t) + (1 if "cve-" in t else 0)
    geo_hits = sum(1 for w in GEO_HIGH + GEO_CRITICAL if w in t)
    if cyber_hits > geo_hits:
        return "Cyber"
    if geo_hits > cyber_hits:
        return "Geopolitics"
    return "General"

def extract_tags(title: str, summary: str) -> List[str]:
    t = f"{title} {summary}".lower()
    tags: List[str] = []
    for tag, pattern in TAG_RULES.items():
        if re.search(pattern, t, flags=re.I):
            tags.append(tag)
    # extract CVEs
    cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", f"{title} {summary}", flags=re.I)
    for c in cves[:3]:
        tags.append(c.upper())
    # de-dup preserve order
    seen = set()
    out = []
    for x in tags:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out[:10]

def score_risk(title: str, summary: str, url: str, category: str) -> Tuple[int, str]:
    text = f"{title} {summary} {url}".lower()

    score = 5  # base

    # domain weighting (simple)
    host = (urlparse(url).netloc or "").lower()
    if "cisa.gov" in host:
        score += 25
    if "mitre.org" in host or "nvd.nist.gov" in host:
        score += 18
    if "bbc.co.uk" in host or "reuters.com" in host:
        score += 10

    # keyword boosts
    for w in CYBER_HIGH:
        if w in text:
            score += 8
    for w in CYBER_CRITICAL:
        if w in text:
            score += 14

    for w in GEO_HIGH:
        if w in text:
            score += 7
    for w in GEO_CRITICAL:
        if w in text:
            score += 13

    # CVE presence
    if re.search(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.I):
        score += 12

    # if category strongly Cyber and mentions "active exploitation" etc.
    if category == "Cyber":
        if "actively exploited" in text or "in the wild" in text or "active exploitation" in text:
            score += 18
        if "ransomware" in text:
            score += 14

    if category == "Geopolitics":
        if "airstrike" in text or "missile" in text or "invasion" in text:
            score += 15
        if "sanction" in text:
            score += 10

    score = clamp(int(score), 0, 100)

    if score >= 85:
        level = "Critical"
    elif score >= 65:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"

    return score, level


# -----------------------------
# Data model (in-memory store)
# -----------------------------
@dataclass
class IntelItem:
    id: str
    title: str
    summary: str
    category: str
    risk_score: int
    risk_level: str
    source: str
    tags: List[str]
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "category": self.category,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "source": self.source,
            "tags": self.tags,
            "created_at": self.created_at,
        }


class Store:
    def __init__(self) -> None:
        self.items: List[IntelItem] = []
        self.last_fetch_ts: float = 0.0

    def set_items(self, items: List[IntelItem]) -> None:
        self.items = items

    def get_items(self) -> List[IntelItem]:
        return self.items

    def is_stale(self) -> bool:
        return (time.time() - self.last_fetch_ts) > FETCH_EVERY_SECONDS

    def touch_fetch(self) -> None:
        self.last_fetch_ts = time.time()


store = Store()

# -----------------------------
# Fetch logic
# -----------------------------
def get_rss_urls() -> List[str]:
    if RSS_URLS:
        urls = [u.strip() for u in RSS_URLS.split(",") if u.strip()]
        return urls or DEFAULT_RSS_URLS
    return DEFAULT_RSS_URLS

async def fetch_text(client: httpx.AsyncClient, url: str) -> str:
    r = await client.get(url, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return r.text

def parse_feed(feed_text: str, fallback_source_url: str) -> List[Dict[str, Any]]:
    parsed = feedparser.parse(feed_text)
    out: List[Dict[str, Any]] = []
    for e in parsed.entries[:MAX_ITEMS]:
        title = (getattr(e, "title", None) or "").strip()
        link = (getattr(e, "link", None) or fallback_source_url).strip()

        # summary / description can vary by feed
        summary_raw = (
            getattr(e, "summary", None)
            or getattr(e, "description", None)
            or ""
        )
        summary = strip_html(str(summary_raw))
        if not summary:
            summary = "No summary provided."

        out.append({
            "title": title or "Untitled",
            "link": link or fallback_source_url,
            "summary": summary,
        })
    return out

async def refresh_items(force: bool = False) -> Dict[str, Any]:
    if not force and not store.is_stale() and store.get_items():
        return {"status": "cached", "count": len(store.get_items()), "fetched_at": now_utc_iso()}

    urls = get_rss_urls()
    items: List[IntelItem] = []

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        tasks = [fetch_text(client, u) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for url, res in zip(urls, results):
        if isinstance(res, Exception):
            # skip bad feed but keep system alive
            continue

        for it in parse_feed(res, url):
            title = it["title"]
            summary = it["summary"]
            link = it["link"]

            category = guess_category(title, summary, link)
            tags = extract_tags(title, summary)
            risk_score, risk_level = score_risk(title, summary, link, category)

            item = IntelItem(
                id=stable_id(title, link),
                title=title,
                summary=summary,
                category=category,
                risk_score=risk_score,
                risk_level=risk_level,
                source=link,
                tags=tags,
                created_at=now_utc_iso(),
            )
            items.append(item)

    # de-dup by id, keep highest risk if duplicates
    by_id: Dict[str, IntelItem] = {}
    for it in items:
        if it.id not in by_id:
            by_id[it.id] = it
        else:
            if it.risk_score > by_id[it.id].risk_score:
                by_id[it.id] = it

    final_items = list(by_id.values())
    final_items.sort(key=lambda x: x.risk_score, reverse=True)
    final_items = final_items[:MAX_ITEMS]

    store.set_items(final_items)
    store.touch_fetch()

    return {"status": "refreshed", "count": len(final_items), "fetched_at": now_utc_iso()}


# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(title=APP_NAME, version=APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# UI (single-file HTML)
# -----------------------------
def render_index(items: List[IntelItem], meta: Dict[str, Any]) -> str:
    # Minimal clean UI, mobile-friendly
    cards_html = ""
    for it in items:
        tags = " ".join([f'<span class="tag">#{t}</span>' for t in it.tags]) if it.tags else '<span class="tag">empty</span>'
        cards_html += f"""
        <div class="card" data-title="{it.title.lower()}" data-summary="{it.summary.lower()}" data-tags="{(' '.join(it.tags)).lower()}">
          <div class="title">{it.title}</div>
          <div class="summary">{it.summary}</div>
          <div class="meta">
            <span class="pill risk">{it.risk_level} ({it.risk_score})</span>
            <span class="pill cat">{it.category}</span>
          </div>
          <div class="tags">{tags}</div>
          <div class="source">Source: <a href="{it.source}" target="_blank" rel="noreferrer">{it.source}</a></div>
        </div>
        """

    status_line = f"Status: OK ({len(items)} items)"
    if meta.get("status") == "cached":
        status_line = f"Status: OK ({len(items)} items) — cached"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{APP_NAME}</title>
  <style>
    :root {{
      --bg: #070b12;
      --panel: rgba(255,255,255,0.06);
      --panel2: rgba(255,255,255,0.09);
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
      --border: rgba(255,255,255,0.12);
      --shadow: 0 16px 50px rgba(0,0,0,0.35);
      --radius: 18px;
    }}
    body {{
      margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 600px at 60% 20%, rgba(65,105,225,0.20), transparent 60%),
                  radial-gradient(900px 500px at 20% 40%, rgba(0,255,255,0.10), transparent 60%),
                  var(--bg);
      color: var(--text);
    }}
    .wrap {{
      max-width: 1100px; margin: 0 auto; padding: 28px 18px 40px;
    }}
    h1 {{
      margin: 0; font-size: 52px; letter-spacing: 0.5px;
    }}
    .status {{
      margin-top: 8px; color: var(--muted); font-size: 18px;
    }}
    .topbar {{
      display: flex; gap: 12px; align-items: center;
      margin-top: 18px; flex-wrap: wrap;
    }}
    button {{
      background: var(--panel2); color: var(--text);
      border: 1px solid var(--border);
      padding: 10px 14px; border-radius: 12px;
      cursor: pointer;
    }}
    input {{
      flex: 1; min-width: 220px;
      background: var(--panel); color: var(--text);
      border: 1px solid var(--border);
      padding: 12px 14px; border-radius: 12px;
      outline: none;
    }}
    .grid {{
      margin-top: 18px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
      gap: 16px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px 16px 14px;
      box-shadow: var(--shadow);
    }}
    .title {{
      font-weight: 700; font-size: 18px; line-height: 1.25;
      margin-bottom: 10px;
    }}
    .summary {{
      color: rgba(255,255,255,0.78);
      font-size: 14.5px;
      line-height: 1.5;
      min-height: 68px;
    }}
    .meta {{
      display: flex; gap: 10px; flex-wrap: wrap;
      margin-top: 12px;
    }}
    .pill {{
      font-size: 13px;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.05);
      color: rgba(255,255,255,0.86);
    }}
    .tags {{
      margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap;
    }}
    .tag {{
      font-size: 12.5px;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(255,255,255,0.04);
      color: rgba(255,255,255,0.72);
    }}
    .source {{
      margin-top: 10px;
      font-size: 13px;
      color: var(--muted);
      word-break: break-word;
    }}
    a {{ color: rgba(120,190,255,0.92); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .foot {{
      margin-top: 18px; color: var(--muted); font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{APP_NAME}</h1>
    <div class="status">{status_line}</div>

    <div class="topbar">
      <button id="reloadBtn">Reload</button>
      <input id="search" placeholder="Search title / summary / tags..." />
    </div>

    <div class="grid" id="grid">
      {cards_html if cards_html else '<div class="card"><div class="title">No items</div><div class="summary">empty</div></div>'}
    </div>

    <div class="foot">Tip: API endpoint → <a href="/api/latest">/api/latest</a> · Refresh → <a href="/api/refresh">/api/refresh</a></div>
  </div>

<script>
  const search = document.getElementById('search');
  const grid = document.getElementById('grid');
  const cards = Array.from(grid.querySelectorAll('.card'));

  function applyFilter(q) {{
    const s = q.trim().toLowerCase();
    cards.forEach(card => {{
      const hay = (card.dataset.title || '') + ' ' + (card.dataset.summary || '') + ' ' + (card.dataset.tags || '');
      card.style.display = hay.includes(s) ? '' : 'none';
    }});
  }}

  search.addEventListener('input', e => applyFilter(e.target.value));

  document.getElementById('reloadBtn').addEventListener('click', async () => {{
    try {{
      document.getElementById('reloadBtn').textContent = "Loading...";
      const r = await fetch('/api/refresh', {{method:'POST'}});
      await r.json();
      location.reload();
    }} catch (e) {{
      alert("Reload failed");
    }} finally {{
      document.getElementById('reloadBtn').textContent = "Reload";
    }}
  }});
</script>
</body>
</html>"""


# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
async def health():
    return {"ok": True, "name": APP_NAME, "version": APP_VERSION, "time": now_utc_iso()}

@app.get("/api/latest")
async def api_latest():
    # refresh if empty or stale
    meta = await refresh_items(force=False)
    items = [x.to_dict() for x in store.get_items()]
    return JSONResponse(items)

@app.post("/api/refresh")
async def api_refresh():
    meta = await refresh_items(force=True)
    return meta

@app.post("/api/seed")
async def api_seed(payload: Optional[Dict[str, Any]] = None):
    # Allows manual seeding (useful for demos)
    payload = payload or {}
    sample = payload.get("items") or []
    items: List[IntelItem] = []
    for e in sample[:MAX_ITEMS]:
        title = str(e.get("title") or "Untitled").strip()
        summary = strip_html(str(e.get("summary") or "No summary provided."))
        source = str(e.get("source") or "https://example.com").strip()
        category = str(e.get("category") or guess_category(title, summary, source)).strip()

        tags = e.get("tags")
        if not isinstance(tags, list):
            tags = extract_tags(title, summary)

        risk_score, risk_level = score_risk(title, summary, source, category)
        items.append(IntelItem(
            id=stable_id(title, source),
            title=title,
            summary=summary,
            category=category,
            risk_score=risk_score,
            risk_level=risk_level,
            source=source,
            tags=[str(t) for t in tags][:10],
            created_at=now_utc_iso(),
        ))

    store.set_items(items)
    store.touch_fetch()
    return {"status": "seeded", "count": len(items), "fetched_at": now_utc_iso()}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    meta = await refresh_items(force=False)
    html = render_index(store.get_items(), meta)
    return HTMLResponse(html)

# optional: old endpoint fallback (if you typed /latest by mistake)
@app.get("/latest")
async def legacy_latest():
    raise HTTPException(status_code=404, detail="Not Found (use /api/latest or /)")