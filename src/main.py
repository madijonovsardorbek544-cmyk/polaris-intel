from __future__ import annotations

import asyncio
import html
import os
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, List
from urllib.parse import urlparse

import httpx
import psycopg
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse


APP_NAME = "POLARIS Intel"
APP_VERSION = "2.0.0"

MAX_ITEMS = int(os.getenv("MAX_ITEMS", "60"))
AUTO_REFRESH_SECONDS = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "15"))
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

DEFAULT_FEEDS = [
    "https://www.cisa.gov/news-events/cybersecurity-advisories.xml",
    "https://www.cisa.gov/news-events/alerts.xml",
    "https://www.cisa.gov/news-events/ics-advisories.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.darkreading.com/rss.xml",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.reutersagency.com/feed/?best-topics=world&post_type=best",
]

ENV_FEEDS = os.getenv("FEEDS", "").strip()
FEEDS = [x.strip() for x in ENV_FEEDS.split(",") if x.strip()] if ENV_FEEDS else DEFAULT_FEEDS


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
_LAST_REFRESH_STATUS = "cold"
_LAST_REFRESH_TS = 0.0
_LOCK = asyncio.Lock()
_BG_TASK_STARTED = False


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp_int(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))


def uniq_keep_order(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        x = (x or "").strip()
        if not x:
            continue
        k = x.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def strip_html(text: str) -> str:
    if not text:
        return ""
    text = html.unescape(text)
    text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text).strip()
    return text


def shorten(text: str, limit: int = 260) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "…"


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def classify_category(title: str, summary: str, source: str) -> str:
    t = f"{title} {summary} {source}".lower()

    cyber_keywords = [
        "cve", "vulnerability", "exploit", "ransomware", "malware", "phishing",
        "credential", "breach", "leak", "patch", "advisory", "cisa", "ics",
        "scada", "ddos", "zero-day", "0day"
    ]
    geo_keywords = [
        "war", "missile", "drone", "sanction", "strike", "airstrike", "ceasefire",
        "conflict", "invasion", "military", "border", "diplomatic", "election",
        "geopolitical", "tension", "attack"
    ]

    cyber = any(k in t for k in cyber_keywords)
    geo = any(k in t for k in geo_keywords)

    if cyber and geo:
        return "Hybrid"
    if cyber:
        return "Cyber"
    if geo:
        return "Geopolitics"
    return "General"


def extract_tags(title: str, summary: str, source: str) -> List[str]:
    t = f"{title} {summary}".lower()
    tags: List[str] = []

    for cve in _CVE_RE.findall(f"{title} {summary}")[:6]:
        tags.append(cve.upper())

    keyword_map = {
        "ransomware": "ransomware",
        "phishing": "phishing",
        "credential": "credentials",
        "leak": "leak",
        "breach": "breach",
        "exploit": "exploit",
        "zero-day": "0day",
        "ddos": "ddos",
        "sanction": "sanctions",
        "ceasefire": "ceasefire",
        "missile": "missile",
        "drone": "drone",
        "election": "election",
        "diplomatic": "diplomacy",
        "iran": "iran",
        "israel": "israel",
        "russia": "russia",
        "ukraine": "ukraine",
    }

    for k, v in keyword_map.items():
        if k in t:
            tags.append(v)

    h = host_of(source)
    if "cisa.gov" in h:
        tags.append("cisa")
    elif "thehackernews.com" in h:
        tags.append("thn")
    elif "bleepingcomputer.com" in h:
        tags.append("bleepingcomputer")
    elif "aljazeera.com" in h:
        tags.append("aljazeera")
    elif "bbc" in h:
        tags.append("bbc")
    elif "reuters" in h:
        tags.append("reuters")

    return uniq_keep_order(tags)


def score_risk(title: str, summary: str, source: str, category: str) -> int:
    t = f"{title} {summary}".lower()
    h = host_of(source)

    score = 18

    if "cisa.gov" in h:
        score += 18
    if "thehackernews.com" in h or "bleepingcomputer.com" in h or "darkreading.com" in h:
        score += 8
    if "reuters" in h or "bbc" in h or "aljazeera" in h:
        score += 6

    cve_count = len(_CVE_RE.findall(f"{title} {summary}"))
    if cve_count:
        score += min(24, 10 + cve_count * 5)

    cyber_weights = {
        "critical": 28,
        "high severity": 18,
        "actively exploited": 28,
        "known exploited": 24,
        "zero-day": 26,
        "ransomware": 26,
        "remote code execution": 26,
        "rce": 22,
        "malware": 16,
        "breach": 18,
        "leak": 12,
        "credential": 12,
        "phishing": 10,
        "ddos": 10,
        "exploit": 16,
        "vulnerability": 8,
        "advisory": 8,
    }

    geo_weights = {
        "war": 20,
        "airstrike": 18,
        "strike": 12,
        "missile": 16,
        "drone": 12,
        "attack": 12,
        "invasion": 22,
        "military": 10,
        "sanction": 8,
        "ceasefire": 6,
        "tension": 8,
        "escalation": 16,
        "nuclear": 20,
    }

    for k, w in cyber_weights.items():
        if k in t:
            score += w

    for k, w in geo_weights.items():
        if k in t:
            score += w

    major_actors = ["iran", "israel", "russia", "ukraine", "china", "taiwan", "nato", "u.s.", "us "]
    if any(x in t for x in major_actors):
        score += 8

    if category == "Cyber":
        score += 6
    elif category == "Geopolitics":
        score += 4
    elif category == "Hybrid":
        score += 10

    if "no imminent threat" in t:
        score -= 10

    return clamp_int(score, 0, 100)


def risk_level(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def dedupe_items(items: List[IntelItem]) -> List[IntelItem]:
    seen = set()
    out = []
    for item in items:
        key = (item.title.strip().lower(), item.source.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def parse_rss_or_atom(xml_text: str, fallback_source: str) -> List[dict[str, str]]:
    entries: List[dict[str, str]] = []

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return entries

    for elem in root.iter():
        tag = elem.tag.lower()
        if tag.endswith("item") or tag.endswith("entry"):
            title = ""
            link = ""
            summary = ""

            for child in list(elem):
                ctag = child.tag.lower()
                if ctag.endswith("title") and not title:
                    title = strip_html(child.text or "")
                elif ctag.endswith("description") and not summary:
                    summary = strip_html(child.text or "")
                elif ctag.endswith("summary") and not summary:
                    summary = strip_html(child.text or "")
                elif ctag.endswith("content") and not summary:
                    summary = strip_html(child.text or "")
                elif ctag.endswith("link") and not link:
                    href = child.attrib.get("href", "").strip()
                    if href:
                        link = href
                    elif child.text:
                        link = child.text.strip()

            if title:
                entries.append({
                    "title": title,
                    "link": link or fallback_source,
                    "summary": summary,
                })

    return entries


async def init_db() -> None:
    if not DATABASE_URL:
        return

    def _run() -> None:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS intel_items (
                        id BIGSERIAL PRIMARY KEY,
                        title TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        category TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        risk_level TEXT NOT NULL,
                        source TEXT NOT NULL,
                        tags JSONB NOT NULL DEFAULT '[]'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL,
                        UNIQUE (title, source)
                    );
                    """
                )
            conn.commit()

    await asyncio.to_thread(_run)


async def save_items_to_db(items: List[IntelItem]) -> None:
    if not DATABASE_URL or not items:
        return

    def _run() -> None:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                for item in items:
                    cur.execute(
                        """
                        INSERT INTO intel_items
                        (title, summary, category, risk_score, risk_level, source, tags, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                        ON CONFLICT (title, source) DO UPDATE SET
                            summary = EXCLUDED.summary,
                            category = EXCLUDED.category,
                            risk_score = EXCLUDED.risk_score,
                            risk_level = EXCLUDED.risk_level,
                            tags = EXCLUDED.tags,
                            created_at = EXCLUDED.created_at;
                        """,
                        (
                            item.title,
                            item.summary,
                            item.category,
                            item.risk_score,
                            item.risk_level,
                            item.source,
                            str(item.tags).replace("'", '"'),
                            item.created_at,
                        ),
                    )
            conn.commit()

    await asyncio.to_thread(_run)


async def load_items_from_db(limit: int = MAX_ITEMS) -> List[IntelItem]:
    if not DATABASE_URL:
        return []

    def _run() -> List[IntelItem]:
        rows: List[IntelItem] = []
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT title, summary, category, risk_score, risk_level, source, tags, created_at
                    FROM intel_items
                    ORDER BY risk_score DESC, created_at DESC
                    LIMIT %s;
                    """,
                    (limit,),
                )
                for row in cur.fetchall():
                    rows.append(
                        IntelItem(
                            title=row[0],
                            summary=row[1],
                            category=row[2],
                            risk_score=row[3],
                            risk_level=row[4],
                            source=row[5],
                            tags=row[6] if isinstance(row[6], list) else [],
                            created_at=row[7].isoformat() if hasattr(row[7], "isoformat") else str(row[7]),
                        )
                    )
        return rows

    return await asyncio.to_thread(_run)


async def fetch_feed(client: httpx.AsyncClient, feed_url: str) -> List[IntelItem]:
    try:
        response = await client.get(
            feed_url,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "POLARIS-Intel/2.0"},
            follow_redirects=True,
        )
        response.raise_for_status()

        raw_entries = parse_rss_or_atom(response.text, feed_url)
        items: List[IntelItem] = []

        for entry in raw_entries:
            title = (entry.get("title") or "").strip()
            if not title:
                continue

            summary = shorten(strip_html(entry.get("summary") or ""))
            source = (entry.get("link") or feed_url).strip()

            category = classify_category(title, summary, source)
            tags = extract_tags(title, summary, source)
            risk_score = score_risk(title, summary, source, category)
            risk = risk_level(risk_score)

            items.append(
                IntelItem(
                    title=title,
                    summary=summary,
                    category=category,
                    risk_score=risk_score,
                    risk_level=risk,
                    source=source,
                    tags=tags,
                    created_at=now_iso(),
                )
            )

        return items
    except Exception:
        return []


async def refresh_store(force: bool = False) -> dict[str, Any]:
    global _STORE, _LAST_REFRESH_STATUS, _LAST_REFRESH_TS

    async with _LOCK:
        now = time.time()
        if not force and _STORE and (now - _LAST_REFRESH_TS < AUTO_REFRESH_SECONDS):
            return {"ok": True, "status": "cached", "items": len(_STORE)}

        _LAST_REFRESH_STATUS = "loading"
        _LAST_REFRESH_TS = now

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[fetch_feed(client, feed) for feed in FEEDS])

    merged: List[IntelItem] = []
    for arr in results:
        merged.extend(arr)

    merged = dedupe_items(merged)
    merged.sort(key=lambda x: (x.risk_score, x.created_at), reverse=True)
    merged = merged[:MAX_ITEMS]

    if merged:
        await save_items_to_db(merged)

    async with _LOCK:
        if merged:
            _STORE = merged
            _LAST_REFRESH_STATUS = "OK"
        else:
            db_items = await load_items_from_db(MAX_ITEMS)
            _STORE = db_items
            _LAST_REFRESH_STATUS = "OK" if db_items else "EMPTY"

        return {"ok": True, "status": _LAST_REFRESH_STATUS, "items": len(_STORE)}


async def background_refresh_loop() -> None:
    while True:
        try:
            await refresh_store(force=True)
        except Exception:
            pass
        await asyncio.sleep(AUTO_REFRESH_SECONDS)


@app.on_event("startup")
async def startup_event() -> None:
    global _BG_TASK_STARTED

    await init_db()

    db_items = await load_items_from_db(MAX_ITEMS)
    async with _LOCK:
        if db_items:
            _STORE[:] = db_items
            global _LAST_REFRESH_STATUS
            _LAST_REFRESH_STATUS = "OK"

    asyncio.create_task(refresh_store(force=True))

    if not _BG_TASK_STARTED:
        _BG_TASK_STARTED = True
        asyncio.create_task(background_refresh_loop())


@app.get("/health")
async def health() -> JSONResponse:
    async with _LOCK:
        return JSONResponse(
            {
                "ok": True,
                "app": APP_NAME,
                "version": APP_VERSION,
                "items": len(_STORE),
                "last_status": _LAST_REFRESH_STATUS,
                "feeds": len(FEEDS),
                "database": bool(DATABASE_URL),
            }
        )


@app.get("/api/latest")
async def api_latest() -> JSONResponse:
    async with _LOCK:
        return JSONResponse([asdict(item) for item in _STORE])


@app.post("/api/refresh")
async def api_refresh() -> JSONResponse:
    result = await refresh_store(force=True)
    return JSONResponse(result)


@app.post("/api/seed")
async def api_seed() -> JSONResponse:
    demo = [
        IntelItem(
            title="Sample cyber threat detected",
            summary="Suspicious activity indicates possible credential abuse. Investigate logs and alerts.",
            category="Cyber",
            risk_score=78,
            risk_level="High",
            source="https://example.com/cyber-alert",
            tags=["phishing", "credentials", "ioc"],
            created_at=now_iso(),
        ),
        IntelItem(
            title="Geopolitical tension rising in region",
            summary="Diplomatic friction and increased rhetoric suggest elevated escalation risk.",
            category="Geopolitics",
            risk_score=65,
            risk_level="High",
            source="https://example.com/geopolitics-brief",
            tags=["diplomacy", "trade", "monitor"],
            created_at=now_iso(),
        ),
    ]

    await save_items_to_db(demo)

    async with _LOCK:
        _STORE[:] = demo

    return JSONResponse({"ok": True, "seeded": len(demo)})


@app.get("/latest")
async def latest_hint() -> JSONResponse:
    return JSONResponse(
        {"detail": "Use /api/latest for JSON or / for UI."},
        status_code=404,
    )


@app.get("/", response_class=HTMLResponse)
async def home() -> HTMLResponse:
    try:
        await refresh_store(force=False)
    except Exception:
        pass

    async with _LOCK:
        items = list(_STORE)
        status = _LAST_REFRESH_STATUS
        count = len(items)

    cards_html_parts: List[str] = []

    if not items:
        cards_html_parts.append(
            """
            <article class="card empty">
              <h3>No items</h3>
              <p>No intelligence items are available yet. Press Refresh or call /api/seed.</p>
            </article>
            """
        )
    else:
        for item in items:
            title = html.escape(item.title)
            summary = html.escape(item.summary)
            source = html.escape(item.source)
            category = html.escape(item.category)
            risk = html.escape(item.risk_level)
            risk_css = risk.lower()
            tags = "".join(
                f'<span class="tag">#{html.escape(tag)}</span>' for tag in item.tags[:6]
            )

            cards_html_parts.append(
                f"""
                <article class="card">
                  <h3>{title}</h3>
                  <p class="summary">{summary}</p>
                  <div class="meta">
                    <span class="pill {risk_css}">Risk: {risk} ({item.risk_score})</span>
                    <span class="pill ghost">{category}</span>
                    {tags}
                  </div>
                  <div class="source">
                    Source:
                    <a href="{source}" target="_blank" rel="noopener noreferrer">{source}</a>
                  </div>
                </article>
                """
            )

    cards_html = "\n".join(cards_html_parts)

    page = f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>{APP_NAME}</title>
      <style>
        :root {{
          color-scheme: dark;
          --bg: #07101f;
          --bg2: #0a1428;
          --card: rgba(255,255,255,0.04);
          --line: rgba(255,255,255,0.08);
          --text: rgba(255,255,255,0.95);
          --muted: rgba(255,255,255,0.68);
          --accent: #8ab4ff;
          --critical: #ff5f6d;
          --high: #ff8a65;
          --medium: #ffd166;
          --low: #8ecae6;
        }}

        * {{
          box-sizing: border-box;
        }}

        body {{
          margin: 0;
          font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
          color: var(--text);
          background:
            radial-gradient(900px 500px at top center, #102244 0%, rgba(16,34,68,0.18) 35%, transparent 70%),
            linear-gradient(180deg, #050b16 0%, #081223 100%);
          min-height: 100vh;
        }}

        .container {{
          max-width: 1380px;
          margin: 0 auto;
          padding: 28px 18px 50px;
        }}

        .hero {{
          margin-bottom: 18px;
        }}

        h1 {{
          margin: 0;
          font-size: clamp(34px, 6vw, 68px);
          letter-spacing: -0.02em;
        }}

        .status {{
          margin-top: 8px;
          color: var(--muted);
          font-size: 15px;
        }}

        .toolbar {{
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
          margin: 18px 0 22px;
        }}

        button {{
          border: 1px solid rgba(138,180,255,0.25);
          background: rgba(138,180,255,0.12);
          color: var(--text);
          padding: 11px 16px;
          border-radius: 14px;
          cursor: pointer;
          font-weight: 700;
        }}

        button:hover {{
          background: rgba(138,180,255,0.18);
        }}

        input {{
          flex: 1;
          min-width: 250px;
          background: rgba(255,255,255,0.04);
          border: 1px solid var(--line);
          color: var(--text);
          padding: 12px 14px;
          border-radius: 14px;
          outline: none;
        }}

        input:focus {{
          border-color: rgba(138,180,255,0.35);
        }}

        .grid {{
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 16px;
        }}

        @media (max-width: 1100px) {{
          .grid {{
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }}
        }}

        @media (max-width: 740px) {{
          .grid {{
            grid-template-columns: 1fr;
          }}
        }}

        .card {{
          border: 1px solid var(--line);
          background: linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.03));
          border-radius: 20px;
          padding: 18px;
          box-shadow: 0 18px 50px rgba(0,0,0,0.28);
          min-height: 250px;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
        }}

        .card h3 {{
          margin: 0 0 12px;
          font-size: 18px;
          line-height: 1.28;
        }}

        .summary {{
          margin: 0 0 14px;
          color: rgba(255,255,255,0.80);
          line-height: 1.55;
          font-size: 14.5px;
          overflow-wrap: anywhere;
          word-break: break-word;
        }}

        .meta {{
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          margin-bottom: 12px;
        }}

        .pill, .tag {{
          display: inline-flex;
          align-items: center;
          min-height: 32px;
          padding: 6px 10px;
          border-radius: 999px;
          font-size: 12.5px;
          border: 1px solid var(--line);
          white-space: nowrap;
        }}

        .pill.ghost {{
          color: var(--muted);
          background: rgba(255,255,255,0.03);
        }}

        .pill.low {{
          border-color: rgba(142,202,230,0.40);
          color: #d7f2ff;
        }}

        .pill.medium {{
          border-color: rgba(255,209,102,0.42);
          color: #fff0bf;
        }}

        .pill.high {{
          border-color: rgba(255,138,101,0.45);
          color: #ffd8cc;
        }}

        .pill.critical {{
          border-color: rgba(255,95,109,0.55);
          color: #ffd6db;
          background: rgba(255,95,109,0.10);
        }}

        .tag {{
          color: rgba(255,255,255,0.76);
          background: rgba(255,255,255,0.03);
        }}

        .source {{
          margin-top: auto;
          font-size: 13px;
          color: var(--muted);
          overflow-wrap: anywhere;
          word-break: break-word;
          line-height: 1.45;
        }}

        a {{
color: var(--accent);
          text-decoration: none;
        }}

        a:hover {{
          text-decoration: underline;
        }}

        .footer {{
          margin-top: 16px;
          font-size: 12.5px;
          color: var(--muted);
        }}

        .empty {{
          min-height: 140px;
        }}
      </style>
    </head>
    <body>
      <div class="container">
        <div class="hero">
          <h1>{APP_NAME}</h1>
          <div class="status">Status: {html.escape(status)} ({count} items)</div>
        </div>

        <div class="toolbar">
          <button id="refreshBtn" type="button">Refresh</button>
          <button id="seedBtn" type="button">Seed demo</button>
          <input id="searchInput" type="text" placeholder="Search title / summary / tags..." />
        </div>

        <section class="grid" id="grid">
          {cards_html}
        </section>

        <div class="footer">
          API:
          <a href="/api/latest" target="_blank" rel="noopener noreferrer">/api/latest</a>
          ·
          Health:
          <a href="/health" target="_blank" rel="noopener noreferrer">/health</a>
        </div>
      </div>

      <script>
        const searchInput = document.getElementById("searchInput");
        const refreshBtn = document.getElementById("refreshBtn");
        const seedBtn = document.getElementById("seedBtn");

        function filterCards() {{
          const q = (searchInput.value || "").toLowerCase().trim();
          const cards = document.querySelectorAll(".card");
          cards.forEach(card => {{
            const text = (card.innerText || "").toLowerCase();
            card.style.display = !q || text.includes(q) ? "" : "none";
          }});
        }}

        searchInput.addEventListener("input", filterCards);

        refreshBtn.addEventListener("click", async () => {{
          refreshBtn.disabled = true;
          refreshBtn.textContent = "Refreshing...";
          try {{
            await fetch("/api/refresh", {{ method: "POST" }});
          }} catch (e) {{
          }}
          location.reload();
        }});

        seedBtn.addEventListener("click", async () => {{
          seedBtn.disabled = true;
          seedBtn.textContent = "Seeding...";
          try {{
            await fetch("/api/seed", {{ method: "POST" }});
          }} catch (e) {{
          }}
          location.reload();
        }});
      </script>
    </body>
    </html>
    """
    return HTMLResponse(page)