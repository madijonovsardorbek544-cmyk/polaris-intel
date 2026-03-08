from __future__ import annotations

import asyncio
import html as html_lib
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
APP_VERSION = "2.0.0"

MAX_ITEMS = int(os.getenv("MAX_ITEMS", "60"))
AUTO_REFRESH_SECONDS = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))  # 15 min
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "15.0"))
DISABLE_BG_REFRESH = os.getenv("DISABLE_BG_REFRESH", "0") == "1"

DEFAULT_FEEDS = [
    # Cyber
    "https://www.cisa.gov/news-events/cybersecurity-advisories.xml",
    "https://www.cisa.gov/news-events/alerts.xml",
    "https://www.cisa.gov/news-events/ics-advisories.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.darkreading.com/rss.xml",

    # Geopolitics / world
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.reutersagency.com/feed/?best-topics=world&post_type=best",
]

ENV_FEEDS = os.getenv("FEEDS", "").strip()
FEEDS = [x.strip() for x in ENV_FEEDS.split(",") if x.strip()] if ENV_FEEDS else DEFAULT_FEEDS

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
    source_host: str
    tags: List[str]
    created_at: str


# =========================================================
# APP + STORE
# =========================================================

app = FastAPI(title=APP_NAME, version=APP_VERSION)

_STORE: List[IntelItem] = []
_LAST_REFRESH_TS: float = 0.0
_LAST_REFRESH_STATUS: str = "cold"
_LOCK = asyncio.Lock()

# =========================================================
# REGEX / UTILS
# =========================================================

TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
WS_RE = re.compile(r"\s+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def clamp_int(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))

def uniq_keep_order(values: List[str]) -> List[str]:
    seen = set()
    out = []
    for v in values:
        v = (v or "").strip()
        if not v:
            continue
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out

def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def strip_html(text: str) -> str:
    if not text:
        return ""
    text = html_lib.unescape(text)
    text = SCRIPT_STYLE_RE.sub(" ", text)
    text = TAG_RE.sub(" ", text)
    text = WS_RE.sub(" ", text).strip()
    return text

def shorten(text: str, limit: int = 260) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "…"

def display_source(url: str) -> str:
    """
    User ko‘rishi uchun source ni chiroyli qisqartiradi.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or ""
        short = host + path
        if len(short) > 70:
            short = short[:67] + "..."
        return short
    except Exception:
        return url[:70] + ("..." if len(url) > 70 else "")

def safe_text(x: Any) -> str:
    return strip_html(str(x or "")).strip()

# =========================================================
# RSS / ATOM PARSER
# =========================================================

def parse_rss_xml(xml_text: str, fallback_source: str) -> List[Dict[str, str]]:
    """
    Minimal RSS / Atom parser using regex.
    """
    blocks = re.findall(r"<item\b.*?>.*?</item>", xml_text, flags=re.I | re.S)
    if not blocks:
        blocks = re.findall(r"<entry\b.*?>.*?</entry>", xml_text, flags=re.I | re.S)

    def pick(tag: str, block: str) -> str:
        m = re.search(rf"<{tag}\b.*?>(.*?)</{tag}>", block, flags=re.I | re.S)
        return m.group(1) if m else ""

    out = []
    for block in blocks[:MAX_ITEMS]:
        title = pick("title", block)
        link = pick("link", block).strip()

        if not link:
            m = re.search(r"<link\b[^>]*href=['\"]([^'\"]+)['\"]", block, flags=re.I)
            if m:
                link = m.group(1).strip()

        summary = (
            pick("description", block)
            or pick("summary", block)
            or pick("content", block)
            or pick("content:encoded", block)
        )

        out.append({
            "title": safe_text(title),
            "summary": safe_text(summary),
            "link": link or fallback_source,
        })
    return out

# =========================================================
# CLASSIFICATION / TAGS / RISK
# =========================================================

def classify_category(title: str, summary: str, source: str) -> str:
    text = f"{title} {summary} {source}".lower()

    cyber_keywords = [
        "cve", "vulnerability", "exploit", "ransomware", "malware", "phishing",
        "zero-day", "0day", "credential", "breach", "leak", "patch", "advisory",
        "ics", "scada", "ddos", "xss", "rce", "botnet", "cisa"
    ]

    geo_keywords = [
        "war", "conflict", "missile", "drone", "strike", "attack", "airstrike",
        "ceasefire", "military", "government", "border", "election",
        "diplomatic", "sanction", "tension", "escalation", "nuclear"
    ]

    is_cyber = any(k in text for k in cyber_keywords)
    is_geo = any(k in text for k in geo_keywords)

    if is_cyber and is_geo:
        return "Hybrid"
    if is_cyber:
        return "Cyber"
    if is_geo:
        return "Geopolitics"
    return "General"

def extract_tags(title: str, summary: str, source: str) -> List[str]:
    text = f"{title} {summary}".lower()
    tags: List[str] = []

    for cve in CVE_RE.findall(f"{title} {summary}")[:6]:
        tags.append(cve.upper())

    keyword_map = {
        "ransomware": "ransomware",
        "phishing": "phishing",
        "credential": "credentials",
        "leak": "leak",
        "breach": "breach",
        "exploit": "exploit",
        "zero-day": "0day",
        "0day": "0day",
        "ddos": "ddos",
        "missile": "missile",
        "drone": "drone",
        "sanction": "sanctions",
        "ceasefire": "ceasefire",
        "diplomatic": "diplomacy",
        "election": "election",
        "malware": "malware",
        "ics": "ics",
        "scada": "scada",
    }

    for k, v in keyword_map.items():
        if k in text:
            tags.append(v)

    h = host_of(source)
    if "cisa.gov" in h:
        tags.append("cisa")
    elif "aljazeera" in h:
        tags.append("aljazeera")
    elif "bbc" in h:
        tags.append("bbc")
    elif "reuters" in h:
        tags.append("reuters")
    elif "bleepingcomputer" in h:
        tags.append("bleepingcomputer")
    elif "thehackernews" in h or "feedburner" in h:
        tags.append("thehackernews")
    elif "darkreading" in h:
        tags.append("darkreading")

    return uniq_keep_order(tags)

def score_risk(title: str, summary: str, source: str, category: str) -> int:
    text = f"{title} {summary}".lower()
    host = host_of(source)

    score = 18

    # Source credibility / impact
    if "cisa.gov" in host:
        score += 18
    elif "reuters" in host or "bbc" in host or "aljazeera" in host:
        score += 8
    elif "bleepingcomputer" in host or "darkreading" in host or "thehackernews" in host:
        score += 10

    # CVEs
    cve_count = len(CVE_RE.findall(f"{title} {summary}"))
    if cve_count:
        score += 10 + min(20, cve_count * 5)

    cyber_weights = {
        "critical": 24,
        "actively exploited": 24,
        "known exploited": 20,
        "zero-day": 22,
        "0day": 22,
        "rce": 18,
        "remote code execution": 20,
        "exploit": 14,
        "ransomware": 22,
        "malware": 12,
        "phishing": 10,
        "credential": 12,
        "breach": 16,
        "leak": 10,
        "ddos": 10,
        "ics": 10,
        "scada": 10,
        "urgent": 8,
        "patch": 6,
    }

    geo_weights = {
        "war": 18,
        "conflict": 12,
        "missile": 18,
        "drone": 14,
        "strike": 12,
        "airstrike": 16,
        "attack": 12,
        "military": 10,
        "border": 8,
        "nuclear": 20,
        "sanction": 8,
        "ceasefire": 5,
        "escalation": 14,
        "tension": 8,
        "election": 8,
        "government": 6,
    }

    for key, weight in cyber_weights.items():
        if key in text:
            score += weight

    for key, weight in geo_weights.items():
        if key in text:
            score += weight

    major_actors = [
        "iran", "israel", "russia", "ukraine", "china", "taiwan",
        "nato", "united states", "u.s.", "us ", "europe", "eu"
    ]
    if any(actor in text for actor in major_actors):
        score += 8

    if "no imminent threat" in text:
        score -= 10

    if category == "Hybrid":
        score += 10
    elif category == "Cyber":
        score += 6
    elif category == "Geopolitics":
        score += 5

    return clamp_int(score, 20, 100)

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

# =========================================================
# FETCH
# =========================================================

async def fetch_feed(client: httpx.AsyncClient, feed_url: str) -> List[IntelItem]:
    try:
        resp = await client.get(
            feed_url,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": "POLARIS-Intel/2.0"}
        )
        resp.raise_for_status()

        entries = parse_rss_xml(resp.text, fallback_source=feed_url)
        results: List[IntelItem] = []

        for entry in entries:
            title = entry.get("title", "").strip()
            if not title:
                continue

            raw_summary = entry.get("summary", "")
            summary = shorten(strip_html(raw_summary), 260)
            source = entry.get("link", feed_url).strip() or feed_url

            category = classify_category(title, summary, source)
            tags = extract_tags(title, summary, source)
            score = score_risk(title, summary, source, category)
            level = risk_level(score)

            results.append(
                IntelItem(
                    title=title,
                    summary=summary,
                    category=category,
                    risk_score=score,
                    risk_level=level,
                    source=source,
                    source_host=display_source(source),
                    tags=tags[:8],
                    created_at=now_iso(),
                )
            )

        return results

    except Exception:
        return []

async def refresh_store(force: bool = False) -> Dict[str, Any]:
    global _STORE, _LAST_REFRESH_TS, _LAST_REFRESH_STATUS

    async with _LOCK:
        now = time.time()
        if not force and (now - _LAST_REFRESH_TS) < AUTO_REFRESH_SECONDS and _STORE:
            return {"ok": True, "status": "cached", "items": len(_STORE)}

        _LAST_REFRESH_TS = now
        _LAST_REFRESH_STATUS = "loading"

    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [fetch_feed(client, url) for url in FEEDS]
        results = await asyncio.gather(*tasks)

    merged: List[IntelItem] = []
    for arr in results:
        merged.extend(arr)

    merged = dedupe_items(merged)
    merged.sort(key=lambda x: x.risk_score, reverse=True)
    merged = merged[:MAX_ITEMS]

    async with _LOCK:
        _STORE = merged
        _LAST_REFRESH_STATUS = "OK" if merged else "OK (0 items)"
        return {"ok": True, "status": _LAST_REFRESH_STATUS, "items": len(_STORE)}

async def bg_loop():
    if DISABLE_BG_REFRESH:
        return
    while True:
        try:
            await refresh_store(force=False)
        except Exception:
            pass
        await asyncio.sleep(AUTO_REFRESH_SECONDS)

@app.on_event("startup")
async def on_startup():
    asyncio.create_task(refresh_store(force=True))
    asyncio.create_task(bg_loop())

# =========================================================
# API ROUTES
# =========================================================

@app.get("/health")
async def health():
    async with _LOCK:
        return {
            "ok": True,
            "app": APP_NAME,
            "version": APP_VERSION,
            "items": len(_STORE),
            "last_status": _LAST_REFRESH_STATUS,
            "feeds": len(FEEDS),
        }

@app.get("/api/latest")
async def api_latest():
    async with _LOCK:
        return JSONResponse([asdict(x) for x in _STORE])

@app.post("/api/refresh")
async def api_refresh():
    data = await refresh_store(force=True)
    return JSONResponse(data)

@app.post("/api/seed")
async def api_seed():
    demo = [
        IntelItem(
            title="Sample cyber threat detected",
            summary="Suspicious activity indicates possible credential abuse. Investigate logs and alerts.",
            category="Cyber",
            risk_score=78,
            risk_level="High",
            source="https://example.com/cyber-alert",
            source_host="example.com/cyber-alert",
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
            source_host="example.com/geopolitics-brief",
            tags=["diplomacy", "trade", "monitor"],
            created_at=now_iso(),
        ),
    ]

    async with _LOCK:
        global _STORE, _LAST_REFRESH_STATUS
        _STORE = demo
        _LAST_REFRESH_STATUS = "OK (seeded)"

    return JSONResponse({"ok": True, "seeded": len(demo)})

@app.get("/latest")
async def latest_help():
    return JSONResponse(
        {"detail": "Use /api/latest for JSON or / for UI."},
        status_code=404
    )

# =========================================================
# UI
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    try:
        await refresh_store(force=False)
    except Exception:
        pass

    async with _LOCK:
        items = list(_STORE)
        status = _LAST_REFRESH_STATUS
        count = len(items)

    cards_html_parts = []

    for item in items:
        title = html_lib.escape(item.title)
        summary = html_lib.escape(item.summary)
        category = html_lib.escape(item.category)
        level = html_lib.escape(item.risk_level)
        score = item.risk_score
        src_url = html_lib.escape(item.source)
        src_show = html_lib.escape(item.source_host)

        tags_html = "".join(
            f'<span class="tag">#{html_lib.escape(tag)}</span>'
            for tag in item.tags[:6]
        )

        cards_html_parts.append(f"""
        <article class="card">
          <div class="card-top">
            <h3 class="title">{title}</h3>
            <p class="summary">{summary}</p>
          </div>

          <div class="meta">
            <span class="pill {level.lower()}">Risk: {level} ({score})</span>
            <span class="pill ghost">{category}</span>
            {tags_html}
          </div>

          <div class="source">
            <span class="source-label">Source:</span>
            <a href="{src_url}" target="_blank" rel="noopener noreferrer">{src_show}</a>
          </div>
        </article>
        """)

    if cards_html_parts:
        cards_html = "\n".join(cards_html_parts)
    else:
        cards_html = """
        <article class="card empty">
          <div class="card-top">
            <h3 class="title">No items</h3>
            <p class="summary">Nothing fetched yet. Press Reload or use POST /api/refresh.</p>
          </div>
          <div class="meta">
            <span class="pill ghost">empty</span>
          </div>
        </article>
        """

    html = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{APP_NAME}</title>
  <style>
    :root {{
      --bg0: #060b16;
      --bg1: #0a1224;
      --card: rgba(255,255,255,0.045);
      --line: rgba(255,255,255,0.08);
      --text: rgba(255,255,255,0.95);
      --muted: rgba(255,255,255,0.65);
      --blue: #84b6ff;
      --shadow: 0 16px 40px rgba(0,0,0,0.34);
      --radius: 18px;
    }}

    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:
        radial-gradient(900px 520px at 20% 0%, #122149 0%, rgba(18,33,73,0) 55%),
        linear-gradient(180deg, var(--bg0), var(--bg1));
      min-height: 100vh;
    }}

    .wrap {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 26px 18px 42px;
    }}

    .hero {{
      margin-bottom: 16px;
    }}

    h1 {{
      margin: 0 0 8px;
      font-size: clamp(40px, 7vw, 72px);
      line-height: 1.02;
      letter-spacing: -0.02em;
    }}

    .status {{
      color: var(--muted);
      font-size: 15px;
      margin-bottom: 16px;
    }}

    .toolbar {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 18px;
    }}

    button {{
      border: 1px solid rgba(132,182,255,0.24);
      background: rgba(132,182,255,0.14);
      color: var(--text);
      padding: 11px 16px;
      border-radius: 12px;
      cursor: pointer;
      font-weight: 700;
      box-shadow: var(--shadow);
    }}

    button:hover {{
      background: rgba(132,182,255,0.19);
      border-color: rgba(132,182,255,0.4);
    }}

    input {{
      flex: 1;
      min-width: 220px;
      padding: 12px 14px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.045);
      color: var(--text);
      outline: none;
      font-size: 15px;
    }}

    input:focus {{
      border-color: rgba(132,182,255,0.38);
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
      align-items: stretch;
    }}

    @media (max-width: 1100px) {{
      .grid {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
    }}

    @media (max-width: 700px) {{
      .wrap {{
        padding: 20px 14px 34px;
      }}

      .grid {{
        grid-template-columns: 1fr;
      }}

      h1 {{
        font-size: clamp(34px, 12vw, 56px);
      }}
    }}

    .card {{
      min-width: 0;
      display: flex;
      flex-direction: column;
       justify-content: space-between;
      gap: 12px;
      padding: 18px 18px 16px;
      border-radius: var(--radius);
      border: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.03));
      box-shadow: var(--shadow);
      overflow: hidden;
    }}

    .card-top {{
      min-width: 0;
    }}

    .title {{
      margin: 0 0 10px;
      font-size: 18px;
      line-height: 1.28;
      font-weight: 800;
      word-break: break-word;
      overflow-wrap: anywhere;

      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }}

    .summary {{
      margin: 0;
      color: rgba(255,255,255,0.78);
      font-size: 14.5px;
      line-height: 1.55;
      min-width: 0;
      word-break: break-word;
      overflow-wrap: anywhere;

      display: -webkit-box;
      -webkit-line-clamp: 5;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }}

    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      min-width: 0;
    }}

    .pill, .tag {{
      max-width: 100%;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    .pill {{
      font-size: 12.5px;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.05);
      color: rgba(255,255,255,0.9);
    }}

    .pill.ghost {{
      background: rgba(255,255,255,0.03);
      color: var(--muted);
    }}

    .pill.low {{
      border-color: rgba(132,182,255,0.28);
    }}

    .pill.medium {{
      border-color: rgba(255,193,7,0.34);
    }}

    .pill.high {{
      border-color: rgba(255,99,132,0.40);
    }}

    .pill.critical {{
      border-color: rgba(220,53,69,0.52);
      background: rgba(220,53,69,0.12);
    }}

    .tag {{
      font-size: 12px;
      padding: 6px 9px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.04);
      color: rgba(255,255,255,0.74);
    }}

    .source {{
      min-width: 0;
      font-size: 13px;
      color: var(--muted);
      line-height: 1.45;
      word-break: break-word;
      overflow-wrap: anywhere;
      padding-top: 2px;
    }}

    .source-label {{
      color: rgba(255,255,255,0.72);
      margin-right: 4px;
    }}

    a {{
      color: var(--blue);
      text-decoration: none;
      word-break: break-word;
      overflow-wrap: anywhere;
    }}

    a:hover {{
      text-decoration: underline;
    }}

    .tip {{
      margin-top: 16px;
      color: var(--muted);
      font-size: 12.5px;
      line-height: 1.5;
    }}

    code {{
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--line);
      padding: 2px 6px;
      border-radius: 8px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>{APP_NAME}</h1>
      <div class="status">Status: {html_lib.escape(status)} ({count} items)</div>
    </div>

    <div class="toolbar">
      <button id="reloadBtn" type="button">Reload</button>
      <input id="q" type="text" placeholder="Search title / summary / tags..." />
    </div>

    <section id="grid" class="grid">
      {cards_html}
    </section>

    <div class="tip">
      Tip: API endpoint → <a href="/api/latest" target="_blank" rel="noopener noreferrer">/api/latest</a>
      • Force refresh → <code>POST /api/refresh</code>
    </div>
  </div>

  <script>
    const grid = document.getElementById("grid");
    const q = document.getElementById("q");
    const reloadBtn = document.getElementById("reloadBtn");

    function normalize(s) {{
      return (s || "").toLowerCase().trim();
    }}

    function filterCards() {{
      const term = normalize(q.value);
      const cards = grid.querySelectorAll(".card");

      if (!term) {{
        cards.forEach(card => card.style.display = "");
        return;
      }}

      cards.forEach(card => {{
        const text = normalize(card.innerText);
        card.style.display = text.includes(term) ? "" : "none";
      }});
    }}

    q.addEventListener("input", filterCards);

    reloadBtn.addEventListener("click", async () => {{
      reloadBtn.disabled = true;
      reloadBtn.innerText = "Loading...";
      try {{
        await fetch("/api/refresh", {{ method: "POST" }});
      }} catch (e) {{}}
      location.reload();
    }});
  </script>
</body>
</html>
"""
    return HTMLResponse(html)