
from __future__ import annotations

import asyncio
import html as html_lib
import os
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse

# -----------------------------
# CONFIG
# -----------------------------

APP_NAME = "POLARIS Intel"
APP_VERSION = "1.0.0"

# How many items to keep/display
MAX_ITEMS = int(os.getenv("MAX_ITEMS", "60"))

# Auto refresh interval for RSS fetch (seconds)
AUTO_REFRESH_SECONDS = int(os.getenv("AUTO_REFRESH_SECONDS", "900"))  # 15 min

# Request timeout
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "12.0"))

# Set to "1" to disable background refresh
DISABLE_BG_REFRESH = os.getenv("DISABLE_BG_REFRESH", "0") == "1"

# RSS sources (cyber + geopolitics). Add/remove safely.
DEFAULT_FEEDS = [
    # Cyber / Vulnerabilities
    "https://www.cisa.gov/news-events/cybersecurity-advisories.xml",
    "https://www.cisa.gov/news-events/alerts.xml",
    "https://www.cisa.gov/news-events/ics-advisories.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.darkreading.com/rss.xml",

    # Geopolitics / World
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.reutersagency.com/feed/?best-topics=world&post_type=best",
]

# You can override feeds with env var (comma-separated)
ENV_FEEDS = os.getenv("FEEDS", "").strip()
FEEDS = [f.strip() for f in ENV_FEEDS.split(",") if f.strip()] if ENV_FEEDS else DEFAULT_FEEDS


# -----------------------------
# DATA MODEL
# -----------------------------

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


# -----------------------------
# APP
# -----------------------------

app = FastAPI(title=APP_NAME, version=APP_VERSION)

# In-memory store
_STORE: List[IntelItem] = []
_LAST_REFRESH_TS: float = 0.0
_LAST_REFRESH_STATUS: str = "cold"
_LOCK = asyncio.Lock()


# -----------------------------
# UTILITIES
# -----------------------------

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_URL_RE = re.compile(r"https?://\S+")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def clamp_int(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))

def uniq_keep_order(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for s in seq:
        k = s.strip()
        if not k:
            continue
        if k.lower() in seen:
            continue
        seen.add(k.lower())
        out.append(k)
    return out

def strip_html(s: str) -> str:
    """Make messy HTML summaries readable & safe."""
    if not s:
        return ""
    # Unescape entities first
    s = html_lib.unescape(s)
    # Remove tags
    s = _TAG_RE.sub(" ", s)
    # Collapse whitespace
    s = _WS_RE.sub(" ", s).strip()
    return s

def shorten(s: str, limit: int = 360) -> str:
    s = (s or "").strip()
    if len(s) <= limit:
        return s
    cut = s[:limit]
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
        "cve", "vulnerability", "exploit", "ransomware", "malware", "phishing", "zero-day",
        "ics", "scada", "botnet", "breach", "leak", "credential", "patch", "advisory", "cisa",
        "mitre", "nvd", "xss", "rce", "sql injection", "ddos"
    ]
    geo_keywords = [
        "war", "conflict", "strike", "missile", "drone", "ceasefire", "invasion", "sanction",
        "diplomatic", "election", "border", "military", "attack", "tension", "protest", "coup"
    ]
    cyber = any(k in t for k in cyber_keywords)
    geo = any(k in t for k in geo_keywords)

    if cyber and not geo:
        return "Cyber"
    if geo and not cyber:
        return "Geopolitics"
    if cyber and geo:
        return "Hybrid"
    return "General"

def extract_tags(title: str, summary: str, source: str) -> List[str]:
    t = f"{title} {summary}".lower()
    tags: List[str] = []

    # CVEs
    cves = _CVE_RE.findall(f"{title} {summary}")
    for c in cves[:6]:
        tags.append(c.upper())

    # keyword tags
    key_map = {
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
    }
    for k, v in key_map.items():
        if k in t:
            tags.append(v)

    # source host tag
    h = host_of(source)
    if h:
        if "cisa.gov" in h:
            tags.append("cisa")
        elif "aljazeera" in h:
            tags.append("aljazeera")
        elif "bbc" in h:
            tags.append("bbc")
        elif "reuters" in h:
            tags.append("reuters")

    return uniq_keep_order(tags)

def score_risk(title: str, summary: str, source: str, category: str) -> int:
    """
    0-100 risk score:
    - Cyber: use CVEs / severity words / exploit indicators
    - Geopolitics: escalation words / casualties indicators (not graphic) / major actors keywords
    - Hybrid: combined weights
    """
    t = f"{title} {summary}".lower()
    h = host_of(source)

    score = 12  # baseline so almost never 0

    # Trust / authority bumps (not "truth", just impact relevance)
    if "cisa.gov" in h:
        score += 18
    if "ics" in t or "scada" in t:
        score += 10

    # CVE presence
    cve_count = len(_CVE_RE.findall(f"{title} {summary}"))
    if cve_count:
        score += 8 + min(18, cve_count * 6)

    # cyber severity words
    cyber_weights = {
        "critical": 26,
        "high": 18,
        "severe": 16,
        "rce": 22,
        "remote code execution": 22,
        "actively exploited": 26,
        "known exploited": 22,
        "zero-day": 26,
        "0day": 26,
        "wormable": 24,
        "ransomware": 26,
        "breach": 18,
        "data leak": 16,
        "leak": 12,
        "phishing": 10,
        "credential": 12,
        "botnet": 14,
        "ddos": 10,
        "patch now": 10,
        "urgent": 12,
    }
    for k, w in cyber_weights.items():
        if k in t:
            score += w

    # geopolitics escalation words
    geo_weights = {
        "airstrike": 16,
        "strike": 12,
        "missile": 16,
        "drone": 12,
        "attack": 12,
        "invasion": 20,
        "mobilization": 14,
        "sanction": 10,
        "ceasefire": 6,
        "tension": 8,
        "escalation": 14,
        "nuclear": 18,
    }
    for k, w in geo_weights.items():
        if k in t:
            score += w

    # major actor bump (keeps geopolitics not always low)
    major_actors = ["iran", "israel", "russia", "ukraine", "china", "taiwan", "nato", "un", "us ", "u.s."]
    if any(a in t for a in major_actors):
        score += 8

    # category shaping
    if category == "Cyber":
        score += 6
    elif category == "Geopolitics":
        score += 4
    elif category == "Hybrid":
        score += 10

    # If text explicitly says "no imminent threat" reduce a bit
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
    out: List[IntelItem] = []
    for it in items:
        key = (it.title.strip().lower(), it.source.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out

def safe_text(x: Any) -> str:
    return strip_html(str(x or "")).strip()

def parse_rss_xml(xml_text: str, fallback_source: str) -> List[Dict[str, str]]:
    """
    Minimal RSS/Atom parsing without external libs:
    - Find <item> or <entry>
    - Extract title, link, description/summary/content
    """
    txt = xml_text

    # choose blocks: RSS item or Atom entry
    blocks = re.findall(r"<item\b.*?>.*?</item>", txt, flags=re.DOTALL | re.IGNORECASE)
    if not blocks:
        blocks = re.findall(r"<entry\b.*?>.*?</entry>", txt, flags=re.DOTALL | re.IGNORECASE)

    def _pick(tag: str, block: str) -> str:
        m = re.search(rf"<{tag}\b.*?>(.*?)</{tag}>", block, flags=re.DOTALL | re.IGNORECASE)
        return m.group(1) if m else ""

    out = []
    for b in blocks[:MAX_ITEMS]:
        title = _pick("title", b)
        link = ""
        # RSS link
        l = _pick("link", b)
        if l.strip():
            link = l.strip()
        else:
            # Atom link href
            m = re.search(r"<link\b[^>]*href=['\"]([^'\"]+)['\"]", b, flags=re.IGNORECASE)
            if m:
                link = m.group(1).strip()

        desc = _pick("description", b) or _pick("summary", b) or _pick("content", b)
        out.append({
            "title": safe_text(title),
            "link": link.strip() or fallback_source,
            "summary": safe_text(desc),
        })
    return out


# -----------------------------
# FETCH + BUILD ITEMS
# -----------------------------

async def fetch_feed(client: httpx.AsyncClient, feed_url: str) -> List[IntelItem]:
    try:
        r = await client.get(feed_url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "POLARIS-Intel/1.0"})
        r.raise_for_status()
        entries = parse_rss_xml(r.text, fallback_source=feed_url)
        items: List[IntelItem] = []
        for e in entries:
            title = e.get("title", "").strip()
            if not title:
                continue
            summary = e.get("summary", "").strip()
            source = e.get("link", feed_url).strip() or feed_url

            cat = classify_category(title, summary, source)
            tags = extract_tags(title, summary, source)
            score = score_risk(title, summary, source, cat)
            lvl = risk_level(score)

            items.append(IntelItem(
                title=title,
                summary=summary,
                category=cat,
                risk_score=score,
                risk_level=lvl,
                source=source,
                tags=tags,
                created_at=now_iso(),
            ))
        return items
    except Exception:
        return []

async def refresh_store(force: bool = False) -> Dict[str, Any]:
    global _STORE, _LAST_REFRESH_TS, _LAST_REFRESH_STATUS

    async with _LOCK:
        now = time.time()
        if not force and (now - _LAST_REFRESH_TS) < AUTO_REFRESH_SECONDS and _STORE:
            return {"ok": True, "status": "cached", "items": len(_STORE)}

        _LAST_REFRESH_STATUS = "loading"
        _LAST_REFRESH_TS = now

    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [fetch_feed(client, u) for u in FEEDS]
        results = await asyncio.gather(*tasks)

    merged: List[IntelItem] = []
    for arr in results:
        merged.extend(arr)

    # Clean & dedupe & sort by score desc
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
    # initial warm-up (non-blocking)
    asyncio.create_task(refresh_store(force=True))
    asyncio.create_task(bg_loop())


# -----------------------------
# ROUTES
# -----------------------------

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
    info = await refresh_store(force=True)
    return JSONResponse(info)

@app.post("/api/seed")
async def api_seed():
    # fallback seed to demonstrate UI even if feeds fail
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
    async with _LOCK:
        global _STORE, _LAST_REFRESH_STATUS
        _STORE = demo
        _LAST_REFRESH_STATUS = "OK (seeded)"
    return JSONResponse({"ok": True, "seeded": len(demo)})

@app.get("/", response_class=HTMLResponse)
async def home():
    # Ensure we have data, but never crash the page
    try:
        await refresh_store(force=False)
    except Exception:
        pass

    async with _LOCK:
        items = list(_STORE)
        status = _LAST_REFRESH_STATUS
        count = len(items)

    # Build cards HTML safely
    cards = []
    for it in items:
        # display-safe
        title = html_lib.escape(it.title)
        summary = html_lib.escape(shorten(strip_html(it.summary)))
        category = html_lib.escape(it.category)
        lvl = html_lib.escape(it.risk_level)
        src = html_lib.escape(it.source)
        score = it.risk_score

        tag_html = ""
        for tg in it.tags[:8]:
            tag_html += f'<span class="tag">#{html_lib.escape(tg)}</span>'

        cards.append(f"""
          <article class="card">
            <h3 class="title">{title}</h3>
            <p class="summary">{summary}</p>
            <div class="meta">
              <span class="pill {lvl.lower()}">Risk: {lvl} ({score})</span>
              <span class="pill ghost">{category}</span>
              {tag_html}
            </div>
            <div class="source">Source: <a href="{src}" target="_blank" rel="noopener noreferrer">{src}</a></div>
          </article>
        """)

    cards_html = "\n".join(cards) if cards else """
      <article class="card empty">
        <h3 class="title">No items</h3>
        <p class="summary">Nothing fetched yet. Try <b>Reload</b> or call <code>/api/refresh</code>.</p>
        <div class="meta"><span class="pill ghost">empty</span></div>
      </article>
    """

    # HTML
    html = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{APP_NAME}</title>
  <style>
    :root {{
      --bg0:#070b14;
      --bg1:#0b1224;
      --card:#0b1732;
      --card2:#09142b;
      --line: rgba(255,255,255,0.08);
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.62);
      --accent: #6ea8fe;
      --shadow: 0 16px 40px rgba(0,0,0,0.35);
      --radius: 18px;
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji","Segoe UI Emoji";
      color: var(--text);
      background: radial-gradient(900px 500px at 30% 10%, #111c3d 0%, var(--bg0) 50%) , linear-gradient(180deg, var(--bg0), var(--bg1));
      min-height: 100vh;
    }}

    .wrap {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 28px 18px 44px;
    }}

    .hero {{
      display:flex;
      flex-direction:column;
      gap: 10px;
      margin-bottom: 16px;
    }}

    h1 {{
      margin: 0;
      font-size: clamp(34px, 5vw, 64px);
      letter-spacing: 0.5px;
    }}

    .status {{
      color: var(--muted);
      font-size: 14px;
    }}

    .toolbar {{
      display:flex;
      gap: 10px;
      align-items:center;
      flex-wrap: wrap;
      margin: 14px 0 18px;
    }}

    button {{
      background: rgba(110,168,254,0.16);
      color: var(--text);
      border: 1px solid rgba(110,168,254,0.24);
      padding: 10px 14px;
      border-radius: 12px;
      cursor: pointer;
      font-weight: 600;
      box-shadow: var(--shadow);
    }}
    button:hover {{
      border-color: rgba(110,168,254,0.5);
      background: rgba(110,168,254,0.2);
    }}

    input {{
      flex: 1;
      min-width: 220px;
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--line);
      color: var(--text);
      padding: 11px 12px;
      border-radius: 12px;
      outline: none;
    }}
    input:focus {{
      border-color: rgba(110,168,254,0.45);
    }}

    .grid {{
      display:grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
    }}

    @media (max-width: 1050px) {{
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 680px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}

    .card {{
      background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 16px 16px 14px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }}

    .title {{
      margin: 0 0 10px;
      font-size: 18px;
      line-height: 1.25;
    }}

    /* IMPORTANT: prevents messy layout */
    .summary {{
      color: rgba(255,255,255,0.78);
      font-size: 14.5px;
      line-height: 1.5;

      overflow-wrap: anywhere;
      word-break: break-word;

      display: -webkit-box;
      -webkit-line-clamp: 5;
      -webkit-box-orient: vertical;
      overflow: hidden;
      margin: 0 0 12px;
    }}

    .meta {{
      display:flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items:center;
      margin-bottom: 10px;
    }}

    .pill {{
      font-size: 12.5px;
      padding: 6px 10px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.05);
      color: rgba(255,255,255,0.88);
      white-space: nowrap;
    }}

    .pill.ghost {{
      background: rgba(255,255,255,0.03);
      color: var(--muted);
    }}

    .pill.low {{
      border-color: rgba(110,168,254,0.25);
    }}
    .pill.medium {{
      border-color: rgba(255,193,7,0.35);
    }}
    .pill.high {{
      border-color: rgba(255,99,132,0.35);
    }}
    .pill.critical {{
      border-color: rgba(220,53,69,0.5);
      background: rgba(220,53,69,0.12);
  }}

    .tag {{
      font-size: 12px;
      padding: 6px 9px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.04);
      color: rgba(255,255,255,0.72);
      white-space: nowrap;
    }}

    .source {{
      margin-top: 2px;
      font-size: 13px;
      color: var(--muted);

      overflow-wrap: anywhere;
      word-break: break-word;
    }}

    a {{
      color: var(--accent);
      text-decoration: none;

      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    a:hover {{
      text-decoration: underline;
    }}

    .tip {{
      margin-top: 14px;
      color: var(--muted);
      font-size: 12.5px;
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
      <button id="reloadBtn">Reload</button>
      <input id="q" placeholder="Search title / summary / tags..." />
    </div>

    <section class="grid" id="grid">
      {cards_html}
    </section>

    <div class="tip">Tip: API endpoint → <a href="/api/latest">/api/latest</a> • Force refresh → <code>POST /api/refresh</code></div>
  </div>

<script>
  const q = document.getElementById("q");
  const grid = document.getElementById("grid");
  const reloadBtn = document.getElementById("reloadBtn");

  function normalize(s) {{
    return (s || "").toLowerCase().trim();
  }}

  function filterCards() {{
    const term = normalize(q.value);
    const cards = grid.querySelectorAll(".card");
    if (!term) {{
      cards.forEach(c => c.style.display = "");
      return;
    }}
    cards.forEach(c => {{
      const text = normalize(c.innerText);
      c.style.display = text.includes(term) ? "" : "none";
    }});
  }}

  q.addEventListener("input", filterCards);

  reloadBtn.addEventListener("click", async () => {{
    reloadBtn.disabled = true;
    reloadBtn.innerText = "Loading...";
    try {{
      await fetch("/api/refresh", {{ method: "POST" }});
      location.reload();
    }} catch (e) {{
      location.reload();
    }}
  }});
</script>

</body>
</html>
"""
    return HTMLResponse(html)

# Optional: handle accidental /latest visits nicely (your screenshot showed /latest "Not Found")
@app.get("/latest")
async def latest_redirect():
    return JSONResponse({"detail": "Use /api/latest for JSON or / for UI."}, status_code=404)