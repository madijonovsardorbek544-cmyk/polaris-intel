from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"

app = FastAPI(
    title="POLARIS Intel",
    version="0.1.0",
    description="Cyber + geopolitical risk intelligence API",
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    # Landing page (index.html)
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "ok", "app": "polaris-intel"}


@app.get("/api/latest", response_class=JSONResponse)
def get_latest():
    # Frontend (index.html) shu endpointdan ma'lumot oladi
    return [
        {
            "title": "Sample cyber threat detected",
            "risk_score": 78,
            "risk_level": "High",
            "category": "Cyber",
            "explanation": "Suspicious activity pattern detected; elevated likelihood of credential abuse.",
            "source": "https://example.com/cyber-alert",
            "tags": ["phishing", "credentials", "IOC"],
        },
        {
            "title": "Geopolitical tension rising in region",
            "risk_score": 65,
            "risk_level": "Medium",
            "category": "Geopolitics",
            "explanation": "Rising rhetoric + troop movement indicators suggest increased escalation risk.",
            "source": "https://example.com/geopolitics-brief",
            "tags": ["diplomacy", "regional", "escalation"],
        },
    ]


@app.get("/reports", response_class=HTMLResponse)
def reports(request: Request):
    # Hozircha simple page (keyin xohlasang dinamik qilamiz)
    html = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>POLARIS Reports</title>
        <style>
          body{font-family:system-ui,Arial;margin:0;background:#0b1220;color:#e8eefc}
          .wrap{max-width:980px;margin:0 auto;padding:24px}
          a{color:#8fb4ff}
          .card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:14px;padding:14px}
        </style>
      </head>
      <body>
        <div class="wrap">
          <h1>Reports</h1>
          <div class="card">
            <p>Bu sahifa hozir demo. Keyin bu yerga real reportlar (daily/weekly) chiqaramiz.</p>
            <p><a href="/">← Back to Home</a></p>
          </div>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html)