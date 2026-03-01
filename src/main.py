from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="POLARIS Intel", version="0.1.0")

# Jinja templates path (senda: src/templates/index.html bor)
templates = Jinja2Templates(directory="src/templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    # index.html render qilish uchun request shart
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health", response_class=JSONResponse)
def health():
    return {"status": "ok", "app": "polaris-intel"}


@app.get("/api/latest", response_class=JSONResponse)
def get_latest():
    # UI shu endpointdan data oladi
    return [
        {
            "title": "Sample cyber threat detected",
            "risk_score": 78,
            "risk_level": "High",
            "category": "Cyber",
            "summary": "Suspicious activity indicates a potential intrusion attempt. Investigate alerts and logs.",
            "source": "https://example.com/cyber-alert",
            "tags": ["intrusion", "SOC", "urgent"],
        },
        {
            "title": "Geopolitical tension rising in region",
            "risk_score": 65,
            "risk_level": "Medium",
            "category": "Geopolitics",
            "summary": "Increased diplomatic friction may affect trade routes and regional stability.",
            "source": "https://example.com/geopolitics",
            "tags": ["diplomacy", "trade", "monitor"],
        },
    ]
