
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

app = FastAPI(title="POLARIS Intel")

templates = Jinja2Templates(directory="src/templates")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

app = FastAPI()

@app.get("/")
def home():
    return {"status": "ok", "app": "polaris-intel"}

@app.get("/api/latest")
def get_latest():
    return [
        {
            "title": "Sample cyber threat detected",
            "risk_score": 78,
            "category": "Cyber"
        },
        {
            "title": "Geopolitical tension rising in region",
            "risk_score": 65,
            "category": "Geopolitics"
        }
    ]
