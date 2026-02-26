from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()

templates = Jinja2Templates(directory="src/templates")

# Landing page
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# API endpoint
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
