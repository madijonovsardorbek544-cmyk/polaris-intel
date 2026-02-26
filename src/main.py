from fastapi import FastAPI
from fastapi.responses import HTMLResponse

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
