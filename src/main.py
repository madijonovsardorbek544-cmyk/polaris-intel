from fastapi import FastAPI

app = FastAPI(title="POLARIS Intel")

@app.get("/")
def home():
    return {"status": "ok", "app": "polaris-intel"}
