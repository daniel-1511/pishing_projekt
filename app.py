from fastapi import FastAPI, HTTPException
from url_scan import scan_url

app = FastAPI(title="Security Guard API")


@app.get("/check")
def check_url(url: str):
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="Ungültige URL")

    result = scan_url(url)

    return {
        "url": url,
        "score": result["score"],
        "status": result["status"],
        "details": result["details"]
    }