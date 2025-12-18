from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from scan.url_scan import scan_url
from urllib.parse import urlparse

app = FastAPI(title="CyberNet Security")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "result": None,
            "error": None,
            "url": None
        }
    )


@app.post("/check", response_class=HTMLResponse)
def check_url(request: Request, url: str = Form(...)):
    url = url.strip()

    # 🔒 Grundlegende URL-Validierung
    if not url.startswith(("http://", "https://")):
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Ungültige URL. Bitte mit http:// oder https:// beginnen.",
                "result": None,
                "url": url
            }
        )

    # 🔒 URL muss eine Domain enthalten
    parsed = urlparse(url)
    if not parsed.netloc:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Ungültige URL-Struktur.",
                "result": None,
                "url": url
            }
        )

    try:
        # 🔍 HAUPTSCAN (Security + Website + HTML)
        result = scan_url(url)

    except Exception as e:
        # ❌ Falls Scanner abstürzt → saubere Fehlermeldung
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": f"Fehler beim Scannen der Website: {str(e)}",
                "result": None,
                "url": url
            }
        )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "result": result,
            "url": url,
            "error": None
        }
    )
