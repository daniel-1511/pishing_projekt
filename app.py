from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from url_scan import scan_url  # Dein Scan-Code muss in url_scan.py sein

app = FastAPI(title="Security Guard API")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Startseite mit Formular.
    """
    return templates.TemplateResponse("index.html", {"request": request, "result": None, "error": None})


@app.post("/check", response_class=HTMLResponse)
def check_url(request: Request, url: str = Form(...)):
    """
    URL prüfen und Ergebnis anzeigen.
    """
    if not url.startswith("http"):
        # Fehler anzeigen, wenn die URL ungültig ist
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": "Ungültige URL. Bitte mit http:// oder https:// beginnen.", "result": None}
        )

    # URL scannen
    result = scan_url(url)

    # Ergebnis zurückgeben
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "result": result, "url": url, "error": None}
    )
