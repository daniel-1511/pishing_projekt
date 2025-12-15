from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from url_scan import scan_url

app = FastAPI(title="CyberNet Security Guard")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "result": None, "error": None, "url": ""}
    )


@app.post("/check", response_class=HTMLResponse)
async def check_url(request: Request, url: str = Form(...)):
    if not url.startswith(("http://", "https://")):
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": "Ungültige URL. Bitte mit http:// oder https:// beginnen.", "result": None, "url": ""}
        )
    result = scan_url(url)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "result": result, "url": url, "error": None}
    )
