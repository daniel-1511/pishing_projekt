from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from scan.url_scan import scan_url
from scan.sms_scan import scan_sms
from scan.email_scan import scan_email
from urllib.parse import urlparse

app = FastAPI(title="CyberNet Security")
templates = Jinja2Templates(directory="templates")


# ===========================
# HOME
# ===========================
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "url_result": None,
            "sms_result": None,
            "email_result": None,
            "error": None,
            "url": "",
            "sms_text": "",
            "email_sender": "",
            "email_subject": "",
            "email_body": ""
        }
    )


# ===========================
# URL SCAN
# ===========================
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
                "url_result": None,
                "sms_result": None,
                "email_result": None,
                "url": url
            }
        )

    try:
        result = scan_url(url)
    except Exception as e:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": f"Fehler beim Scannen der Website: {str(e)}",
                "url_result": None,
                "sms_result": None,
                "email_result": None,
                "url": url
            }
        )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "url_result": result,
            "sms_result": None,
            "email_result": None,
            "url": url
        }
    )


# ===========================
# SMS SCAN
# ===========================
@app.post("/check-sms", response_class=HTMLResponse)
def check_sms(request: Request, sms_text: str = Form(...)):
    sms_text = sms_text.strip()
    try:
        result = scan_sms(sms_text)
    except Exception as e:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": f"Fehler beim Scannen der SMS: {str(e)}",
                "url_result": None,
                "sms_result": None,
                "email_result": None,
                "sms_text": sms_text
            }
        )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "sms_result": result,
            "url_result": None,
            "email_result": None,
            "sms_text": sms_text
        }
    )


# ===========================
# EMAIL SCAN
# ===========================
@app.post("/check-email", response_class=HTMLResponse)
def check_email(request: Request,
                email_sender: str = Form(...),
                email_subject: str = Form(...),
                email_body: str = Form(...)):
    email_sender = email_sender.strip()
    email_subject = email_subject.strip()
    email_body = email_body.strip()

    try:
        result = scan_email(email_sender, email_subject, email_body)
    except Exception as e:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": f"Fehler beim Scannen der E-Mail: {str(e)}",
                "url_result": None,
                "sms_result": None,
                "email_result": None,
                "email_sender": email_sender,
                "email_subject": email_subject,
                "email_body": email_body
            }
        )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "email_result": result,
            "url_result": None,
            "sms_result": None,
            "email_sender": email_sender,
            "email_subject": email_subject,
            "email_body": email_body
        }
    )
