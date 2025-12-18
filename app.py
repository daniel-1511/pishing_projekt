from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import urlparse

# Scanner importieren
from scan.url_scan import scan_url
from scan.sms_scan import scan_sms
from scan.email_scan import scan_email
from scan.phone_scan import scan_phone_number

app = FastAPI(title="CyberNet Security")
templates = Jinja2Templates(directory="templates")


# ======================================================
# STARTSEITE
# ======================================================
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,

            # Ergebnisse
            "url_result": None,
            "sms_result": None,
            "email_result": None,
            "phone_result": None,

            # Eingaben
            "url": "",
            "sms_text": "",
            "email_sender": "",
            "email_subject": "",
            "email_body": "",
            "phone_number": "",

            "error": None
        }
    )


# ======================================================
# URL SCAN
# ======================================================
@app.post("/check", response_class=HTMLResponse)
def check_url(request: Request, url: str = Form(...)):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Bitte eine gültige URL mit http:// oder https:// eingeben.",
                "url": url
            }
        )

    parsed = urlparse(url)
    if not parsed.netloc:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Die URL scheint ungültig zu sein.",
                "url": url
            }
        )

    result = scan_url(url)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "url_result": result,
            "url": url
        }
    )


# ======================================================
# SMS SCAN
# ======================================================
@app.post("/check-sms", response_class=HTMLResponse)
def check_sms(request: Request, sms_text: str = Form(...)):
    sms_text = sms_text.strip()

    result = scan_sms(sms_text)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "sms_result": result,
            "sms_text": sms_text
        }
    )


# ======================================================
# EMAIL SCAN
# ======================================================
@app.post("/check-email", response_class=HTMLResponse)
def check_email(
    request: Request,
    email_sender: str = Form(...),
    email_subject: str = Form(...),
    email_body: str = Form(...)
):
    email_sender = email_sender.strip()
    email_subject = email_subject.strip()
    email_body = email_body.strip()

    result = scan_email(email_sender, email_subject, email_body)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "email_result": result,
            "email_sender": email_sender,
            "email_subject": email_subject,
            "email_body": email_body
        }
    )


# ======================================================
# TELEFONNUMMER SCAN
# ======================================================
@app.post("/check-phone", response_class=HTMLResponse)
def check_phone(request: Request, phone_number: str = Form(...)):
    phone_number = phone_number.strip()

    result = scan_phone_number(phone_number)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "phone_result": result,
            "phone_number": phone_number
        }
    )
