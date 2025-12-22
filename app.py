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
# TEMPLATE RENDER HELPER
# ======================================================
def render_index(request: Request, **kwargs):
    context = {
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

        "error": None,
    }

    context.update(kwargs)
    return templates.TemplateResponse("index.html", context)


# ======================================================
# STARTSEITE
# ======================================================
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render_index(request)


# ======================================================
# URL SCAN
# ======================================================
@app.post("/check", response_class=HTMLResponse)
def check_url(request: Request, url: str = Form(...)):
    url = url.strip()

    if not url:
        return render_index(
            request,
            error="Bitte eine URL eingeben."
        )

    if not url.startswith(("http://", "https://")):
        return render_index(
            request,
            error="Bitte eine gültige URL mit http:// oder https:// eingeben.",
            url=url
        )

    parsed = urlparse(url)
    if not parsed.netloc:
        return render_index(
            request,
            error="Die URL scheint ungültig zu sein.",
            url=url
        )

    result = scan_url(url)

    return render_index(
        request,
        url_result=result,
        url=url
    )

# GET-Fallback für /check – kein Error mehr beim Neuladen
@app.get("/check", response_class=HTMLResponse)
def check_url_get(request: Request):
    return render_index(request)


# ======================================================
# SMS SCAN
# ======================================================
@app.post("/check-sms", response_class=HTMLResponse)
def check_sms(request: Request, sms_text: str = Form(...)):
    sms_text = sms_text.strip()

    if not sms_text:
        return render_index(
            request,
            error="Bitte einen SMS-Text eingeben."
        )

    result = scan_sms(sms_text)

    return render_index(
        request,
        sms_result=result,
        sms_text=sms_text
    )

# GET-Fallback für /check-sms – kein Error mehr beim Neuladen
@app.get("/check-sms", response_class=HTMLResponse)
def check_sms_get(request: Request):
    return render_index(request)


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

    if not email_sender or not email_subject or not email_body:
        return render_index(
            request,
            error="Bitte alle E-Mail-Felder ausfüllen.",
            email_sender=email_sender,
            email_subject=email_subject,
            email_body=email_body
        )

    result = scan_email(email_sender, email_subject, email_body)

    return render_index(
        request,
        email_result=result,
        email_sender=email_sender,
        email_subject=email_subject,
        email_body=email_body
    )

# GET-Fallback für /check-email – kein Error mehr beim Neuladen
@app.get("/check-email", response_class=HTMLResponse)
def check_email_get(request: Request):
    return render_index(request)


# ======================================================
# TELEFONNUMMER SCAN
# ======================================================
@app.post("/check-phone", response_class=HTMLResponse)
def check_phone(request: Request, phone_number: str = Form(...)):
    phone_number = phone_number.strip()

    if not phone_number:
        return render_index(
            request,
            error="Bitte eine Telefonnummer eingeben."
        )

    result = scan_phone_number(phone_number)

    return render_index(
        request,
        phone_result=result,
        phone_number=phone_number
    )

# GET-Fallback für /check-phone – kein Error mehr beim Neuladen
@app.get("/check-phone", response_class=HTMLResponse)
def check_phone_get(request: Request):
    return render_index(request)
