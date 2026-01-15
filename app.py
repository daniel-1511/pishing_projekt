from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from urllib.parse import urlparse
import subprocess
import re

# SCANNER IMPORTE
from scan.url_scan import scan_url
from scan.sms_scan import scan_sms
from scan.email_scan import scan_email
from scan.phone_scan import scan_phone_number

# HELPER FUNCTION - Parse AI explanation in short and full
def parse_ai_explanation(text):
    """Parse AI explanation into short (3 bullets) and full text"""
    short_text = ""
    full_text = ""
    
    # Split by "DETAILS:" marker
    if "DETAILS:" in text:
        parts = text.split("DETAILS:", 1)
        short_part = parts[0].replace("KURZ (3 Stichpunkte):", "").strip()
        full_part = parts[1].strip() if len(parts) > 1 else ""
        
        # Extract bullet points
        bullets = [line.strip() for line in short_part.split("\n") if line.strip().startswith("•")]
        short_text = "\n".join(bullets[:3]) if bullets else short_part[:200]
        full_text = full_part if full_part else text
    else:
        # Fallback: use first 3 lines as short, rest as full
        lines = text.split("\n")
        short_text = "\n".join(lines[:3])
        full_text = text
    
    return short_text, full_text

# HELPER FUNCTION - Format AI explanation as HTML
def format_ai_explanation_html(text):
    """Convert structured AI text to formatted HTML"""
    html = ""
    lines = text.split("\n")
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Skip empty lines
        if not line:
            i += 1
            continue
        
        # Headers with emojis (🚨, 🎯, 🔴, 📌, ✅)
        if any(emoji in line for emoji in ["🚨", "🎯", "🔴", "📌", "✅"]) and ":" in line:
            html += f"<strong style='color: #2196F3; display: block; margin-top: 12px; margin-bottom: 6px; font-size: 16px;'>{line}</strong>"
            i += 1
            
            # Collect bullet points until next header or end
            while i < len(lines):
                next_line = lines[i].strip()
                if not next_line:
                    i += 1
                    continue
                if any(emoji in next_line for emoji in ["🚨", "🎯", "🔴", "📌", "✅"]) and ":" in next_line:
                    break
                if next_line.startswith("-"):
                    if not html.endswith("<ul>"):
                        html += "<ul style='margin: 6px 0 12px 0; padding-left: 25px;'>"
                    html += f"<li>{next_line[1:].strip()}</li>"
                elif next_line.startswith("•"):
                    if not html.endswith("<ul>"):
                        html += "<ul style='margin: 6px 0 12px 0; padding-left: 25px;'>"
                    html += f"<li>{next_line[1:].strip()}</li>"
                else:
                    if html.endswith("</li>"):
                        html += "</ul>"
                    html += f"<p style='margin: 8px 0; line-height: 1.6;'>{next_line}</p>"
                i += 1
            
            # Close ul if open
            if html.count("<ul") > html.count("</ul"):
                html += "</ul>"
        else:
            i += 1
    
    return html

# APP SETUP
app = FastAPI(title="CyberNet Security")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# KI SYSTEM PROMPT (OLLAMA)
SYSTEM_PROMPT = """Du bist ein erfahrener Cybersecurity-Profi mit 10+ Jahren Erfahrung in Betrugserkennung.

DEINE EXPERTISE:
- Du verstehst Phishing, Betrug und Hacker-Tricks
- Du kennst alle gängigen Betrugsmuster
- Du erkennst versteckte Gefahren sofort

ABER: Du erklärst ALLES in einfachen Worten! Keine Fachjargon!

WIE DU ANTWORTEST:
✓ Nutze einfache Wörter, die jeder versteht
✓ Erkläre wie zu einem Freund, nicht wie in einem Lehrbuch
✓ Gib konkrete Beispiele aus dem echten Leben
✓ Nenne die Gefahren klar und deutlich
✓ Gib praktische Tipps, was der Nutzer TUN soll

✗ Verwende KEINE Fachbegriffe wie "Trojaner", "Malware", "Phishing-Domain"
✗ Schreib nicht kompliziert - kurz und verständlich!
✗ Erstelle NIEMALS Anleitungen für Betrüger

BEISPIEL (Schlecht): "Die URL zeigt Indikatoren für Domain-Typosquatting via SSL-Zertifikat-Anomalien."
BEISPIEL (Gut): "Die Website sieht aus wie Amazon, ist aber nicht echt. Das ist ein Trick von Betrügern."

ANTWORT-FORMAT:
1. Warnung in einfachen Worten (was ist das Problem?)
2. Warum das gefährlich ist (konkrete Beispiele)
3. Was der Nutzer TUN soll (praktische Tipps)
"""

# TEMPLATE RENDER HELPER
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
    
    # Parse AI explanations if present
    if context.get("url_result") and context["url_result"].get("ai_explanation"):
        short, full = parse_ai_explanation(context["url_result"]["ai_explanation"])
        context["url_result"]["ai_explanation_short"] = short
        context["url_result"]["ai_explanation_full"] = format_ai_explanation_html(full)
    
    if context.get("email_result") and context["email_result"].get("ai_explanation"):
        short, full = parse_ai_explanation(context["email_result"]["ai_explanation"])
        context["email_result"]["ai_explanation_short"] = short
        context["email_result"]["ai_explanation_full"] = format_ai_explanation_html(full)
    
    if context.get("sms_result") and context["sms_result"].get("ai_explanation"):
        short, full = parse_ai_explanation(context["sms_result"]["ai_explanation"])
        context["sms_result"]["ai_explanation_short"] = short
        context["sms_result"]["ai_explanation_full"] = format_ai_explanation_html(full)
    
    if context.get("phone_result") and context["phone_result"].get("ai_explanation"):
        short, full = parse_ai_explanation(context["phone_result"]["ai_explanation"])
        context["phone_result"]["ai_explanation_short"] = short
        context["phone_result"]["ai_explanation_full"] = format_ai_explanation_html(full)
    
    return templates.TemplateResponse("index.html", context)

# STARTSEITE
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render_index(request)

# URL SCAN
@app.post("/check", response_class=HTMLResponse)
def check_url(request: Request, url: str = Form(...)):
    url = url.strip()

    if not url:
        return render_index(request, error="Bitte eine URL eingeben.")

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
        return render_index(request, error="Bitte einen SMS-Text eingeben.")

    result = scan_sms(sms_text)

    return render_index(
        request,
        sms_result=result,
        sms_text=sms_text
    )

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
        return render_index(request, error="Bitte eine Telefonnummer eingeben.")

    result = scan_phone_number(phone_number)

    return render_index(
        request,
        phone_result=result,
        phone_number=phone_number
    )

@app.get("/check-phone", response_class=HTMLResponse)
def check_phone_get(request: Request):
    return render_index(request)

# ======================================================
# ✅ KI-CHAT (ECHTE KI, KOSTENLOS, OLLAMA)
# ======================================================
@app.post("/chat", response_class=JSONResponse)
async def chat(request: Request):
    form = await request.form()
    message = form.get("message", "").strip()

    if not message:
        return {"answer": "Bitte eine Frage eingeben."}

    prompt = f"{SYSTEM_PROMPT}\n\nFrage:\n{message}\n\nAntwort:"

    try:
        result = subprocess.run(
            ["ollama", "run", "mistral", prompt],
            capture_output=True,
            text=True,
            timeout=90
        )

        answer = result.stdout.strip()

        if not answer:
            return {"answer": "Die KI hat keine Antwort geliefert."}

        return {"answer": answer}

    except FileNotFoundError:
        return {"answer": "Ollama ist nicht installiert oder nicht im PATH."}

    except Exception as e:
        return {"answer": f"KI-Fehler: {str(e)}"}
