import re
from email.utils import parseaddr

SUSPICIOUS_EMAIL_ENDINGS = ["@free-email.com", "@secure-mail.org", "@unknown-domain.net"]
SUSPICIOUS_LINKS = ["account-login", "verify-now", "update-details"]

def scan_email(sender, subject, body):
    score = 100
    details = []

    # Absenderadresse überprüfen
    username, domain = parseaddr(sender)[1].split("@")
    if f"@{domain}" in SUSPICIOUS_EMAIL_ENDINGS:
        deduction = 25
        score -= deduction
        details.append(("Verdächtige Absenderadresse", deduction, "Herkunft von Free/Unbekannten Mailservern."))

    # Suche nach Keywords im E-Mail-Text
    found_keywords = [w for w in SUSPICIOUS_LINKS if w in body.lower()]
    if found_keywords:
        deduction = len(found_keywords) * 10
        score -= deduction
        details.append(("Verdächtige Links im Inhalt", deduction, f"Gefunden: {', '.join(found_keywords)}"))

    # Überprüfung des Betreffs auf hohe Dringlichkeit
    if "dringend" in subject.lower() or "sofort" in subject.lower():
        deduction = 15
        score -= deduction
        details.append(("Dringlichkeitssubjekt", deduction, "Emotionale, dringliche Worte gefunden."))

    # Überprüfung auf unbekannte Domains oder verkürzte Links
    if any(link in body.lower() for link in ["bit.ly", "tinyurl", "shorturl"]):
        deduction = 20
        score -= deduction
        details.append(("Verkürzte Links", deduction, "Verkürzte Links verwenden oft zum Verschleiern."))

    score = max(score, 0)
    status = "Gefährlich" if score < 40 else "Potentiell Gefährlich" if score < 70 else "Ungefährlich"

    return {
        "score": score,
        "status": status,
        "details": details
    }