import re

SUSPICIOUS_KEYWORDS = ["gewonnen", "preis", "bank", "konto", "loggen", "hier klicken", "verifizieren"]

def scan_sms(sms_text):
    score = 100
    details = []

    if len(sms_text) > 160:
        deduction = 10
        score -= deduction
        details.append(("Länge der Nachricht", deduction, "Nachricht ist länger als normale SMS."))

    # Überprüfung auf verdächtige Keywords
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in sms_text.lower()]
    if found_keywords:
        deduction = len(found_keywords) * 5
        score -= deduction
        details.append(("Verdächtige Wörter", deduction, f"Gefunden: {', '.join(found_keywords)}"))

    # Suche nach Links in der Nachricht
    if "http" in sms_text or "www" in sms_text:
        deduction = 20
        score -= deduction
        details.append(("Verdächtige Links", deduction, "Links werden oft für Phishing genutzt."))

    # Detektion von ungewöhnlichen Zahlmustern (z. B. Gewinnspiel-Codes)
    if re.search(r"\b\d{6}\b", sms_text):
        deduction = 15
        score -= deduction
        details.append(("Ungewöhnliches Zahlmuster", deduction, "Gefunden: Sequenz aus 6 Ziffern."))

    score = max(score, 0)
    status = "Gefährlich" if score < 40 else "Potentiell Gefährlich" if score < 70 else "Ungefährlich"

    return {
        "score": score,
        "status": status,
        "details": details
    }