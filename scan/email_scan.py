import re
from email.utils import parseaddr
import ollama

SUSPICIOUS_EMAIL_ENDINGS = ["@free-email.com", "@secure-mail.org", "@unknown-domain.net"]
SUSPICIOUS_LINKS = ["account-login", "verify-now", "update-details"]

# 🤖 KI-Erklärung und Score generieren mit Ollama
def generate_ai_explanation_email(sender, subject, body, score, status, details):
    prompt = f"Analysiere diese E-Mail auf Phishing-Risiken. Gib einen Score von 0-100 (0=extrem gefährlich, 100=vollkommen sicher) und erkläre kurz auf Deutsch, warum sie sicher oder gefährlich ist. Format: Score: [zahl]\nErklärung: [text]\n\nAbsender: {sender}, Betreff: {subject}, Inhalt: {body}"
    try:
        response = ollama.chat(model='llama3.2', messages=[{'role': 'user', 'content': prompt}])
        content = response['message']['content'].strip()
        
        # Parse Score und Erklärung
        lines = content.split('\n')
        ai_score = score  # Fallback
        explanation = content
        
        for line in lines:
            if line.lower().startswith('score:'):
                try:
                    ai_score = int(line.split(':')[1].strip())
                    ai_score = max(0, min(100, ai_score))  # Clamp 0-100
                except:
                    pass
            elif line.lower().startswith('erklärung:'):
                explanation = line.split(':', 1)[1].strip()
                break
        
        return ai_score, explanation
    except Exception as e:
        return score, ""

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

    # Initialer Status für KI-Prompt
    status = "Unbekannt"

    # 🤖 KI-Erklärung und Score generieren
    ai_score, ai_explanation = generate_ai_explanation_email(sender, subject, body, score, status, details)

    # 🧠 Status basierend auf KI-Score
    if ai_score < 40:
        status = "Gefährlich"
    elif ai_score < 70:
        status = "Potentiell Gefährlich"
    else:
        status = "Ungefährlich"

    return {
        "score": ai_score,
        "status": status,
        "details": details,
        "ai_explanation": ai_explanation
    }