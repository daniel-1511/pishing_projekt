import re
from email.utils import parseaddr
import ollama

SUSPICIOUS_EMAIL_ENDINGS = ["@free-email.com", "@secure-mail.org", "@unknown-domain.net"]
SUSPICIOUS_LINKS = ["account-login", "verify-now", "update-details"]

# 🤖 KI-Erklärung und Score generieren mit Ollama
def generate_ai_explanation_email(sender, subject, body, score, status, details):
    prompt = f"""Du bist ein E-Mail-Sicherheits-Profi. Erkläre diese E-Mail wie zu einem Freund - EINFACH!

Von: {sender}
Betreff: {subject}
Text: {body[:300]}

ANTWORTE GENAU IN DIESEM FORMAT (strukturiert und übersichtlich):

KURZ (3 Stichpunkte):
• Punkt 1: (kurz und knapp)
• Punkt 2: (kurz und knapp)
• Punkt 3: (kurz und knapp)

DETAILS:

🚨 IST DIESE E-MAIL EIN BETRUG?
(Ja/Nein + klare Begründung in 1-2 Sätzen)

🎯 WAS WOLLEN DIE BETRÜGER?
- Ziel 1 (z.B. Passwort klauen, Geld verlangen)
- Ziel 2
- Ziel 3

🔴 WARNSIGNALE IN DER E-MAIL:
- Signal 1 (z.B. "Dringend handeln!")
- Signal 2
- Signal 3

📌 ECHTE BEISPIELE:
(Gib ein oder zwei echte Betrugsbeispiele)

✅ WAS SOLL ICH TUN:
- Tipp 1 (z.B. nicht auf Links klicken)
- Tipp 2
- Tipp 3

---

WICHTIG:
- KEINE Fachbegriffe
- Kurz und deutlich
- Nummeriere und strukturiere alles
- Verwende Emojis für Übersichtlichkeit"""
    
    try:
        response = ollama.chat(model='llama3.2', messages=[{'role': 'user', 'content': prompt}])
        explanation = response['message']['content'].strip()
        return score, explanation
    except Exception as e:
        return score, f"KI-Analyse nicht verfügbar: {str(e)}"

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