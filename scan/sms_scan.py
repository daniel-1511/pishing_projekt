import re
from typing import Dict, List

# =====================================================
# PHISHING-SCHLÜSSELWÖRTER
# =====================================================

PHISHING_KEYWORDS: Dict[str, List[str]] = {

    "familie": [
        "hallo mama", "hallo papa",
        "mama", "papa", "mutti", "vati",
        "mutter", "vater",
        "sohn", "tochter", "bruder", "schwester",
        "oma", "opa",
        "neue nummer", "neue handynummer",
        "handy kaputt", "kann nicht telefonieren",
        "bitte hilf mir", "ich brauche geld",
        "melde dich"
    ],

    "geld": [
        "überweis", "überweisung", "zahlung", "zahlen", "bezahlen",
        "geld", "betrag", "rechnung", "mahnung",
        "paypal", "klarna", "sofortüberweisung"
    ],

    "bank": [
        "bank", "konto", "iban", "login", "verifizieren",
        "bestätigen", "gesperrt", "passwort", "pin", "tan"
    ],

    "druck": [
        "dringend", "sofort", "jetzt", "heute",
        "letzte chance", "24 stunden", "umgehend"
    ],

    "link": [
        "hier klicken", "klick hier", "link öffnen"
    ]
}

# =====================================================
# SMS SCANNER
# =====================================================

def scan_sms(sms_text: str) -> Dict:
    score = 100
    details = []
    warnings = []
    sms_lower = sms_text.lower()

    found = {category: [] for category in PHISHING_KEYWORDS}

    # 🔍 Schlüsselwörter finden
    for category, words in PHISHING_KEYWORDS.items():
        for word in words:
            if re.search(rf"\b{re.escape(word)}\b", sms_lower):
                found[category].append(word)

    # 🚨 Familienbezug
    if found["familie"]:
        score -= 40
        details.append((
            "Familienbezug erkannt",
            40,
            f"Begriffe: {', '.join(found['familie'])}"
        ))

        warnings.append(
            "⚠️ In dieser Nachricht werden Familienmitglieder erwähnt.\n"
            "Gehe besonders vorsichtig vor:\n"
            "- Antworte NICHT direkt auf diese Nachricht\n"
            "- Kontaktiere die Person über eine bereits gespeicherte Nummer\n"
            "- Frage ein anderes Familienmitglied, ob die Nachricht echt ist\n"
            "- Überweise kein Geld und teile keine Codes"
        )

    # 🚨 Familie + Geld
    if found["familie"] and found["geld"]:
        score -= 30
        details.append((
            "Familien-Geld-Kombination",
            30,
            "Sehr typisches Betrugsmuster (Hallo‑Mama/Papa‑Betrug)"
        ))

    # 🔗 Links
    if re.search(r"(https?://|www\.)", sms_lower):
        score -= 25
        details.append(("Link", 25, "Verdächtiger Link gefunden"))

    # 🔢 Zahlencodes
    if re.search(r"\b\d{5,}\b", sms_text):
        score -= 15
        details.append(("Code", 15, "Langer Zahlencode gefunden"))

    # 🔎 Allgemeine Schlüsselwörter
    total_keywords = sum(len(v) for v in found.values())
    if total_keywords:
        deduction = min(total_keywords * 3, 35)
        score -= deduction
        details.append((
            "Phishing-Muster",
            deduction,
            f"Anzahl erkannter Muster: {total_keywords}"
        ))

    score = max(score, 0)

    # 🚦 Status
    if score < 30:
        status = "GEFÄHRLICH"
        color = "red"
    elif score < 60:
        status = "POTENTIELL GEFÄHRLICH"
        color = "orange"
    else:
        status = "UNGEFÄHRLICH"
        color = "green"

    return {
        "score": score,
        "status": status,
        "color": color,
        "details": details,
        "warnings": warnings
    }

# =====================================================
# DEMO
# =====================================================

if __name__ == "__main__":
    sms = "Hallo Mama, mein Handy ist kaputt. Bitte überweis mir sofort 800€."
    result = scan_sms(sms)

    print("SMS:", sms)
    print("\nBewertung:")
    for k, v in result.items():
        print(f"{k}: {v}")
