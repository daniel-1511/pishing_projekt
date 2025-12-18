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
        "neue nummer", "handy kaputt",
        "bitte hilf mir", "ich brauche geld"
    ],

    "geld": [
        "überweis", "überweisung", "zahlung",
        "zahlen", "bezahlen", "geld",
        "betrag", "rechnung", "paypal"
    ],

    "bank": [
        "bank", "konto", "iban",
        "login", "verifizieren",
        "passwort", "pin", "tan", "code"
    ],

    "gewinn": [
        "gewonnen", "gewinn", "preis",
        "jackpot", "lotterie",
        "gutschein", "bonus", "belohnung"
    ],

    "gratis": [
        "gratis", "kostenlos", "free",
        "umsonst", "geschenk", "0€"
    ],

    "druck": [
        "dringend", "sofort", "jetzt",
        "letzte chance", "heute", "frist"
    ],

    "link": [
        "hier klicken", "klick hier",
        "jetzt bestätigen"
    ]
}

# =====================================================
# HILFSFUNKTIONEN
# =====================================================

def keyword_found(text: str, keyword: str) -> bool:
    if " " in keyword:
        return keyword in text
    return re.search(rf"\b{re.escape(keyword)}\b", text) is not None


def highlight_suspicious_words(text: str, found: Dict[str, List[str]]) -> str:
    highlighted = text
    for words in found.values():
        for word in sorted(words, key=len, reverse=True):
            highlighted = re.sub(
                re.escape(word),
                r"<mark>\g<0></mark>",
                highlighted,
                flags=re.IGNORECASE
            )
    return highlighted

# =====================================================
# SMS-ANALYSE
# =====================================================

def scan_sms(sms_text: str) -> Dict:
    score = 100
    details = []

    sms_lower = sms_text.lower()
    found = {category: [] for category in PHISHING_KEYWORDS}

    # 🔍 Keywords finden
    for category, words in PHISHING_KEYWORDS.items():
        for word in words:
            if keyword_found(sms_lower, word):
                found[category].append(word)

    highlighted_text = highlight_suspicious_words(sms_text, found)

    # =================================================
    # 🚨 FAMILIE
    # =================================================

    family_verification = {
        "active": False,
        "title": "",
        "steps_before_reply": [],
        "analysis": ""
    }

    if found["familie"]:
        family_verification["active"] = True
        family_verification["title"] = "Hinweis: Familienbezug erkannt"
        family_verification["analysis"] = (
            "SMS mit Familienbezug werden häufig für Betrug missbraucht."
        )
        family_verification["steps_before_reply"] = [
            "Nicht direkt antworten",
            "Person über gespeicherte Nummer anrufen",
            "Kein Geld überweisen",
            "Keine Codes weitergeben"
        ]

        score -= 40
        details.append(("Familienbezug", 40, ", ".join(found["familie"])))

    if found["familie"] and found["geld"]:
        score -= 30
        details.append(("Familie + Geld", 30, "Sehr hohes Risiko"))

    # =================================================
    # 🎁 GEWINN / GRATIS → IMMER −50
    # =================================================

    if found["gewinn"] or found["gratis"]:
        score -= 50
        details.append((
            "Gewinn- oder Gratisversprechen",
            50,
            "Typisches Betrugsmuster"
        ))

    # Verstärkung bei Druck
    if (found["gewinn"] or found["gratis"]) and found["druck"]:
        score -= 20
        details.append((
            "Zeitdruck",
            20,
            "Erhöhtes Risiko durch Dringlichkeit"
        ))

    # =================================================
    # 🔗 LINK
    # =================================================

    if re.search(r"(https?://|www\.)", sms_lower):
        score -= 25
        details.append(("Link erkannt", 25, "Externer Link enthalten"))

    # 🔢 Zahlencodes
    if re.search(r"\b\d{5,}\b", sms_text):
        score -= 15
        details.append(("Zahlencode", 15, "Verdächtige Zahlenfolge"))

    score = max(score, 0)

    # =================================================
    # 🚦 STATUS
    # =================================================

    if score < 30:
        status = "GEFÄHRLICH"
        color = "red"
    elif score < 60:
        status = "POTENTIELL GEFÄHRLICH"
        color = "orange"
    else:
        status = "UNGEFÄHRLICH"
        color = "green"

    # ❗ Gewinn/Gratis NIE sicher
    if (found["gewinn"] or found["gratis"]) and status == "UNGEFÄHRLICH":
        status = "POTENTIELL GEFÄHRLICH"
        color = "orange"

    # ❗ Familie NIE sicher
    if family_verification["active"] and status == "UNGEFÄHRLICH":
        status = "POTENTIELL GEFÄHRLICH"
        color = "orange"

    return {
        "score": score,
        "status": status,
        "color": color,
        "details": details,
        "highlighted_text": highlighted_text,
        "family_verification": family_verification
    }

# =====================================================
# TEST
# =====================================================

if __name__ == "__main__":
    sms = "Glückwunsch! Sie haben einen GRATIS Gutschein gewonnen. Jetzt hier klicken!"
    result = scan_sms(sms)
    for k, v in result.items():
        print(f"{k}: {v}")
