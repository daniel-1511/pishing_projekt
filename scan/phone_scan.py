import re

# 🚨 HARTE BLACKLIST – sofort Score 0
BLACKLISTED_PHONE_NUMBERS = [
    "0000", "00000", "000000", "0000000", "000000000",
    "1111", "11111", "111111", "111222333",
    "12345", "123456", "1234567", "123456789",
    "99999", "999888777", "999999999",
    "+99123456789", "+37111222333", "+86999888777",
    "+123456789", "+987654321",
    "555-555-555", "000-000-000", "123-456-789",
    "+1111111111", "+2222222222", "+3333333333"
]

# 🚫 Anonyme / versteckte Nummern
ANONYMOUS_KEYWORDS = [
    "anonym", "unknown", "unbekannt",
    "private", "private number",
    "hidden", "blocked"
]

# ⚠️ Verdächtige Länderpräfixe
SUSPICIOUS_COUNTRY_CODES = [
    "+99", "+86", "+37", "+231", "+252"
]

# ⚠️ Auffällige Muster
SUSPICIOUS_PATTERNS = [
    r"(\d)\1{5,}",
    r"\b12345\b",
    r"\b0000\b",
    r"\d{3}-\d{3}-\d{3}"
]


def scan_phone_number(phone_number: str):
    phone_number = phone_number.strip().lower()

    # 🚫 ANONYM / UNBEKANNT → SOFORT GEFÄHRLICH
    if any(word in phone_number for word in ANONYMOUS_KEYWORDS):
        return {
            "score": 0,
            "status": "EXTREM GEFÄHRLICH",
            "details": [
                (
                    "Anonymer Anruf",
                    100,
                    "Anonyme oder versteckte Nummern werden sehr häufig für Betrug oder Belästigung genutzt. "
                    "Es wird dringend empfohlen, nicht ranzugehen."
                )
            ]
        }

    # 🚨 BLACKLIST CHECK
    if phone_number in BLACKLISTED_PHONE_NUMBERS:
        return {
            "score": 0,
            "status": "EXTREM GEFÄHRLICH (BLACKLIST)",
            "details": [
                (
                    "Nummer auf Blacklist",
                    100,
                    "Diese Telefonnummer ist als betrügerisch bekannt und sollte blockiert werden."
                )
            ]
        }

    score = 100
    details = []

    # 🌍 Länderpräfix
    if any(phone_number.startswith(code) for code in SUSPICIOUS_COUNTRY_CODES):
        score -= 25
        details.append((
            "Ungewöhnliche Ländervorwahl",
            25,
            "Anrufe aus bestimmten Ländern werden sehr oft für Betrug genutzt."
        ))

    # 🔁 Muster
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, phone_number):
            score -= 15
            details.append((
                "Auffälliges Zahlenmuster",
                15,
                "Die Nummer sieht automatisch erzeugt aus."
            ))
            break

    # 📏 Länge
    if len(phone_number) < 7 or len(phone_number) > 15:
        score -= 10
        details.append((
            "Ungewöhnliche Länge",
            10,
            "Echte Telefonnummern haben normalerweise eine feste Länge."
        ))

    # ❌ Ungültige Zeichen
    if re.search(r"[^\d+ -]", phone_number):
        score -= 5
        details.append((
            "Ungültige Zeichen",
            5,
            "Telefonnummern bestehen normalerweise nur aus Zahlen."
        ))

    score = max(score, 0)

    # 🧠 Status
    if score <= 10:
        status = "Extrem gefährlich"
    elif score <= 30:
        status = "Unsicher"
    elif score <= 60:
        status = "Potentiell gefährlich"
    else:
        status = "Sicher"

    return {
        "score": score,
        "status": status,
        "details": details
    }
