import re

# Liste bekannter verdächtiger Telefonnummern (zum Beispiel aus einer Blacklist)
SUSPICIOUS_PHONE_NUMBERS = [
    "+123456789", "+987654321", "111222333", "999888777"
]

# Schlüsselwörter oder Muster, die auf verdächtige Aktivitäten hinweisen könnten
SUSPICIOUS_PATTERNS = [
    r"\b(12345|54321|0000)\b",  # Einfache aufeinanderfolgende Zahlen
    r"\d{3}-\d{3}-\d{3}",       # Amerikanisches Nummernmuster
    r"(\d)\1{5,}",               # Wiederholung derselben Ziffer mehr als 5-Mal
]

# Verdächtige Länderpräfixe
SUSPICIOUS_COUNTRY_CODES = [
    "+99", "+86", "+37",  # Beispielhafte Präfixe für betrügerische Länder
]


def scan_phone_number(phone_number):
    score = 100
    details = []

    # Ungewöhnliches Länderpräfix (Prüfung auf bekannte verdächtige Präfixe)
    if any(phone_number.startswith(prefix) for prefix in SUSPICIOUS_COUNTRY_CODES):
        deduction = 25
        score -= deduction
        details.append(("Verdächtiges Ländervorwahl", deduction, f"Gefundenes Präfix: {phone_number[:4]}"))

    # Prüfung von bekannten verdächtigen Telefonnummern
    if phone_number in SUSPICIOUS_PHONE_NUMBERS:
        deduction = 40
        score -= deduction
        details.append(("Bekannte verdächtige Telefonnummer", deduction, f"Gefunden: {phone_number}"))

    # Prüfung auf wiederholte Muster
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, phone_number):
            deduction = 15
            score -= deduction
            details.append(("Verdächtiges Muster", deduction, f"Gefundenes Muster: {pattern}"))

    # Telefonnummer ist zu kurz oder zu lang
    if len(phone_number) < 7 or len(phone_number) > 15:
        deduction = 10
        score -= deduction
        details.append(("Ungewöhnliche Länge", deduction, f"Telefonnummer hat {len(phone_number)} Zeichen"))

    # Prüfung auf Sonderzeichen oder ungültige Zeichen
    if re.search(r"[^\d+]", phone_number):
        deduction = 5
        score -= deduction
        details.append(("Ungültige Zeichen gefunden", deduction, "Telefonnummer enthält nicht-numerische Zeichen"))

    # Maximieren und Status interpretieren
    score = max(score, 0)
    if score <= 10:
        status = "Extrem gefährlich"
    elif score <= 30:
        status = "Unsicher"
    elif score <= 60:
        status = "Potentiell sicher"
    else:
        status = "Sicher"

    # Ergebnis des Scans zurückgeben
    return {
        "score": score,
        "status": status,
        "details": details,
    }