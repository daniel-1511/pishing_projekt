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
    "+1111111111", "+2222222222", "+3333333333",
    # Beliebte Scammer-Nummern
    "+27", "+234", "+237", "+256", "+255",
    "+212", "+233", "+241", "+880", "+92",
    "+88", "+998", "+996", "+7", "+375"
]

# 🚫 Anonyme / versteckte Nummern
ANONYMOUS_KEYWORDS = [
    "anonym", "unknown", "unbekannt",
    "private", "private number",
    "hidden", "blocked", "withheld",
    "call blocked", "private caller"
]

# ⚠️ Verdächtige Länderpräfixe (bekannt für Schwindel & Betrug)
SUSPICIOUS_COUNTRY_CODES = [
    "+99",   # Ungültig
    "+86",   # China (häufig für Phishing)
    "+37",   # Estland
    "+231",  # Liberia
    "+252",  # Somalia
    "+27",   # Südafrika (Schwindel)
    "+234",  # Nigeria (Scammer-Nummern)
    "+237",  # Kamerun
    "+256",  # Uganda
    "+255",  # Tansania
    "+212",  # Marokko
    "+233",  # Ghana
    "+241",  # Gabun
    "+880",  # Bangladesch
    "+92",   # Pakistan
    "+88",   # Hongkong
    "+998",  # Usbekistan
    "+996",  # Kirgisistan
    "+7",    # Russland/Kasachstan
    "+375",  # Belarus
    "+370",  # Litauen
    "+373",  # Moldawien
    "+593",  # Ecuador
    "+691",  # Mikronesien
    "+850",  # Nordkorea
]

# 🚨 HOCHRISIKO-LÄNDER FÜR BETRUG
HIGH_RISK_COUNTRIES = {
    "+27": "Südafrika - Häufige Romance/Inheritance Scams",
    "+234": "Nigeria - Nigerian Prince Scams",
    "+237": "Kamerun - Betrügereien",
    "+256": "Uganda - Betrügereien",
    "+255": "Tansania - Betrügereien",
    "+92": "Pakistan - Sextortion & Erpressung",
    "+880": "Bangladesch - Call Center Betrug",
    "+86": "China - Tech Support Scams",
    "+7": "Russland - Cyberkriminalität",
}

# ⚠️ Auffällige Muster (Bot-Nummern, Scammer)
SUSPICIOUS_PATTERNS = [
    r"(\d)\1{5,}",        # Wiederholte Ziffern (111111, 222222)
    r"\b12345\b",         # Sequenzen
    r"\b0000\b",          # Nur Nullen
    r"\d{3}-\d{3}-\d{3}", # Typisches Testmuster
    r"^1-?\d{3}-?\d{3}-?\d{4}$",  # Fake US Numbers
    r"^0-?\d{3}-?\d{3}-?\d{4}$",  # Fake UK Numbers
    r"\b123\b",           # 123 Muster
    r"\b999\b",           # 999 Muster
]

# 🤖 BOT & AUTOMATION ZEICHEN
BOT_PATTERNS = [
    r"\+1-?800",          # Roboter-Anrufe
    r"\+1-?888",          # Toll-free Nummern (Betrug)
    r"\+1-?877",          # Toll-free
    r"\+1-?866",          # Toll-free
]

# 🔴 EXTREM GEFÄHRLICHE PRÄFIXE
EXTREME_RISK_PREFIXES = [
    "+99",                 # Ungültige Nummer
    "+234",                # Nigeria Prime Scammer Hub
    "+27",                 # Südafrika (Romance Scams)
    "+92",                 # Pakistan (Sextortion)
]


def scan_phone_number(phone_number: str):
    phone_number = phone_number.strip().lower()
    original_number = phone_number

    # 🔴 EXTREM RISIKO: EXTREME_RISK_PREFIXES
    for prefix in EXTREME_RISK_PREFIXES:
        if phone_number.startswith(prefix.lower()):
            return {
                "score": 5,
                "status": "EXTREM GEFÄHRLICH",
                "color": "#CC0000",
                "details": [
                    (
                        "Hochrisiko Landesprefix",
                        95,
                        f"Nummer aus {HIGH_RISK_COUNTRIES.get(prefix, 'bekanntem Schwindel-Land')}. NICHT annehmen!"
                    )
                ],
                "risk_level": "EXTREME"
            }

    # 🚫 ANONYM / UNBEKANNT → SOFORT GEFÄHRLICH
    if any(word in phone_number for word in ANONYMOUS_KEYWORDS):
        return {
            "score": 0,
            "status": "EXTREM GEFÄHRLICH",
            "color": "#CC0000",
            "details": [
                (
                    "Anonymer Anruf",
                    100,
                    "Anonyme oder versteckte Nummern werden sehr häufig für Betrug oder Belästigung genutzt. "
                    "Es wird dringend empfohlen, nicht ranzugehen."
                )
            ],
            "risk_level": "EXTREME"
        }

    # 🚨 BLACKLIST CHECK
    if phone_number in BLACKLISTED_PHONE_NUMBERS:
        return {
            "score": 0,
            "status": "EXTREM GEFÄHRLICH (BLACKLIST)",
            "color": "#CC0000",
            "details": [
                (
                    "Nummer auf Blacklist",
                    100,
                    "Diese Telefonnummer ist als betrügerisch bekannt und sollte blockiert werden."
                )
            ],
            "risk_level": "EXTREME"
        }

    score = 100
    details = []

    # 🤖 BOT-ANRUFE ERKENNEN
    for bot_pattern in BOT_PATTERNS:
        if re.search(bot_pattern, phone_number):
            score -= 30
            details.append((
                "Roboter-Anruf erkannt",
                30,
                "Diese Nummern werden häufig für automatisierte Betrügereien verwendet."
            ))
            break

    # 🌍 Hochrisiko-Länder
    for country_code, risk_desc in HIGH_RISK_COUNTRIES.items():
        if phone_number.startswith(country_code.lower()):
            score -= 35
            details.append((
                f"Hochrisiko-Land: {country_code}",
                35,
                risk_desc
            ))
            break

    # ⚠️ Andere verdächtige Länderpräfixe
    if any(phone_number.startswith(code.lower()) for code in SUSPICIOUS_COUNTRY_CODES):
        if not any(details):  # Falls noch nicht durch Hochrisiko gelabelt
            score -= 20
            details.append((
                "Verdächtige Ländervorwahl",
                20,
                "Anrufe aus bestimmten Ländern werden sehr oft für Betrug genutzt."
            ))

    # 🔁 Verdächtige Muster (Bot-Signatur)
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, phone_number):
            score -= 25
            details.append((
                "Auffälliges Zahlenmuster",
                25,
                "Die Nummer sieht automatisch/zufällig erzeugt aus - typisch für Spam."
            ))
            break

    # 📏 Länge prüfen
    if len(phone_number) < 7:
        score -= 15
        details.append((
            "Nummer zu kurz",
            15,
            "Echte Telefonnummern haben normalerweise mindestens 7 Ziffern."
        ))
    elif len(phone_number) > 20:
        score -= 15
        details.append((
            "Nummer zu lang",
            15,
            "Telefonnummern sind normalerweise nicht länger als 15 Ziffern."
        ))

    # ❌ Ungültige Zeichen
    if re.search(r"[^\d+ \-()x#*]", phone_number):
        score -= 10
        details.append((
            "Ungültige Zeichen",
            10,
            "Telefonnummern sollten nur aus Zahlen und Sonderzeichen bestehen."
        ))

    # 🔍 WEITERE ROTE FLAGGEN
    # Toll-free Nummern (viele Scams)
    if re.search(r"1-?800|1-?888|1-?877|1-?866", phone_number):
        score -= 20
        details.append((
            "Toll-free Nummer",
            20,
            "Kostenlose Servicenummern werden oft für Betrügereien missbraucht."
        ))

    # VoIP-Nummern (beliebte Scammer-Tools)
    if re.search(r"\+1-?5[0-9]{2}-?[0-9]{3}-?[0-9]{4}", phone_number):
        score -= 18
        details.append((
            "VoIP-Muster erkannt",
            18,
            "VoIP-Nummern werden häufig von Betrügern für Vertuschung verwendet."
        ))

    # Massenversand Indikatoren
    if phone_number.count('0') >= len(phone_number) * 0.4:
        score -= 8
        details.append((
            "Ungewöhnlich viele Nullen",
            8,
            "Könnte auf massengenerierten Spam hindeuten."
        ))

    score = max(score, 0)

    # 🧠 Status Bestimmung
    if score <= 10:
        status = "🔴 EXTREM GEFÄHRLICH"
        color = "#CC0000"
        risk_level = "EXTREME"
    elif score <= 30:
        status = "🔴 SEHR UNSICHER"
        color = "#FF0000"
        risk_level = "HIGH"
    elif score <= 50:
        status = "🟠 UNSICHER"
        color = "#FF6600"
        risk_level = "MEDIUM"
    elif score <= 70:
        status = "🟡 POTENTIELL GEFÄHRLICH"
        color = "#FFAA00"
        risk_level = "LOW"
    else:
        status = "🟢 SICHER"
        color = "#00CC00"
        risk_level = "SAFE"

    return {
        "score": score,
        "status": status,
        "color": color,
        "details": details,
        "risk_level": risk_level
    }
