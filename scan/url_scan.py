import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# 🔍 Typische Betrugsbegriffe
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "bank",
    "account", "update", "free", "bonus",
    "confirm", "password"
]

# 🔞 NSFW / Erwachsenen-Inhalte
NSFW_KEYWORDS = [
    "porn", "xxx", "sex", "adult", "nude",
    "camgirl", "escort"
]

# 🎰 Glücksspiel / Casino
CASINO_KEYWORDS = [
    "casino", "bet", "poker", "slot",
    "jackpot", "gambling", "roulette"
]


# --------------------------------------------------
# 🌐 Website-Analyse
# --------------------------------------------------
def analyze_website(url):
    results = {
        "reachable": True,
        "http_status": None,
        "errors": [],
        "warnings": [],
        "nsfw": False,
        "casino": False
    }

    try:
        response = requests.get(url, timeout=10)
        results["http_status"] = response.status_code

        if response.status_code >= 400:
            results["reachable"] = False
            results["errors"].append(
                f"Die Website antwortet nicht korrekt (Status {response.status_code})."
            )
            return results

        html = response.text.lower()
        soup = BeautifulSoup(html, "html.parser")

        # 🔞 NSFW erkennen
        if any(word in html for word in NSFW_KEYWORDS):
            results["nsfw"] = True
            results["warnings"].append("NSFW / Inhalte für Erwachsene gefunden")

        # 🎰 Casino erkennen
        if any(word in html for word in CASINO_KEYWORDS):
            results["casino"] = True
            results["warnings"].append("Casino / Glücksspiel-Inhalte gefunden")

        # ❌ Kein Titel
        if not soup.title or not soup.title.text.strip():
            results["errors"].append(
                "Die Seite hat keinen Titel."
            )

        # ⚠️ Keine Beschreibung
        if not soup.find("meta", attrs={"name": "description"}):
            results["warnings"].append(
                "Die Seite hat keine Beschreibung."
            )

    except Exception as e:
        results["reachable"] = False
        results["errors"].append(
            f"Website nicht erreichbar: {str(e)}"
        )

    return results


# --------------------------------------------------
# 🔐 Haupt-URL-Scan
# --------------------------------------------------
def scan_url(url: str):
    score = 100
    details = []
    easy_explanation = []

    # 🔐 HTTPS
    if not url.startswith("https://"):
        score -= 25
        details.append((
            "Keine sichere Verbindung",
            25,
            "Die Verbindung ist nicht verschlüsselt."
        ))
        easy_explanation.append(
            "Die Seite ist nicht sicher verschlüsselt."
        )

    # 🌐 IP statt Domain
    if re.search(r"(http://|https://)?(\d{1,3}\.){3}\d{1,3}", url):
        score -= 30
        details.append((
            "Ungewöhnliche Adresse",
            30,
            "Die Seite nutzt Zahlen statt eines Namens."
        ))
        easy_explanation.append(
            "Seriöse Seiten haben normalerweise einen Namen."
        )

    # ⚠️ Verdächtige Begriffe
    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if found:
        deduction = len(found) * 5
        score -= deduction
        details.append((
            "Verdächtige Begriffe",
            deduction,
            f"Gefunden: {', '.join(found)}"
        ))
        easy_explanation.append(
            "Die Adresse enthält Wörter, die oft bei Betrug vorkommen."
        )

    # 🌐 Website prüfen
    website = analyze_website(url)

    if not website["reachable"]:
        score -= 40
        details.append((
            "Website nicht erreichbar",
            40,
            "Die Seite antwortet nicht."
        ))
        easy_explanation.append(
            "Die Seite ist nicht erreichbar."
        )

    # 🔞 NSFW → NUR Details (Score nicht abziehen)
    if website["nsfw"]:
        details.append((
            "NSFW / Erwachsene Inhalte",
            0,
            "Die Seite enthält pornographische Inhalte. Keine technische Sicherheitswarnung."
        ))

    # 🎰 Casino → NUR Details (Score nicht abziehen)
    if website["casino"]:
        details.append((
            "Casino / Glücksspiel-Inhalte",
            0,
            "Die Seite enthält Glücksspiel- oder Casino-Inhalte."
        ))

    score = max(score, 0)

    # 🧠 Status
    if score <= 10:
        status, color = "Extrem gefährlich", "red"
    elif score <= 30:
        status, color = "Unsicher", "orange"
    elif score <= 60:
        status, color = "Potentiell gefährlich", "yellow"
    else:
        status, color = "Sicher", "green"

    return {
        "score": score,
        "status": status,
        "color": color,
        "easy_explanation": list(set(easy_explanation)),
        "details": details,
        "website_analysis": website
    }


# --------------------------------------------------
# 🧪 Test
# --------------------------------------------------
if __name__ == "__main__":
    from pprint import pprint
    pprint(scan_url("https://example.com"))
