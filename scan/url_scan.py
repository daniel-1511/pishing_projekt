import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Wörter, die oft bei Betrugsseiten vorkommen
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "bank",
    "account", "update", "free", "bonus",
    "confirm", "password"
]


# =================================================
# 1️⃣ URL selbst prüfen (Adresse)
# =================================================
def scan_url_structure(url: str):
    score = 100
    explanations = []          # einfache Erklärungen
    technical_details = []     # technische Infos

    if not url.startswith("https://"):
        score -= 25
        explanations.append(
            "Die Internetadresse ist nicht geschützt. Fremde könnten Daten mitlesen."
        )
        technical_details.append(("HTTPS fehlt", "Keine verschlüsselte Verbindung"))

    if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
        score -= 30
        explanations.append(
            "Die Adresse besteht nur aus Zahlen. Das wird oft bei Fake‑Seiten benutzt."
        )
        technical_details.append(("IP‑Adresse", "Keine normale Domain"))

    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if found:
        score -= len(found) * 5
        explanations.append(
            "Die Adresse enthält Wörter, die häufig bei Betrug verwendet werden."
        )
        technical_details.append(("Verdächtige Wörter", ", ".join(found)))

    if len(url) > 75:
        score -= 10
        explanations.append(
            "Die Adresse ist sehr lang und könnte absichtlich verwirrend sein."
        )
        technical_details.append(("Lange URL", f"{len(url)} Zeichen"))

    if len(urlparse(url).netloc.split(".")) > 3:
        score -= 15
        explanations.append(
            "Die Adresse hat viele Unterbereiche. Das wird oft genutzt, um echte Seiten zu imitieren."
        )
        technical_details.append(("Viele Subdomains", urlparse(url).netloc))

    if not explanations:
        explanations.append(
            "Die Internetadresse wirkt normal und unauffällig."
        )

    return max(score, 0), explanations, technical_details


# =================================================
# 2️⃣ Website & Code Analyse
# =================================================
def analyze_website(url: str):
    score = 100
    errors = []
    warnings = []

    try:
        response = requests.get(url, timeout=10)

        if response.status_code >= 400:
            score -= 40
            errors.append(
                "Die Website antwortet mit einem Fehler und ist möglicherweise nicht vertrauenswürdig."
            )
            return max(score, 0), errors, warnings

        soup = BeautifulSoup(response.text, "html.parser")

        if not soup.title or not soup.title.text.strip():
            score -= 10
            errors.append(
                "Die Seite hat keinen Titel. Seriöse Seiten haben fast immer einen."
            )

        if not soup.find("meta", attrs={"name": "description"}):
            score -= 5
            warnings.append(
                "Die Seite hat keine kurze Beschreibung. Das ist unüblich."
            )

        if len(soup.find_all("h1")) > 1:
            score -= 5
            warnings.append(
                "Die Seite hat mehrere Hauptüberschriften, was untypisch ist."
            )

        if url.startswith("https://"):
            for img in soup.find_all("img", src=True):
                if img["src"].startswith("http://"):
                    score -= 10
                    errors.append(
                        "Die Seite lädt unsichere Inhalte, obwohl sie eigentlich geschützt sein sollte."
                    )
                    break

    except Exception:
        score -= 50
        errors.append(
            "Die Website konnte nicht erreicht werden."
        )

    return max(score, 0), errors, warnings


# =================================================
# 3️⃣ Gesamtauswertung
# =================================================
def scan_url(url: str):
    url_score, explanations, technical = scan_url_structure(url)
    analysis_score, analysis_errors, analysis_warnings = analyze_website(url)

    def rating(score):
        if score <= 30:
            return "Gefährlich", "red"
        elif score <= 60:
            return "Auffällig", "orange"
        else:
            return "Unauffällig", "green"

    url_status, url_color = rating(url_score)
    analysis_status, analysis_color = rating(analysis_score)

    return {
        # URL-Score
        "url_score": url_score,
        "url_status": url_status,
        "url_color": url_color,
        "summary": explanations,            # leicht verständlich für Laien
        "technical_details": technical,      # Details für Interessierte

        # Website / Code Analyse
        "analysis_score": analysis_score,
        "analysis_status": analysis_status,
        "analysis_color": analysis_color,
        "analysis_errors": analysis_errors,
        "analysis_warnings": analysis_warnings
    }


# =================================================
# Direkt testen
# =================================================
if __name__ == "__main__":
    test_url = "https://example.com"
    result = scan_url(test_url)
    from pprint import pprint
    pprint(result)
