import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# --- Verdächtige Wörter ---
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "bank",
    "account", "update", "free", "bonus",
    "confirm", "password"
]


# --- Website Analyse ---
def analyze_website(url):
    results = {
        "reachable": True,
        "http_status": None,
        "errors": [],
        "warnings": []
    }

    try:
        response = requests.get(url, timeout=10)
        results["http_status"] = response.status_code

        if response.status_code >= 400:
            results["errors"].append(f"HTTP-Fehler {response.status_code}")
            results["reachable"] = False
            return results

        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # Fehlender <title>
        if not soup.title or not soup.title.text.strip():
            results["errors"].append("Kein <title>-Tag vorhanden")

        # Fehlende Meta Description
        if not soup.find("meta", attrs={"name": "description"}):
            results["warnings"].append("Meta Description fehlt")

        # Mehrere H1-Tags
        if len(soup.find_all("h1")) > 1:
            results["warnings"].append("Mehrere <h1>-Tags gefunden")

        # Inline-JavaScript
        if soup.find_all("script", src=False):
            results["warnings"].append("Inline-JavaScript gefunden")

        # Mixed Content (HTTP Ressourcen auf HTTPS)
        if url.startswith("https://"):
            for img in soup.find_all("img", src=True):
                if img["src"].startswith("http://"):
                    results["errors"].append("Mixed Content (HTTP-Ressourcen)")

    except requests.exceptions.RequestException as e:
        results["reachable"] = False
        results["errors"].append(f"Seite nicht erreichbar: {str(e)}")

    return results


# --- HTML Validator (W3C) ---
def validate_html(url):
    errors = []

    try:
        api_url = "https://validator.w3.org/nu/"
        params = {"doc": url, "out": "json"}
        response = requests.get(api_url, params=params, timeout=10)
        data = response.json()

        for msg in data.get("messages", []):
            if msg.get("type") == "error":
                line = msg.get("lastLine", "?")
                message = msg.get("message", "Unbekannter HTML-Fehler")
                errors.append(f"Zeile {line}: {message}")

    except Exception as e:
        errors.append(f"HTML-Validierung fehlgeschlagen: {str(e)}")

    return errors


# --- Hauptfunktion: URL-Scan ---
def scan_url(url):
    score = 100
    details = []

    # --- URL Sicherheitschecks ---
    if not url.startswith("https://"):
        score -= 25
        details.append(("HTTPS fehlt", 25, "Daten können abgefangen werden"))

    if re.search(r"(http://|https://)?(\d{1,3}\.){3}\d{1,3}", url):
        score -= 30
        details.append(("IP-Adresse", 30, "IP-URLs werden oft für Phishing genutzt"))

    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if found:
        deduction = len(found) * 5
        score -= deduction
        details.append(("Verdächtige Wörter", deduction, f"Gefunden: {', '.join(found)}"))

    if len(url) > 75:
        score -= 10
        details.append(("Lange URL", 10, "Lange URLs können täuschen"))

    symbols = sum(url.count(s) for s in ["@", "-", "_"])
    if symbols:
        deduction = symbols * 3
        score -= deduction
        details.append(("Sonderzeichen", deduction, "Ungewöhnliche URL-Struktur"))

    if len(urlparse(url).netloc.split(".")) > 3:
        score -= 15
        details.append(("Viele Subdomains", 15, "Imitiert oft echte Webseiten"))

    # --- Website Analyse ---
    website = analyze_website(url)

    if not website["reachable"]:
        score -= 40
        details.append(("Website nicht erreichbar", 40, "Server antwortet nicht"))

    for err in website["errors"]:
        score -= 5
        details.append(("Website-Fehler", 5, err))

    for warn in website["warnings"]:
        details.append(("Website-Warnung", 0, warn))

    # --- HTML Validator ---
    html_errors = validate_html(url)
    for err in html_errors:
        score -= 3
        details.append(("HTML-Fehler", 3, err))

    score = max(score, 0)

    # --- Status / Score Balken ---
    if score <= 10:
        status, color, width = "Extrem gefährlich", "red", "5%"
    elif score <= 30:
        status, color, width = "Unsicher", "orange", "25%"
    elif score <= 60:
        status, color, width = "Relativ sicher", "yellow", "50%"
    else:
        status, color, width = "Sicher", "green", "80%"

    return {
        "score": score,
        "status": status,
        "color": color,
        "width": width,
        "details": details,
        "website_analysis": website,
        "html_errors": html_errors
    }


# --- Direkt testen ---
if __name__ == "__main__":
    url = "https://example.com"
    result = scan_url(url)
    from pprint import pprint
    pprint(result)
