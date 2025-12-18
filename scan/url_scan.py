import re
import requests
import traceback
from bs4 import BeautifulSoup

# -----------------------------
# 🔍 Verdächtige Wörter in URL
# -----------------------------
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "bank",
    "account", "update", "free", "bonus",
    "confirm", "password"
]

# 🔞 NSFW / Erwachsene
NSFW_KEYWORDS = ["porn", "xxx", "sex", "adult", "nude", "camgirl", "escort"]

# 🎰 Casino / Glücksspiel
CASINO_KEYWORDS = ["casino", "bet", "poker", "slot", "jackpot", "gambling", "roulette"]

# -----------------------------
# 🌐 HTTP STATUS TRANSLATION
# -----------------------------
HTTP_STATUS_MAP = {
    200: "OK – Seite erfolgreich geladen.",
    201: "Created – Ressource wurde erstellt.",
    204: "No Content – Keine Daten zurückgegeben.",
    301: "Moved Permanently – Seite dauerhaft verschoben.",
    302: "Found – Temporäre Weiterleitung.",
    304: "Not Modified – Seite wurde seit letztem Besuch nicht geändert.",
    400: "Bad Request – Anfrage fehlerhaft.",
    401: "Unauthorized – Zugriff verweigert, Anmeldung erforderlich.",
    403: "Forbidden – Zugriff verboten.",
    404: "Not Found – Seite existiert nicht, URL prüfen.",
    408: "Request Timeout – Server hat zu lange gebraucht.",
    500: "Internal Server Error – Serverfehler, Seite kann nicht angezeigt werden.",
    502: "Bad Gateway – Serverfehler oder Proxy-Problem.",
    503: "Service Unavailable – Seite momentan nicht verfügbar.",
    504: "Gateway Timeout – Server reagiert nicht rechtzeitig.",
}

def http_status_text(code):
    return HTTP_STATUS_MAP.get(code, f"Unbekannter Status ({code})")

# -----------------------------
# 🌐 Website Analyse
# -----------------------------
def analyze_website(url, debug=False):
    results = {
        "reachable": True,
        "http_status": None,
        "errors": [],
        "warnings": [],
        "nsfw": False,
        "casino": False,
        "exceptions": []
    }

    try:
        response = requests.get(url, timeout=10)
        results["http_status"] = http_status_text(response.status_code)

        if response.status_code >= 400:
            results["reachable"] = False
            results["errors"].append(f"HTTP-Fehler: {http_status_text(response.status_code)}")
            return results

        html = response.text.lower()
        soup = BeautifulSoup(html, "html.parser")

        # ❌ Fehlender <title>
        if not soup.title or not soup.title.text.strip():
            results["errors"].append("Fehler: Kein <title>-Tag vorhanden. Jede Seite sollte einen Titel haben, sonst weiß der Besucher nicht, worum es geht.")

        # ⚠️ Fehlende Meta Description
        if not soup.find("meta", attrs={"name": "description"}):
            results["warnings"].append("Warnung: Meta Description fehlt. Suchmaschinen und Nutzer erhalten keine kurze Seitenbeschreibung.")

        # ⚠️ Mehrere H1-Tags
        h1_tags = soup.find_all("h1")
        if len(h1_tags) > 1:
            results["warnings"].append("Warnung: Mehrere <h1>-Tags gefunden. Normalerweise sollte jede Seite nur ein <h1> haben für bessere SEO.")

        # ⚠️ Inline-JavaScript
        if soup.find_all("script", src=False):
            results["warnings"].append("Warnung: Inline-JavaScript gefunden. Das kann die Ladegeschwindigkeit reduzieren und Sicherheitsrisiken erhöhen.")

        # ❌ Mixed Content
        if url.startswith("https://"):
            for img in soup.find_all("img", src=True):
                if img["src"].startswith("http://"):
                    results["errors"].append("Fehler: Mixed Content gefunden (HTTP-Bilder auf HTTPS-Seite). Das kann die Sicherheit gefährden.")

        # 🔞 NSFW erkennen
        if any(word in html for word in NSFW_KEYWORDS):
            results["nsfw"] = True
            results["warnings"].append("Warnung: NSFW / Inhalte für Erwachsene erkannt. Keine Sicherheitswarnung, nur Info.")

        # 🎰 Casino erkennen
        if any(word in html for word in CASINO_KEYWORDS):
            results["casino"] = True
            results["warnings"].append("Warnung: Casino- oder Glücksspiel-Inhalte erkannt. Keine Sicherheitswarnung, nur Info.")

    except requests.exceptions.RequestException as e:
        results["reachable"] = False
        results["errors"].append(f"Seite nicht erreichbar: {str(e)}")

    except Exception as e:
        results["reachable"] = False
        results["errors"].append(f"Analysefehler: {str(e)}")
        if debug:
            results["exceptions"].append({
                "type": type(e).__name__,
                "message": str(e),
                "traceback": traceback.format_exc()
            })

    return results

# -----------------------------
# 🔐 URL-Scan + Score
# -----------------------------
def scan_url(url: str, debug=False):
    score = 100
    details = []
    easy_explanation = []

    # 🔐 HTTPS
    if not url.startswith("https://"):
        score -= 25
        details.append(("Keine sichere Verbindung", 25, "Die Seite nutzt kein HTTPS, daher werden Daten unverschlüsselt übertragen."))
        easy_explanation.append("Die Seite ist nicht sicher verschlüsselt.")

    # 🌐 IP-Adresse statt Domain
    if re.search(r"(http://|https://)?(\d{1,3}\.){3}\d{1,3}", url):
        score -= 30
        details.append(("IP-Adresse verwendet", 30, "Seriöse Seiten nutzen normalerweise einen Domainnamen, nicht nur Zahlen."))
        easy_explanation.append("Die Adresse enthält nur Zahlen statt eines Namens.")

    # ⚠️ Verdächtige Wörter in URL
    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if found:
        deduction = len(found) * 5
        score -= deduction
        details.append(("Verdächtige Begriffe", deduction, f"Die URL enthält typische Betrugsbegriffe: {', '.join(found)}"))
        easy_explanation.append("Die URL enthält Wörter, die oft bei Betrugsseiten vorkommen.")

    # 🌐 Website analysieren
    website = analyze_website(url, debug=debug)

    # ❌ Nicht erreichbar
    if not website["reachable"]:
        score -= 40
        details.append(("Website nicht erreichbar", 40, "Die Seite antwortet nicht oder es gab einen technischen Fehler."))
        easy_explanation.append("Die Seite ist nicht erreichbar.")

    # ❌ Analysefehler
    if website["errors"]:
        penalty = min(len(website["errors"]) * 10, 40)
        score -= penalty
        details.append(("Technische Fehler", penalty, "Fehler bei der Analyse: " + "; ".join(website["errors"])))

    # 🔞 NSFW (nur Info)
    if website["nsfw"]:
        details.append(("NSFW-Inhalte", 0, "Die Seite enthält Inhalte für Erwachsene. Keine technische Sicherheitswarnung."))

    # 🎰 Casino (nur Info)
    if website["casino"]:
        details.append(("Glücksspiel", 0, "Die Seite enthält Casino- oder Glücksspiel-Inhalte."))

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
        "url": url,
        "score": score,
        "status": status,
        "color": color,
        "easy_explanation": list(set(easy_explanation)),
        "details": details,
        "website_analysis": website
    }

# -----------------------------
# 🧪 Test
# -----------------------------
if __name__ == "__main__":
    from pprint import pprint

    test_url = "https://example.com"
    pprint(scan_url(test_url, debug=True))
