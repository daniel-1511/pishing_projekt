import re
import requests
import traceback
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ollama

# 🔍 Verdächtige Wörter in URL
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "bank",
    "account", "update", "free", "bonus",
    "confirm", "password"
]

# 🔞 NSFW / Erwachsene
NSFW_KEYWORDS = ["porn", "xxx", "sex", "adult", "nude", "camgirl", "escort"]

# 🎰 Casino / Glücksspiel
CASINO_KEYWORDS = ["casino", "bet", "poker", "slot", "jackpot", "gambling", "roulette"]

# 🎣 Phishing-Domains (Ziele von Betrügern)
PHISHING_DOMAINS = [
    "amazon", "apple", "google", "facebook", "microsoft", 
    "paypal", "netflix", "instagram", "whatsapp", "telegram",
    "twitter", "steam", "discord", "ebay", "dropbox"
]

# 🔗 URL-Verkürzer
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "short.link",
    "ow.ly", "t.co", "buff.ly", "adf.ly", "rebrand.ly",
    "s.click", "tiny.cc", "short.cm", "x.co"
]

# 🔍 Verdächtige Wörter (erweitert)
SUSPICIOUS_WORDS_EXTENDED = [
    "login", "verify", "account", "confirm", "signin", "auth",
    "pay", "billing", "alert", "urgent", "action-required",
    "update", "password", "secure", "bank", "free", "bonus",
    "validate", "confirm-identity", "security-check", "click-here",
    "limited-time", "act-now", "claim", "prize", "winner"
]

# Updatersuspicious_words mit erweiterten Begriffen
SUSPICIOUS_WORDS = SUSPICIOUS_WORDS_EXTENDED


# 🌐 HTTP STATUS TRANSLATION
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

# 🤖 KI-Erklärung und Score generieren mit Ollama
def generate_ai_explanation(url, score, status, details):
    prompt = f"""Du bist ein Website-Sicherheits-Profi. Erkläre diese URL wie zu einem Freund - EINFACH und VERSTÄNDLICH!

URL: {url}
Probleme gefunden: {', '.join([d[0] for d in details]) if details else 'Keine Probleme'}

ANTWORTE GENAU IN DIESEM FORMAT (strukturiert und übersichtlich):

KURZ (3 Stichpunkte):
• Punkt 1: (kurz und knapp)
• Punkt 2: (kurz und knapp)
• Punkt 3: (kurz und knapp)

DETAILS:

🔴 WARNSIGNALE:
- Signal 1
- Signal 2
- Signal 3

💡 ERKLÄRUNG:
(2-3 Sätze, was das Problem ist, in einfachen Worten)

📌 ECHTE BEISPIELE:
(Gib ein oder zwei echte Beispiele, wann dieser Trick verwendet wurde)

✅ WAS SOLL ICH TUN:
- Tipp 1
- Tipp 2
- Tipp 3

---

WICHTIG:
- Nutze KEINE Fachbegriffe
- Schreib kurz und deutlich
- Nummeriere und strukturiere alles
- Verwende Emojis und Bindestriche für Übersichtlichkeit"""
    
    try:
        response = ollama.chat(model='llama3.2', messages=[{'role': 'user', 'content': prompt}])
        explanation = response['message']['content'].strip()
        return score, explanation
    except Exception as e:
        return score, f"KI-Analyse nicht verfügbar: {str(e)}"

# 🌐 Website Analyse
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
        results["errors"].append(f"Seite nicht erreichbar")

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

    # � URL-Validierung
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            ai_score, ai_explanation = 0, "Diese URL ist ungültig und kann nicht analysiert werden. Stellen Sie sicher, dass sie mit http:// oder https:// beginnt und eine gültige Domain hat."
            return {
                "url": url,
                "score": ai_score,
                "status": "UNGÜLTIGE URL",
                "color": "red",
                "easy_explanation": ["Ungültige URL-Struktur"],
                "details": [("Ungültige URL", 100, "Die URL hat keine gültige Struktur (fehlendes Schema oder Domain).")],
                "website_analysis": {"reachable": False, "errors": ["Ungültige URL"]},
                "ai_explanation": ai_explanation
            }
    except Exception as e:
        ai_score, ai_explanation = 0, f"Fehler beim Verarbeiten der URL: {str(e)}. Überprüfen Sie die URL-Syntax."
        return {
            "url": url,
            "score": ai_score,
            "status": "UNGÜLTIGE URL",
            "color": "red",
            "easy_explanation": ["URL-Parsing-Fehler"],
            "details": [("URL-Fehler", 100, f"Fehler beim Parsen der URL: {str(e)}")],
            "website_analysis": {"reachable": False, "errors": ["URL-Fehler"]},
            "ai_explanation": ai_explanation
        }

    # �🔐 HTTPS (Critical)
    if not url.startswith("https://"):
        score -= 35
        details.append(("Keine sichere Verbindung (HTTP)", 35, "KRITISCH: Die Seite nutzt kein HTTPS. Daten werden unverschlüsselt übertragen - ideal für Diebe!"))
        easy_explanation.append("⚠️ KRITISCH: Keine sichere Verbindung!")

    # 🌐 IP-Adresse statt Domain (Critical)
    if re.search(r"(http://|https://)?(\d{1,3}\.){3}\d{1,3}", url):
        score -= 50
        details.append(("IP-Adresse statt Domain", 50, "EXTREM VERDÄCHTIG: Seriöse Seiten nutzen niemals nur Zahlen-Adressen!"))
        easy_explanation.append("⚠️ EXTREM VERDÄCHTIG: Nur Zahlen statt Domain!")

    # ⚠️ URL-Verkürzer erkannt
    if any(shortener in url.lower() for shortener in URL_SHORTENERS):
        score -= 40
        details.append(("URL-Verkürzer verwendet", 40, "Phishing-Methode: Die echte Adresse ist versteckt. Vorsicht!"))
        easy_explanation.append("⚠️ URL-Verkürzer erkannt - versteckte Zielseite!")

    # 🎣 Domain-Typosquatting
    for phishing_domain in PHISHING_DOMAINS:
        if phishing_domain in url.lower():
            # Check for variations
            if "amaozn" in url.lower() or "amazoon" in url.lower() or "amaz0n" in url.lower():
                score -= 45
                details.append(("Domain-Typosquatting (Amazon)", 45, "Betrüger verwenden ähnliche Namen wie echte Seiten!"))
                easy_explanation.append("⚠️ Verdächtige Amazon-Kopie erkannt!")
            elif "appl3" in url.lower() or "appie" in url.lower() or "aple" in url.lower():
                score -= 45
                details.append(("Domain-Typosquatting (Apple)", 45, "Betrüger verwenden ähnliche Namen wie echte Seiten!"))
                easy_explanation.append("⚠️ Verdächtige Apple-Kopie erkannt!")
            elif "micr0soft" in url.lower() or "microsfot" in url.lower():
                score -= 45
                details.append(("Domain-Typosquatting (Microsoft)", 45, "Betrüger verwenden ähnliche Namen wie echte Seiten!"))
                easy_explanation.append("⚠️ Verdächtige Microsoft-Kopie erkannt!")

    # ⚠️ Verdächtige Wörter in URL (erhöht)
    found = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    if found:
        deduction = len(found) * 8  # Erhöht von 5 zu 8
        score -= deduction
        details.append(("Verdächtige Begriffe in URL", deduction, f"Typische Phishing-Wörter: {', '.join(found)}"))
        easy_explanation.append(f"⚠️ Verdächtige Wörter: {', '.join(found[:2])}")

    # 🌐 Website analysieren
    website = analyze_website(url, debug=debug)

    # ❌ Nicht erreichbar
    if not website["reachable"]:
        score -= 35
        details.append(("Website nicht erreichbar", 35, "Seite antwortet nicht - könnte eine gefälschte Seite sein."))
        easy_explanation.append("⚠️ Seite nicht erreichbar!")

    # ❌ Analysefehler
    if website["errors"]:
        penalty = min(len(website["errors"]) * 12, 50)
        score -= penalty
        details.append(("Technische Fehler", penalty, "Mehrere Fehler gefunden: " + "; ".join(website["errors"])))

    # 🔞 NSFW (nur Info, kein Punktabzug)
    if website["nsfw"]:
        details.append(("Erwachsenen-Inhalte", 0, "NSFW-Inhalte erkannt - keine Sicherheitswarnung, nur Info."))

    # 🎰 Casino (nur Info, kein Punktabzug)
    if website["casino"]:
        details.append(("Casino/Glücksspiel", 0, "Glücksspiel-Inhalte erkannt - keine Sicherheitswarnung, nur Info."))

    # ⚠️ Zu lange URL (common obfuscation)
    if len(url) > 100:
        score -= 10
        details.append(("Verdächtig lange URL", 10, "Betrüger verstecken echte Adressen in langen URLs."))

    # ⚠️ Zu viele Subdomains
    subdomain_count = url.count(".")
    if subdomain_count > 4:
        score -= 15
        details.append(("Zu viele Subdomains", 15, "Betrüger nutzen komplexe Subdomains zur Verschleierung."))

    score = max(score, 0)

    # Initialer Status für KI-Prompt
    status = "Unbekannt"

    # 🤖 KI-Erklärung und Score generieren
    ai_score, ai_explanation = generate_ai_explanation(url, score, status, details)

    # 🧠 Status basierend auf KI-Score
    if ai_score <= 15:
        status, color = "EXTREM GEFÄHRLICH ⚠️", "red"
    elif ai_score <= 35:
        status, color = "SEHR GEFÄHRLICH", "orange"
    elif ai_score <= 55:
        status, color = "VERDÄCHTIG", "yellow"
    elif ai_score <= 75:
        status, color = "Eher sicher", "lightgreen"
    else:
        status, color = "Sicher", "green"

    return {
        "url": url,
        "score": ai_score,
        "status": status,
        "color": color,
        "easy_explanation": list(set(easy_explanation)),
        "details": details,
        "website_analysis": website,
        "ai_explanation": ai_explanation
    }

# -----------------------------
# 🧪 Test
# -----------------------------
if __name__ == "__main__":
    from pprint import pprint

    test_url = "https://example.com"
    pprint(scan_url(test_url, debug=True))