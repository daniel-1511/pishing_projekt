import requests
from bs4 import BeautifulSoup
import traceback

# 🔞 NSFW / Erwachsenen-Inhalte
NSFW_KEYWORDS = ["porn", "xxx", "sex", "adult", "nude", "camgirl", "escort"]

# 🎰 Glücksspiel / Casino
CASINO_KEYWORDS = ["casino", "bet", "poker", "slot", "jackpot", "gambling", "roulette"]

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
        results["http_status"] = response.status_code

        if response.status_code >= 400:
            results["errors"].append(f"HTTP-Fehler {response.status_code}")
            results["reachable"] = False
            return results

        html = response.text.lower()
        soup = BeautifulSoup(html, "html.parser")

        # ❌ Fehlender <title>
        if not soup.title or not soup.title.text.strip():
            results["errors"].append("Kein <title>-Tag vorhanden")

        # ⚠️ Fehlende Meta Description
        if not soup.find("meta", attrs={"name": "description"}):
            results["warnings"].append("Meta Description fehlt")

        # ❌ Mehrere H1-Tags
        if len(soup.find_all("h1")) > 1:
            results["warnings"].append("Mehrere <h1>-Tags gefunden")

        # ❌ Inline-JavaScript
        if soup.find_all("script", src=False):
            results["warnings"].append("Inline-JavaScript gefunden")

        # ❌ Mixed Content
        if url.startswith("https://"):
            for img in soup.find_all("img", src=True):
                if img["src"].startswith("http://"):
                    results["errors"].append("Mixed Content (HTTP-Ressourcen)")

        # 🔞 NSFW erkennen
        if any(word in html for word in NSFW_KEYWORDS):
            results["nsfw"] = True
            results["warnings"].append("NSFW / Inhalte für Erwachsene gefunden")

        # 🎰 Casino erkennen
        if any(word in html for word in CASINO_KEYWORDS):
            results["casino"] = True
            results["warnings"].append("Casino / Glücksspiel-Inhalte gefunden")

    except requests.exceptions.RequestException as e:
        results["reachable"] = False
        results["errors"].append(f"Seite nicht erreichbar: {str(e)}")

    except Exception as e:
        results["reachable"] = False
        results["errors"].append(f"Analyse fehlgeschlagen: {str(e)}")
        if debug:
            results["exceptions"].append({
                "type": type(e).__name__,
                "message": str(e),
                "traceback": traceback.format_exc()
            })

    return results