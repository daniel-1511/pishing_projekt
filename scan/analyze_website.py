import requests
from bs4 import BeautifulSoup

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
            results["errors"].append(
                f"HTTP-Fehler {response.status_code}"
            )
            results["reachable"] = False
            return results

        html = response.text
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

    except requests.exceptions.RequestException as e:
        results["reachable"] = False
        results["errors"].append(f"Seite nicht erreichbar: {str(e)}")

    return results
