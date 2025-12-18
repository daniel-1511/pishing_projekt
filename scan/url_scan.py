def scan_url(url):
    score = 100
    details = []

    # --- DEIN CODE (unverändert) ---
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

    # --- NEU: WEBSITE ANALYSE ---
    website = CyberNet(url)

    if not website["reachable"]:
        score -= 40
        details.append(("Website nicht erreichbar", 40, "Server antwortet nicht"))

    for err in website["errors"]:
        score -= 5
        details.append(("Website-Fehler", 5, err))

    for warn in website["warnings"]:
        details.append(("Website-Warnung", 0, warn))

    # --- HTML VALIDIERUNG ---
    html_errors = validate_html(url)
    for err in html_errors:
        score -= 3
        details.append(("HTML-Fehler", 3, err))

    score = max(score, 0)

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
