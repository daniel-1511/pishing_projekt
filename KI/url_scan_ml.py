import os
import re
from urllib.parse import urlparse
import joblib

MODEL_PATH = "model.pkl"

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "bank",
    "account", "update", "free", "bonus",
    "confirm", "password", "signin", "click"
]

def has_https(url):
    return 1 if url.startswith("https://") else 0

def has_ip(url):
    ip_pattern = r"(http://|https://)?(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(ip_pattern, url) else 0

def suspicious_word_count(url):
    lu = url.lower()
    return sum(1 for w in SUSPICIOUS_WORDS if w in lu)

def url_length(url):
    return len(url)

def count_special_chars(url):
    return url.count("@"), url.count("-"), url.count("_"), url.count("%")

def subdomain_depth(url):
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]
    parts = [p for p in host.split(".") if p]
    return max(len(parts) - 2, 0)

def path_depth(url):
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return 0
    return len([p for p in path.split("/") if p])

def extract_feature_dict(url):
    f = {}
    f["has_https"] = has_https(url)
    f["has_ip"] = has_ip(url)
    f["suspicious_count"] = suspicious_word_count(url)
    f["url_length"] = url_length(url)
    at_count, dash_count, underscore_count, pct_count = count_special_chars(url)
    f["at_count"] = at_count
    f["dash_count"] = dash_count
    f["underscore_count"] = underscore_count
    f["pct_count"] = pct_count
    f["subdomain_depth"] = subdomain_depth(url)
    f["path_depth"] = path_depth(url)
    return f

# Modell einmal laden (wenn vorhanden)
_model_bundle = None
if os.path.exists(MODEL_PATH):
    try:
        _model_bundle = joblib.load(MODEL_PATH)
    except Exception:
        _model_bundle = None

def _heuristic_result_from_features(url, f):
    # Erzeuge die gleiche Punkt- und Statuslogik wie vorher, aber als Liste von Tripeln
    score = 100
    details = []

    # HTTPS
    if f["has_https"] == 0:
        points = 25
        details.append(("HTTPS Check", points, "URL beginnt nicht mit https://"))
        score -= points

    # IP
    if f["has_ip"] == 1:
        points = 30
        details.append(("IP-Adresse", points, "IP statt Domain in der URL"))
        score -= points

    # Verdächtige Wörter
    if f["suspicious_count"] > 0:
        points = f["suspicious_count"] * 5
        found = [w for w in SUSPICIOUS_WORDS if w in url.lower()][:5]
        details.append(("Verdächtige Wörter", points, f"Gefundene Keywords: {', '.join(found)}"))
        score -= points

    # Länge
    if f["url_length"] > 75:
        points = 10
        details.append(("URL Länge", points, "URL ist länger als 75 Zeichen"))
        score -= points

    # Symbole
    sym_points = f["at_count"] * 6 + f["dash_count"] * 2 + f["underscore_count"] * 2 + f["pct_count"] * 2
    if sym_points > 0:
        details.append(("Symbole", sym_points, "Vorkommen von @ / - / _ / %"))
        score -= sym_points

    # Subdomain
    if f["subdomain_depth"] > 2:
        points = 15
        details.append(("Subdomains", points, f"Tiefe Subdomain-Struktur: {f['subdomain_depth']}"))
        score -= points

    score = max(0, score)

    if score <= 10:
        status, color = "Extrem gefährlich", "red"
    elif score <= 30:
        status, color = "Unsicher", "orange"
    elif score <= 60:
        status, color = "Relativ sicher", "yellow"
    else:
        status, color = "Sicher", "green"

    # Wenn keine Details gesammelt wurden, positive Info
    if not details:
        details.append(("Keine offensichtlichen Heuristiken", 0, "Keine heuristischen Warnsignale gefunden"))

    return {"score": score, "status": status, "color": color, "details": details}

def scan_url(url):
    """
    Gibt ein dict zurück: {score, status, color, details}
    details ist eine Liste von Tripeln (name, points, reason) — kompatibel mit eurer Jinja2-Schleife.
    """
    # Basis Feature-Dict
    f = extract_feature_dict(url)

    # Wenn kein ML-Bundle vorhanden: fallback heuristics
    if _model_bundle is None:
        return _heuristic_result_from_features(url, f)

    # ML-Pfad
    try:
        model = _model_bundle["model"]
        scaler = _model_bundle["scaler"]
        feature_names = _model_bundle["feature_names"]

        # Baue Array in richtiger Reihenfolge
        X_raw = [f[name] for name in feature_names]
        X_scaled = scaler.transform([X_raw])
        proba_malicious = float(model.predict_proba(X_scaled)[0, 1])
        score = int(round((1.0 - proba_malicious) * 100))
        score = max(0, min(100, score))

        # Status
        if score <= 10:
            status, color = "Extrem gefährlich", "red"
        elif score <= 30:
            status, color = "Unsicher", "orange"
        elif score <= 60:
            status, color = "Relativ sicher", "yellow"
        else:
            status, color = "Sicher", "green"

        # Erklär-Details: ML-Wahrscheinlichkeit + heuristische Hinweise
        details = []
        details.append(("ML Wahrscheinlichkeit unsicher", int(round(proba_malicious*100)), f"Modell: {proba_malicious:.2f} P(Malicious)"))

        # gleiche heuristischen Hinweise wie Fallback (nur zur Erklärung)
        if f["has_https"] == 0:
            details.append(("HTTPS Check", 10, "Kein HTTPS"))
        if f["has_ip"] == 1:
            details.append(("IP-Adresse", 30, "IP in URL"))
        if f["suspicious_count"] > 0:
            details.append(("Verdächtige Wörter", f["suspicious_count"]*5, f"{f['suspicious_count']} verdächtige Wörter"))
        if f["url_length"] > 75:
            details.append(("URL Länge", 10, "Sehr lange URL"))
        if f["at_count"] > 0:
            details.append(("@-Zeichen", f["at_count"]*6, "Verwendung von @"))
        if f["dash_count"] > 4:
            details.append(("Viele Bindestriche", f["dash_count"]*2, "Viele '-' vorhanden"))
        if f["subdomain_depth"] > 2:
            details.append(("Subdomains", f["subdomain_depth"]*3, "Viele Subdomains"))

        if len(details) == 1:
            details.append(("Keine offensichtlichen Heuristiken", 0, "Keine heuristischen Warnsignale gefunden"))

        return {"score": score, "status": status, "color": color, "details": details}

    except Exception as e:
        # Bei Fehlern: loggen (wenn du Logging hast) und Fallback
        return _heuristic_result_from_features(url, f)