import re
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "bank",
    "account", "update", "free", "bonus",
    "confirm", "password"
]

def check_https(url):
    return 0 if url.startswith("https://") else 25

def check_ip(url):
    ip_pattern = r"(http://|https://)?(\d{1,3}\.){3}\d{1,3}"
    return 30 if re.search(ip_pattern, url) else 0

def check_words(url):
    count = sum(word in url.lower() for word in SUSPICIOUS_WORDS)
    return count * 5

def check_length(url):
    return 10 if len(url) > 75 else 0

def check_symbols(url):
    dangerous = ["@", "-", "_"]
    return sum(url.count(sym) * 3 for sym in dangerous)

def check_subdomain(url):
    parsed = urlparse(url)
    parts = parsed.netloc.split(".")
    return 15 if len(parts) > 3 else 0

def scan_url(url):
    score = 100
    deductions = {
        "HTTPS Check": check_https(url),
        "IP-Adresse": check_ip(url),
        "Verdächtige Wörter": check_words(url),
        "URL Länge": check_length(url),
        "Symbole": check_symbols(url),
        "Subdomain": check_subdomain(url),
    }
    for value in deductions.values():
        score -= value
    score = max(score, 0)

    # Status
    if score <= 10:
        status = "Extrem gefährlich"
        color = "red"
    elif score <= 30:
        status = "Unsicher"
        color = "orange"
    elif score <= 60:
        status = "Relativ sicher"
        color = "yellow"
    else:
        status = "Sicher"
        color = "green"

    return {
        "score": score,
        "status": status,
        "color": color,
        "details": deductions
    }
