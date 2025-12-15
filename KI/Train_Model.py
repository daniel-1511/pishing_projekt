import os
import re
import random
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

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
    # Zähle ein paar häufige verdächtige Symbole
    return url.count("@"), url.count("-"), url.count("_"), url.count("%")

def subdomain_depth(url):
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]
    parts = host.split(".")
    # Wenn z.B. www.example.co.uk -> parts len 4 -> subdomain depth = len-2 (approx)
    return max(len(parts) - 2, 0)

def path_depth(url):
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return 0
    return len([p for p in path.split("/") if p])

def extract_features(url):
    features = {}
    features["has_https"] = has_https(url)
    features["has_ip"] = has_ip(url)
    features["suspicious_count"] = suspicious_word_count(url)
    features["url_length"] = url_length(url)
    at_count, dash_count, underscore_count, pct_count = count_special_chars(url)
    features["at_count"] = at_count
    features["dash_count"] = dash_count
    features["underscore_count"] = underscore_count
    features["pct_count"] = pct_count
    features["subdomain_depth"] = subdomain_depth(url)
    features["path_depth"] = path_depth(url)
    return features

def synthetic_urls():
    safe_domains = [
        "https://example.com", "https://github.com", "https://www.wikipedia.org",
        "https://news.ycombinator.com", "https://www.python.org", "https://stackoverflow.com"
    ]
    bad_keywords = ["login", "secure", "update", "bank", "confirm", "signin", "account", "password"]
    tlds = ["com", "net", "org", "info", "biz"]
    safe = []
    malicious = []

    # Erzeuge sichere Varianten
    for d in safe_domains:
        for i in range(10):
            safe.append(d + ("/" if i % 2 == 0 else "") + f"page{i}")

    # Erzeuge bösartige Varianten
    for i in range(600):
        proto = random.choice(["http://", "https://"])
        sub = random.choice(["", "secure.", "update.", "login.", "auth."])
        kw = random.choice(bad_keywords)
        domain = f"{sub}{kw}-{random.randint(1,999)}.{random.choice(tlds)}"
        path = "/" + "/".join([random.choice(["verify","id","reset","confirm",""]) for _ in range(random.randint(0,3))])
        url = proto + domain + path
        # gelegentlich IP-Adresse einfügen
        if random.random() < 0.15:
            ip = f"http://{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            url = ip + path
        malicious.append(url)

    # Füge noch einige gemischte Beispiele hinzu
    for i in range(400):
        proto = random.choice(["http://", "https://"])
        domain = f"www.{random.choice(['example','mysite','portal','service'])}{random.randint(1,500)}.com"
        path = "/" + "-".join([random.choice(["home","about","contact","product","download"]) for _ in range(random.randint(0,3))])
        safe.append(proto + domain + path)

    return safe, malicious

def load_urls_from_files():
    safe = []
    malicious = []
    if os.path.exists("safe_urls.txt"):
        with open("safe_urls.txt", "r", encoding="utf-8") as f:
            safe += [line.strip() for line in f if line.strip()]
    if os.path.exists("malicious_urls.txt"):
        with open("malicious_urls.txt", "r", encoding="utf-8") as f:
            malicious += [line.strip() for line in f if line.strip()]
    return safe, malicious

def build_dataset():
    safe_sys, malicious_sys = synthetic_urls()
    safe_files, malicious_files = load_urls_from_files()
    safe = safe_sys + safe_files
    malicious = malicious_sys + malicious_files

    urls = safe + malicious
    labels = [0] * len(safe) + [1] * len(malicious)

    features_list = []
    for u in urls:
        features_list.append(extract_features(u))

    df = pd.DataFrame(features_list)
    df["label"] = labels
    return df

def train_and_save(output_path="model.pkl"):
    df = build_dataset()
    feature_names = [c for c in df.columns if c != "label"]
    X = df[feature_names].values
    y = df["label"].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("Accuracy:", accuracy_score(y_test, y_pred))
    try:
        print("ROC AUC:", roc_auc_score(y_test, y_proba))
    except Exception:
        pass
    print("Classification report:")
    print(classification_report(y_test, y_pred))

    # Speichere Modell + Scaler + Feature-Namen
    bundle = {"model": clf, "scaler": scaler, "feature_names": feature_names}
    joblib.dump(bundle, output_path)
    print(f"Model saved to {output_path}")

if __name__ == "__main__":
    train_and_save()