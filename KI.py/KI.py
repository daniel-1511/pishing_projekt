from fastapi import FastAPI
import pickle
import re
from sklearn.ensemble import RandomForestClassifier

# =========================
# 1. DATASET (inline)
# =========================
DATA = [
    ("https://www.google.com", 0),
    ("https://www.github.com", 0),
    ("https://www.wikipedia.org", 0),
    ("https://www.amazon.de", 0),
    ("https://www.stackoverflow.com", 0),
    ("http://paypal-login-security.com", 1),
    ("https://paypal.com@verify.ru", 1),
    ("http://bank-update123.net/login", 1),
    ("http://secure-account-check.net", 1),
]

# =========================
# 2. FEATURE EXTRACTION
# =========================
def extract_features(url: str):
    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.startswith("https"),
        bool(re.search(r"\d", url))
    ]

# =========================
# 3. TRAINING
# =========================
X = [extract_features(url) for url, _ in DATA]
y = [label for _, label in DATA]

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X, y)

# Modell speichern (optional, aber gut für Abgabe)
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ KI-Modell trainiert & gespeichert")

# =========================
# 4. FASTAPI
# =========================
app = FastAPI(title="Phishing URL Checker")

@app.post("/check-url")
def check_url(data: dict):
    url = data["url"]
    features = [extract_features(url)]
    probabilities = model.predict_proba(features)[0]

    return {
        "safe": round(probabilities[0] * 100, 2),
        "phishing": round(probabilities[1] * 100, 2)
    }
