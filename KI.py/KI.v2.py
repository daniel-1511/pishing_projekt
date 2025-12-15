#!/usr/bin/env python3

from __future__ import annotations
import argparse
import logging
import math
import pickle
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sklearn.ensemble import RandomForestClassifier

# Optional runtime imports (only used when serving or testing)
try:
    import uvicorn
    from fastapi.testclient import TestClient
except Exception:
    uvicorn = None  # type: ignore
    TestClient = None  # type: ignore

# ---------------------------
# Configuration / Logging
# ---------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("phishing_checker")

MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "model.pkl"

# ---------------------------
# Small example dataset (dev only)
# Replace with a large, labeled dataset for production
# ---------------------------
DEFAULT_DATA: List[Tuple[str, int]] = [
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

SUSPICIOUS_TOKENS = ["login", "secure", "account", "update", "verify", "bank", "paypal", "signin", "confirm"]

# ---------------------------
# Feature extraction
# ---------------------------
def _get_host(url: str) -> str:
    """
    Extract host from a URL string in a simple way.
    """
    m = re.search(r'://([^/]+)', url)
    host = m.group(1) if m else url
    host = host.split(':')[0]  # remove port
    return host.lower()


def _is_ip(host: str) -> int:
    """
    Simple IPv4 check. Returns 1 if host looks like an IP.
    """
    return int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host)))


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    digits = sum(ch.isdigit() for ch in s)
    return digits / len(s)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    l = len(s)
    for count in freq.values():
        p = count / l
        ent -= p * math.log2(p)
    return ent


def extract_features(url: str) -> List[float]:
    """
    Return a numeric feature vector for a given URL.

    Booleans are converted to ints (0/1) for clarity/consistency.
    """
    host = _get_host(url)
    features: List[float] = [
        len(url),                       # total length of URL
        url.count("."),                 # number of dots
        url.count("-"),                 # number of hyphens
        url.count("@"),                 # number of '@'
        int(url.startswith("https")),   # has https
        int(bool(re.search(r"\d", url))),  # contains any digit
        _is_ip(host),                   # host is an IP
        _digit_ratio(host),             # ratio of digits in host
        _shannon_entropy(host),         # host entropy
        sum(int(tok in url.lower()) for tok in SUSPICIOUS_TOKENS),  # suspicious token count
    ]
    return features


# ---------------------------
# Model training / saving / loading
# ---------------------------
def train_model(
    data: List[Tuple[str, int]] = DEFAULT_DATA,
    model_path: Path = MODEL_PATH,
    n_estimators: int = 200,
    random_state: int = 42,
) -> RandomForestClassifier:
    """
    Train a RandomForestClassifier on provided dataset and save to model_path.
    Returns the trained classifier object.
    """
    logger.info("Training model with %d examples", len(data))
    X = [extract_features(url) for url, _ in data]
    y = [label for _, label in data]

    clf = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state)
    clf.fit(X, y)

    try:
        with model_path.open("wb") as f:
            pickle.dump(clf, f)
        logger.info("Saved model to %s", model_path)
    except Exception as e:
        logger.exception("Failed to save model: %s", e)
        raise

    return clf


def load_model(model_path: Path = MODEL_PATH) -> Optional[RandomForestClassifier]:
    """
    Load a pickled model. Returns None if model cannot be loaded or doesn't exist.
    """
    if not model_path.exists():
        logger.warning("Model file %s not found.", model_path)
        return None
    try:
        with model_path.open("rb") as f:
            model = pickle.load(f)
        logger.info("Loaded model from %s", model_path)
        return model
    except Exception as e:
        logger.exception("Failed to load model from %s: %s", model_path, e)
        return None


# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI(title="Phishing URL Checker (single-file)")

class URLRequest(BaseModel):
    url: str

class URLResponse(BaseModel):
    safe: float
    phishing: float

@app.on_event("startup")
def _startup_load_model() -> None:
    """
    Load model on startup and attach to app.state.model
    """
    app.state.model = load_model(MODEL_PATH)
    if app.state.model is None:
        logger.warning("No model loaded during startup. /check-url will return 503 until model exists.")


@app.post("/check-url", response_model=URLResponse)
def check_url(req: URLRequest):
    """
    Predict safe vs phishing probabilities for a given URL. Expects JSON {"url": "..."}.
    """
    model: Optional[RandomForestClassifier] = getattr(app.state, "model", None)
    if model is None:
        raise HTTPException(status_code=503, detail="Model not available. Train model first (python KI.py train).")

    url = req.url
    if not isinstance(url, str) or not url.strip():
        raise HTTPException(status_code=400, detail="Invalid or empty url")

    features = [extract_features(url)]
    try:
        probs = model.predict_proba(features)[0]
    except Exception as e:
        logger.exception("Model prediction failed: %s", e)
        raise HTTPException(status_code=500, detail="Model prediction failed")

    # Map class labels to indices for safety
    class_to_index = {c: i for i, c in enumerate(model.classes_)}
    safe_prob = float(probs[class_to_index.get(0, 0)]) if 0 in class_to_index else float(probs[0])
    phishing_prob = float(probs[class_to_index.get(1, 1)]) if 1 in class_to_index else float(probs[-1])

    return {
        "safe": round(safe_prob * 100, 2),
        "phishing": round(phishing_prob * 100, 2),
    }


# ---------------------------
# CLI helpers
# ---------------------------
def serve(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """
    Serve the FastAPI app using uvicorn programmatically.
    """
    if uvicorn is None:
        logger.error("uvicorn is not installed. Install with `pip install uvicorn`.")
        return

    if not MODEL_PATH.exists():
        logger.warning("Model not found at %s. The app will start but /check-url will return 503 until model exists.", MODEL_PATH)

    logger.info("Starting server at %s:%d (reload=%s)", host, port, reload)
    uvicorn.run("KI:app", host=host, port=port, reload=reload)  # module name: KI if executed as KI.py


def quick_predict(url: str) -> Optional[Dict[str, float]]:
    """
    Quick local prediction (does not start server) - loads model and returns probabilities.
    """
    model = load_model(MODEL_PATH)
    if model is None:
        logger.error("Model not found. Train first using 'python KI.py train'")
        return None
    features = [extract_features(url)]
    probs = model.predict_proba(features)[0]
    class_to_index = {c: i for i, c in enumerate(model.classes_)}
    safe_prob = float(probs[class_to_index.get(0, 0)]) if 0 in class_to_index else float(probs[0])
    phishing_prob = float(probs[class_to_index.get(1, 1)]) if 1 in class_to_index else float(probs[-1])
    return {"safe": round(safe_prob * 100, 2), "phishing": round(phishing_prob * 100, 2)}


def run_tests() -> None:
    """
    Run simple internal tests:
      - trains model if missing
      - spins up the FastAPI TestClient and checks endpoint behavior
    This is not a replacement for real unit tests but is helpful for quick validation.
    """
    if TestClient is None:
        logger.error("fastapi.testclient isn't available. Install with `pip install fastapi[all]` or `pip install testclient`.")
        return

    # Ensure model exists
    if not MODEL_PATH.exists():
        logger.info("Model not found; training quick demo model for tests.")
        train_model(DEFAULT_DATA)

    # Import app module (this file)
    client = TestClient(app)
    logger.info("Running internal tests against /check-url")

    # happy path
    resp = client.post("/check-url", json={"url": "https://www.google.com"})
    assert resp.status_code == 200, f"expected 200, got {resp.status_code} - {resp.text}"
    data = resp.json()
    assert "safe" in data and "phishing" in data
    logger.info("/check-url happy path OK: %s", data)

    # validation error (missing url)
    resp2 = client.post("/check-url", json={})
    assert resp2.status_code == 422, f"expected 422 for validation, got {resp2.status_code}"
    logger.info("/check-url validation path OK (returned 422)")

    # bad url value
    resp3 = client.post("/check-url", json={"url": ""})
    assert resp3.status_code == 400, f"expected 400 for empty url, got {resp3.status_code}"
    logger.info("/check-url empty url handling OK (returned 400)")

    logger.info("All internal tests passed.")


# ---------------------------
# Main CLI
# ---------------------------
def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Phishing URL checker (train + serve + test) — single file")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="Train a model and save to models/model.pkl")
    p_train.add_argument("--n-estimators", type=int, default=200, help="Number of trees for RandomForest")
    p_train.add_argument("--overwrite", action="store_true", help="Overwrite existing model file if present")

    p_serve = sub.add_parser("serve", help="Serve the FastAPI app (requires uvicorn)")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true", help="Enable uvicorn reload (dev only)")

    p_predict = sub.add_parser("predict", help="Quick local predict (loads models/model.pkl)")
    p_predict.add_argument("--url", required=True, help="URL to check")

    p_test = sub.add_parser("test", help="Run simple internal tests (uses TestClient)")

    args = parser.parse_args(argv)

    if args.cmd == "train":
        if MODEL_PATH.exists() and not args.overwrite:
            logger.info("Model already exists at %s. Use --overwrite to retrain.", MODEL_PATH)
            return
        train_model(DEFAULT_DATA, MODEL_PATH, n_estimators=args.n_estimators)
        logger.info("Training complete.")
    elif args.cmd == "serve":
        if uvicorn is None:
            logger.error("uvicorn not available. Install with `pip install uvicorn`.")
            return
        # Ensure module name used by uvicorn matches this file. When running `python KI.py serve`,
        # uvicorn.run("KI:app", ...) expects the module importable as KI. This is fine when running as a script
        # since Python sets the module name to '__main__'. To avoid issues, we run uvicorn programmatically.
        serve(host=args.host, port=args.port, reload=args.reload)
    elif args.cmd == "predict":
        out = quick_predict(args.url)
        if out is not None:
            print(f"safe: {out['safe']}%, phishing: {out['phishing']}%")
    elif args.cmd == "test":
        run_tests()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()