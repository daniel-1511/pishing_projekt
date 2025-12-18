import requests

def validate_html(url):
    errors = []
    try:
        api = "https://validator.w3.org/nu/"
        params = {
            "doc": url,
            "out": "json"
        }
        response = requests.get(api, params=params, timeout=10)
        data = response.json()

        for msg in data.get("messages", []):
            if msg["type"] == "error":
                errors.append(
                    f"HTML-Fehler Zeile {msg.get('lastLine')}: {msg.get('message')}"
                )

    except Exception as e:
        errors.append(f"HTML-Validator Fehler: {str(e)}")

    return errors
