# CyberNet — ML-Modul für URL-Klassifikation

Dieses Repository enthält:
- `train_model.py` — trainiert ein RandomForest-Modell zur Vorhersage, ob eine URL gefährlich ist, und speichert `model.pkl`.
- `url_scan_ml.py` — Inferenz-Modul mit Funktion `scan_url(url)`; lädt `model.pkl` und liefert ein Ergebnisformat, das die vorhandene FastAPI/Jinja2-App erwartet.
- `requirements.txt` — benötigte Python-Pakete.

Anleitung:
1. Abhängigkeiten installieren:
   ```
   pip install -r requirements.txt
   ```

2. Modell trainieren (oder verwende eigene URL-Listen):
   - Optional: Lege `safe_urls.txt` und `malicious_urls.txt` an (je eine URL pro Zeile), dann wird das Training diese Daten zusätzlich zur synthetischen Menge verwenden.
   ```
   python train_model.py
   ```
   Dadurch wird `model.pkl` erstellt.

3. In FastAPI integrieren:
   - In deiner `main`-Datei (wo aktuell `from url_scan import scan_url` steht) ersetze die Importzeile durch:
     ```python
     from url_scan_ml import scan_url
     ```
   - Alternativ: benenne `url_scan_ml.py` in `url_scan.py` um/überschreibe die vorhandene Datei.

4. Starte die App:
   ```
   uvicorn main:app --reload
   ```
   (oder wie du deine App normalerweise startest)

Hinweise:
- Das Trainingsdataset im Skript ist synthetisch; für bessere Ergebnisse solltest du ein echtes, gelabeltes Dataset verwenden (z.B. aus OpenPhish, PhishTank oder eigenen Logs).
- Für interpretierbare Erklärungen kannst du SHAP/LIME integrieren — das ist nicht enthalten, um es einfach zu halten.
- Die `details`-Struktur ist eine Liste von Tripeln (name, points, reason), sodass deine Jinja-Schleife `{% for name, points, reason in result.details %}` funktioniert.