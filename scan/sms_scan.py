import re
from typing import Dict, List
import ollama

# PHISHING-SCHLÜSSELWÖRTER - VERBESSERT

PHISHING_KEYWORDS: Dict[str, List[str]] = {

    "familie": [
        "hallo mama", "hallo papa", "hi mama", "hi papa",
        "mama", "papa", "mutti", "vati", "mom", "dad",
        "mutter", "vater", "liebe mama", "lieber papa",
        "sohn", "tochter", "bruder", "schwester",
        "oma", "opa", "großmutter", "großvater",
        "neue nummer", "handy kaputt", "neues handy",
        "bitte hilf mir", "hilf mir", "ich brauche geld", "brauch geld",
        "in der falle", "verhaftet", "verhaftung", "verhastet",
        "unfallbericht", "unfall", "krankenhaus", "notfall",
        "im ausland", "strand", "problem", "hilfe",
        "notlage", "notwendig", "dringend", "eilig",
        "tante", "onkel", "cousin", "cousine",
        "enkel", "enkelin", "verwandt", "familienangehörig"
    ],

    "geld": [
        "überweis", "überweisung", "zahlung", "bezahlen",
        "geld", "betrag", "euro", "€", "rechnung",
        "paypal", "banktransfer", "sepa",
        "bankdaten", "kontonummer", "iban", "blz",
        "kreditkarte", "visa", "mastercard", "amex",
        "psc", "cvv", "prüfziffer", "cvv2",
        "kontoauszug", "kontostand", "kontoführung",
        "vermögen", "erbe", "erbschaft", "hinterlassenschaft",
        "kredite", "darlehn", "zinsen", "gebühren",
        "schulden", "zahle", "bezahle", "vergütung"
    ],

    "bank": [
        "bank", "konto", "iban", "bankverbindung",
        "login", "verifizieren", "verifizier", "bestätigen",
        "passwort", "pin", "tan", "code",
        "bestätigung", "authentifizierung", "authentifizier",
        "zwei-faktor", "2fa", "zweifaktor",
        "sicherheit", "sicherheitscode", "sicherheitsabfrage",
        "legitimation", "verifikation", "verifizier",
        "identität", "identitätsnachweis", "ausweis",
        "adresse verifizieren", "kontobestätigung", "kontoverifizier",
        "benutzername", "passwort zurücksetzen", "pw", "password"
    ],

    "gewinn": [
        "gewonnen", "gewinn", "preis", "gewinner",
        "jackpot", "lotterie", "gewinnspiel",
        "gutschein", "bonus", "belohnung", "prämie",
        "glückwunsch", "herzlichen glückwunsch", "glück",
        "sie sind auserwählt", "auserwählt", "gewählt",
        "gewinnchance", "chance", "los",
        "iphone", "ipad", "playstation", "ps5",
        "amazon gutschein", "itunes gutschein", "guthaben",
        "preisgeld", "geldpreis", "hauptgewinn"
    ],

    "gratis": [
        "gratis", "kostenlos", "free", "free download",
        "umsonst", "geschenk", "0€", "kostenlos",
        "kostenlose", "null euro", "ohne kosten",
        "keine gebühren", "gebührenfrei", "kostenfrei",
        "umsonst", "freebie", "frei", "ohne zahlung"
    ],

    "druck": [
        "dringend", "sofort", "jetzt", "gleich",
        "letzte chance", "heute", "frist", "deadline",
        "eile", "eilig", "zeitlich begrenzt", "begrenzt",
        "endet heute", "läuft ab", "ablaufdatum", "ablauf",
        "verfällt", "verfallsdatum", "gültig bis",
        "handeln sie jetzt", "zögern sie nicht", "nicht warten",
        "schnell handeln", "beeilen sie sich", "beeilt",
        "nicht verpassen", "verpassen sie nicht", "don't miss",
        "begrenzte zeit", "limitiert", "limited", "nur heute"
    ],

    "link": [
        "hier klicken", "klick hier", "hier", "klicken",
        "jetzt bestätigen", "bestätigen", "aktivieren",
        "link", "anklicken", "anmelden", "login",
        "aktivieren", "folgen", "besuchen", "öffnen",
        "öffne", "bestätigung hier", "klicken sie hier",
        "tinyurl", "bit.ly", "shortened", "url",
        "kurz.link", "short", "website", "webseite",
        "download", "laden", "herunterladen"
    ],

    "social_engineering": [
        "können sie mir helfen", "brauche hilfe", "hilf mir",
        "vertrauen sie mir", "vertrau mir", "trau mir",
        "nur du kannst mir helfen", "nur sie können",
        "frag nicht", "sag niemand", "sag keinem",
        "erzähl es niemandem", "geheim", "heimlich",
        "darf keiner wissen", "darf die mama nicht wissen",
        "streng geheim", "vertraulich", "privat",
        "vertrau mir", "im vertrauen", "zwischen uns"
    ],

    "malware": [
        "update erforderlich", "update verfügbar",
        "software update", "sicherheitsupdate",
        "neueste version", "herunterladen",
        "datei öffnen", "download",
        "anhang öffnen", "attachment",
        "installieren", "aktivieren",
        "aktion erforderlich", "wird benötigt",
        ".exe", ".zip", ".apk", ".dmg"
    ],

    "phishing_trojan": [
        "virus erkannt", "malware erkannt",
        "ihr gerät wurde gehackt", "gehackt",
        "kompromittiert", "infiziert",
        "warnung", "alert",
        "sicherheitswarnung", "security warning",
        "trojaner", "rootkit", "spyware",
        "bitte umgehend", "dringend erforderlich",
        "klicken sie hier jetzt", "betroffene konten"
    ],

    "imitation": [
        "apple", "amazon", "google", "microsoft",
        "paypal", "ebay", "instagram", "facebook",
        "bankname", "commerzbank", "sparkasse",
        "deutsche bank", "dkb", "ing",
        "apple id", "amazon konto", "google account",
        "paypal konto", "instagram konto",
        "offizielle mitteilung", "wichtige mitteilung"
    ],

    "urgency_threats": [
        "account gesperrt", "gesperrt",
        "eingeschränkt", "bald gelöscht",
        "wird gelöscht", "löschen",
        "deaktiviert", "deaktivierung",
        "suspended", "banned",
        "bestätigen sie sofort", "sofort bestätigen",
        "heute noch", "innerhalb 24 stunden",
        "droht zu verfallen", "droht gesperrt",
        "handeln sie augenblicklich"
    ],

    "sextortion": [
        "bloß gestellt", "öffentlich machen",
        "fotos verbreiten", "screenshot",
        "porno", "nacktfotos", "bilder",
        "webcam", "kamera",
        "erpressen", "erpressung",
        "bitcoin", "geld überweisen",
        "wenn nicht", "ansonsten",
        "stunden", "tage", "besorgnis"
    ]
}

# HILFSFUNKTIONEN

def keyword_found(text: str, keyword: str) -> bool:
    if " " in keyword:
        return keyword in text
    return re.search(rf"\b{re.escape(keyword)}\b", text, re.IGNORECASE) is not None


def highlight_suspicious_words(text: str, found: Dict[str, List[str]]) -> str:
    highlighted = text
    for words in found.values():
        for word in sorted(words, key=len, reverse=True):
            highlighted = re.sub(
                re.escape(word),
                r"<mark>\g<0></mark>",
                highlighted,
                flags=re.IGNORECASE
            )
    return highlighted


def analyze_url_in_text(text: str) -> Dict:
    """Analysiert verdächtige URLs in der SMS"""
    url_pattern = r"https?://[^\s]+"
    urls = re.findall(url_pattern, text)
    
    suspicious_domains = [
        "bit.ly", "tinyurl", "goo.gl", "short.link",
        "cloudflare", "herokuapp", "github.io",
        "000webhostapp", "epizy", "000webhostapp"
    ]
    
    url_risks = []
    for url in urls:
        for suspicious in suspicious_domains:
            if suspicious in url.lower():
                url_risks.append(("URL-Verkürzung", 15, f"Verkürzte URL kann Phishing-Link verstecken: {url[:50]}"))
                break
    
    return {
        "found_urls": len(urls),
        "urls": urls,
        "risks": url_risks
    }


def detect_unicode_homoglyphs(text: str) -> Dict:
    """Erkennt homoglyph-Attacken (ähnliche Zeichen)"""
    cyrillic_chars = re.findall(r"[а-яА-ЯёЁ]", text)
    greek_chars = re.findall(r"[α-ωΑ-Ω]", text)
    
    risks = []
    if cyrillic_chars:
        risks.append(("Kyrillische Zeichen erkannt", 20, "Könnte Homoglyph-Angriff sein (ähnliche Zeichen)"))
    if greek_chars:
        risks.append(("Griechische Zeichen erkannt", 15, "Könnte verdächtig sein"))
    
    return {
        "cyrillic": len(cyrillic_chars),
        "greek": len(greek_chars),
        "risks": risks
    }


def analyze_emoji_usage(text: str) -> Dict:
    """Analysiert verdächtige Emoji-Nutzung"""
    emoji_pattern = r"[😀-🙏🌀-🗿🚀-🛿]"
    emojis = re.findall(emoji_pattern, text)
    
    # Betrüger nutzen oft Emojis zur Ablenkung
    if len(emojis) > 3:
        return {
            "count": len(emojis),
            "risk": ("Übermäßige Emoji-Nutzung", 10, "Könnte zur Ablenkung genutzt werden")
        }
    
    return {"count": len(emojis), "risk": None}

# 🤖 KI-Erklärung und Score generieren mit Ollama
def generate_ai_explanation_sms(sms_text, score, status, details):
    prompt = f"""Du bist ein SMS-Sicherheits-Profi der Polizei - Erkläre diese Nachricht wie zu einem guten Freund. EINFACH UND KLAR!

SMS-TEXT ZU ANALYSIEREN: {sms_text}

ANTWORTE IN GENAU DIESEM FORMAT:

==== KURZ (3 Punkte) ====
• Punkt 1: [Hauptproblem in 10 Worten]
• Punkt 2: [Zweites Problem in 10 Worten]
• Punkt 3: [Konkrete Warnung in 10 Worten]

==== DETAILS ====

🚨 IST DAS EIN BETRUG?
JA/NEIN + kurze Begründung (max 2 Sätze, einfache Worte)

🎯 WAS WOLLEN DIE BETRÜGER?
- Ziel 1 (z.B. "Mein Geld klauen", "Meine Login-Daten", "Meine Kreditkarte")
- Ziel 2
- Ziel 3

🔴 WARNSIGNALE IN DIESER SMS:
- Signal 1 (z.B. "Dringend = Zeitdruck", "Unbekannte Nummer = Verdächtig")
- Signal 2
- Signal 3

📌 ECHTE BEISPIELE VON BETRÜGERN:
"Lieber Sohn, bin in Notlage. Brauch 500€ auf dieses Konto..." [= ENKELTRICK]
"Du hast einen Preis gewonnen! Klick hier..." [= GEWINN-BETRUG]

✅ SO SCHÜTZT DU DICH:
- Tipp 1 (z.B. "Nicht antworten oder klicken")
- Tipp 2 (z.B. "Anzrufen unter alter Nummer")
- Tipp 3 (z.B. "Polizei anrufen wenn verdächtig")

---

REGELN BEFOLGEN:
✓ NUR EINFACHE DEUTSCHE WORTE (keine Fachbegriffe)
✓ SEHR KURZ (max 3-4 Zeilen pro Abschnitt)
✓ DIREKTE ANSPRACHE ("Du", "Dein")
✓ KONKRETE BEISPIELE AUS ECHTEN BETRÜGEREIEN
✓ SOFORTIGE TIPPS ZUM HANDELN
✓ KEINE WIEDERHOLUNGEN"""
    
    try:
        response = ollama.chat(model='llama3.2', messages=[{'role': 'user', 'content': prompt}])
        explanation = response['message']['content'].strip()
        return score, explanation
    except Exception as e:
        return score, f"KI-Analyse nicht verfügbar: {str(e)}"

# SMS-ANALYSE

def scan_sms(sms_text: str) -> Dict:
    score = 100
    details = []
    high_risk_indicators = 0

    sms_lower = sms_text.lower()
    found = {category: [] for category in PHISHING_KEYWORDS}

    # 🔍 ALLE KEYWORDS DURCHSUCHEN
    for category, words in PHISHING_KEYWORDS.items():
        for word in words:
            if keyword_found(sms_lower, word):
                found[category].append(word)

    highlighted_text = highlight_suspicious_words(sms_text, found)

    # ===== URL ANALYSE =====
    url_analysis = analyze_url_in_text(sms_lower)
    if url_analysis["risks"]:
        for risk in url_analysis["risks"]:
            details.append(risk)
            score -= risk[1]

    # ===== UNICODE/HOMOGLYPH ANALYSE =====
    unicode_analysis = detect_unicode_homoglyphs(sms_text)
    for risk in unicode_analysis["risks"]:
        details.append(risk)
        score -= risk[1]

    # ===== EMOJI ANALYSE =====
    emoji_analysis = analyze_emoji_usage(sms_text)
    if emoji_analysis["risk"]:
        details.append(emoji_analysis["risk"])
        score -= emoji_analysis["risk"][1]

    # ===== SEXTORTION ERKENNUNG =====
    if found["sextortion"]:
        score -= 70
        high_risk_indicators += 1
        details.append((
            "🚨 SEXTORTION / ERPRESSUNG ERKANNT",
            70,
            "Dies ist eine bekannte Erpressungs-SMS. Geld zu überweisen ist eine Falle!"
        ))

    # ===== MALWARE / TROJANER ERKENNUNG =====
    if found["malware"] or found["phishing_trojan"]:
        score -= 65
        high_risk_indicators += 1
        details.append((
            "🚨 MALWARE / TROJANER WARNUNG",
            65,
            "Dies könnte ein Versuch sein, Malware auf Ihr Gerät zu laden."
        ))

    # ===== IMITATION von Unternehmen =====
    if found["imitation"]:
        score -= 55
        high_risk_indicators += 1
        details.append((
            "🚨 UNTERNEHMENS-IMITATION",
            55,
            f"Verdacht auf Fake-SMS von: {', '.join(found['imitation'][:3])}"
        ))

    # ===== URGENCY & THREATS =====
    if found["urgency_threats"]:
        score -= 50
        high_risk_indicators += 1
        details.append((
            "🚨 KONTO-SPERRUNGS BETRUG",
            50,
            "Typisches Phishing: Behauptung, dass Konto gesperrt wird"
        ))

    # ===== SOZIALES ENGINEERING =====
    if found["social_engineering"]:
        score -= 45
        high_risk_indicators += 1
        details.append((
            "🔴 SOZIALES ENGINEERING",
            45,
            "Versuch, Sie zu manipulieren und zu täuschen"
        ))

    # 🚨 FAMILIE (aber keine andere Kategorie)
    family_verification = {
        "active": False,
        "title": "",
        "steps_before_reply": [],
        "analysis": ""
    }

    if found["familie"] and not found["geld"] and not found["druck"]:
        # Eventuell legitim, aber verdächtig
        family_verification["active"] = True
        family_verification["title"] = "⚠️ Familienbezug erkannt - Vorsicht!"
        family_verification["analysis"] = (
            "SMS mit Familienbezug können legitim sein, werden aber häufig von Betrügern genutzt."
        )
        family_verification["steps_before_reply"] = [
            "❌ Nicht direkt antworten",
            "📞 Person über BEKANNTE Nummer anrufen",
            "💰 KEIN Geld überweisen",
            "🔐 KEINE Codes weitergeben",
            "📸 KEINE Fotos/Beweise hochladen"
        ]
        score -= 30
        details.append((
            "⚠️ Familienbezug mit Druck",
            30,
            f"Kritische Keywords: {', '.join(found['familie'][:3])}"
        ))

    # 🎯 KOMBOS - SEHR GEFÄHRLICH
    # Familie + Geld/Druck = KLASSISCHER BETRUG (Enkeltrick)
    if found["familie"] and (found["geld"] or found["druck"]):
        score -= 65
        high_risk_indicators += 2
        combined_keywords = (found["familie"] + found["geld"] + found["druck"])[:3]
        details.append((
            "🔴🔴 KRITISCH: Familie + Geld/Druck",
            65,
            f"Klassischer Enkeltrick/Oma-Betrug! Keywords: {', '.join(combined_keywords)}"
        ))
        family_verification["active"] = True
        family_verification["title"] = "🚨 KRITISCHE WARNUNG - ENKELTRICK ERKANNT!"

    # Gewinn/Gratis + Druck = FAST SICHER BETRUG
    elif (found["gewinn"] or found["gratis"]) and found["druck"]:
        score -= 60
        high_risk_indicators += 1
        details.append((
            "🔴 HOCHRISIKO: Gewinn-Betrug mit Zeitdruck",
            60,
            "\"Gewinnen Sie JETZT\" ist ein klassisches Betrugsmuster"
        ))

    # Bank + Link + Druck = PHISHING
    elif found["bank"] and found["link"] and found["druck"]:
        score -= 65
        high_risk_indicators += 1
        details.append((
            "🔴 BANK-PHISHING WARNUNG",
            65,
            "Verdacht auf Phishing mit gefälschtem Bank-Link"
        ))

    # Geld + Druck + Link = ZAHLUNGS-PHISHING
    elif found["geld"] and found["druck"] and found["link"]:
        score -= 60
        high_risk_indicators += 1
        details.append((
            "🔴 ZAHLUNG-PHISHING",
            60,
            "Versuch, Sie zu schneller Zahlung zu manipulieren"
        ))

    # 🎁 GEWINN / GRATIS (einzeln)
    elif (found["gewinn"] or found["gratis"]):
        score -= 50
        high_risk_indicators += 1
        details.append((
            "🟠 Gewinn-/Gratisversprechen",
            50,
            "Verdächtig: Ungefragte Gewinnversprechen sind typische Betrugsmasche"
        ))

    # 💰 GELD + CODE (sehr verdächtig)
    if found["geld"] and found["bank"]:
        score -= 40
        details.append((
            "🔴 FINANZIELLE DATEN GEFORDERT",
            40,
            "Niemals Bankdaten, TANs oder PINs mitteilen! Das ist Phishing!"
        ))

    # 🔗 LINKS ANALYSE
    if re.search(r"(https?://|www\.)", sms_lower):
        score -= 25
        details.append((
            "⚠️ Link in SMS",
            25,
            "Phishing-Links können gefährliche Websites öffnen oder Malware laden"
        ))

    if url_analysis["found_urls"] > 2:
        score -= 15
        details.append((
            "⚠️ Mehrere Links",
            15,
            f"Mehrere Links in einer SMS ({url_analysis['found_urls']}) sind suspekt"
        ))

    # 🔢 ZAHLENCODE ANALYSE
    codes = re.findall(r"\b\d{4,6}\b", sms_text)
    if codes:
        score -= 25
        details.append((
            "🔴 Zahlencode(s) erkannt",
            25,
            f"Codes wie {', '.join(codes[:3])} könnten TANs/PINs sein - NIE weitergeben!"
        ))

    # 📊 LÄNGE-ANOMALIEN
    if len(sms_text) > 300:
        score -= 8
        details.append((
            "⚠️ Ungewöhnlich lange SMS",
            8,
            "Sehr lange SMS werden für Phishing oft genutzt"
        ))

    # 🌐 FREMDSPRACHIGE MERKMALE
    if found["imitation"]:
        score -= 15
        details.append((
            "⚠️ Verdächtige Sprachmuster",
            15,
            "SMS könnte maschinell übersetzt sein"
        ))

    # 🔐 PASSWORT / GEHEIMNIS FRAGEN
    if re.search(r"passwort|pin|code|geheim|bestätigung", sms_lower):
        score -= 30
        details.append((
            "🔴 GEHEIME DATEN GEFORDERT",
            30,
            "Legitime Unternehmen fragen NIEMALS per SMS nach Passwörtern/Codes!"
        ))

    # 👤 IDENTITÄTS-VERIFIZIERUNG BETRUG
    if re.search(r"identität|personalausweis|ausweis|ausweiskopie|dateianhang", sms_lower):
        score -= 40
        high_risk_indicators += 1
        details.append((
            "🔴 IDENTITÄTSDIEBSTAHL-VERSUCH",
            40,
            "Keine seriöse Institution fordert Ausweiskopien per SMS!"
        ))

    # ⏰ ZEITDRUCK
    if found["druck"]:
        score -= 30
        details.append((
            "🔴 EXTREMER ZEITDRUCK",
            30,
            "Betrüger erzeugen künstliche Dringlichkeit um schnelle (falsche) Entscheidungen zu erzwingen"
        ))

    # 💸 BITCOIN / KRYPTOWÄHRUNG
    if re.search(r"bitcoin|ethereum|kryptowährung|wallet|crypto", sms_lower):
        score -= 60
        high_risk_indicators += 1
        details.append((
            "🔴 KRYPTOWÄHRUNG-BETRUG",
            60,
            "Betrüger fordern Zahlungen in Kryptos um nicht zurückverfolgt zu werden"
        ))

    score = max(score, 0)

    # Initialer Status für KI-Prompt
    status = "Unbekannt"

    # 🤖 KI-Erklärung und Score generieren
    ai_score, ai_explanation = generate_ai_explanation_sms(sms_text, score, status, details)

    # 🧠 Status basierend auf KI-Score
    if ai_score <= 10:
        status = "🔴🔴 EXTREM GEFÄHRLICH"
        color = "#CC0000"
        risk_level = "EXTREME"
    elif ai_score <= 25:
        status = "🔴 SEHR GEFÄHRLICH"
        color = "#FF0000"
        risk_level = "CRITICAL"
    elif ai_score <= 45:
        status = "🟠 GEFÄHRLICH"
        color = "#FF6600"
        risk_level = "HIGH"
    elif ai_score <= 70:
        status = "🟡 POTENTIELL GEFÄHRLICH"
        color = "#FFAA00"
        risk_level = "MEDIUM"
    else:
        status = "🟢 WAHRSCHEINLICH SICHER"
        color = "#00CC00"
        risk_level = "LOW"

    return {
        "score": ai_score,
        "status": status,
        "color": color,
        "details": sorted(details, key=lambda x: x[1], reverse=True),
        "highlighted_text": highlighted_text,
        "family_verification": family_verification,
        "risk_level": risk_level,
        "high_risk_indicators_count": high_risk_indicators,
        "keywords_found": {k: v for k, v in found.items() if v},
        "recommendation": _get_recommendation(risk_level, found),
        "ai_explanation": ai_explanation
    }


def _get_recommendation(risk_level: str, found: Dict) -> str:
    """Gibt klare Empfehlung basierend auf Risiko-Level"""
    if risk_level == "EXTREME":
        return "🚨 DIESE SMS SOFORT LÖSCHEN! Nicht anclicken, nicht antworten, von unbekannten Nummern blockieren!"
    elif risk_level == "CRITICAL":
        return "🚨 SEHR VERDÄCHTIG! Diese SMS wahrscheinlich Phishing/Betrug. Nicht interagieren!"
    elif risk_level == "HIGH":
        return "⚠️ VERDÄCHTIG! Nicht auf Links klicken, keine Daten mitteilen. Mit Familie/Bank kontaktieren zur Verifikation"
    elif risk_level == "MEDIUM":
        return "⚠️ WARNUNG: Diese SMS zeigt verdächtige Merkmale. Seien Sie vorsichtig!"
    else:
        return "✅ Diese SMS zeigt typischerweise keine Phishing-Merkmale, aber immer vorsichtig bleiben!"


# =====================================================
# TEST
# =====================================================

if __name__ == "__main__":
    test_cases = [
        "Glückwunsch! Sie haben einen GRATIS Gutschein gewonnen. Jetzt hier klicken!",
        "Hallo Mama! Mein Handy ist kaputt. Bitte überweise 500€ auf dieses Konto!",
        "Apple ID bestätigung erforderlich: Klicke hier www.apple-secure.fake",
        "Ihr Account wurde gehackt! Bestätigen Sie sofort Ihre Identität oder wird gelöscht!",
        "Herzlichen Glückwunsch! Sie haben 10000€ gewonnen. Geben Sie Ihre Bankdaten ein!",
        "Hi, bitte sende Bitcoins an 1A1z7agoat44GCstEZryQsKCvtSvkaEB - betrag: 0.5 BTC",
    ]
    
    print("=" * 80)
    print("SMS PHISHING SCANNER - TESTFÄLLE")
    print("=" * 80)
    
    for i, sms in enumerate(test_cases, 1):
        print(f"\n📱 TESTFALL {i}:")
        print(f"Text: {sms[:70]}...")
        result = scan_sms(sms)
        print(f"Score: {result['score']}/100")
        print(f"Status: {result['status']}")
        print(f"Risiko-Level: {result['risk_level']}")
        print(f"Empfehlung: {result['recommendation']}")
        if result['details'][:3]:
            print("Top Probleme:")
            for detail in result['details'][:3]:
                print(f"  - {detail[0]} ({detail[1]} Punkte)")

