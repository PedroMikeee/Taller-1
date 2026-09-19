# matrix_evaluation.py - matriz de evaluacion con 10 peticiones (5 normales, 5 de ataque)
import re, math
from urllib.parse import unquote
import pandas as pd
from score_request import score, is_anomalous, ANOMALY_THRESHOLD

SUSPICIOUS = re.compile(
    r"(--|;|<script|\.\./|\bUNION\b|'\s*(OR|AND)\s*'|\bOR\b\s+1=1|\bOR\b\s+'1'\s*=\s*'1')",
    re.I,
)

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract(url, body="", req_per_minute=5):
    decoded = unquote(url) + unquote(body)
    return {
        "url_length": len(url),
        "body_length": len(body),
        "entropy": round(shannon_entropy(url + body), 4),
        "n_params": url.count("&") + 1 if "?" in url else 0,
        "has_suspicious_chars": int(bool(SUSPICIOUS.search(decoded))),
        "req_per_minute": req_per_minute,
    }

test_cases = [
    # (label, tipo_esperado, url, body, req_per_minute)
    ("Normal - busqueda de producto", "normal",
     "/rest/products/search?q=apple", "", 133),
    ("Normal - detalle de producto", "normal",
     "/rest/products/1", "", 8),
    ("Normal - login valido", "normal",
     "/rest/user/login", '{"email":"user@test.com","password":"abc123"}', 5),
    ("Normal - ver carrito", "normal",
     "/rest/basket/1", "", 6),
    ("Normal - whoami", "normal",
     "/rest/user/whoami", "", 10),
    ("Ataque - SQLi basico", "ataque",
     "/rest/products/search?q=%27%20OR%20%271%27%3D%271", "", 5),
    ("Ataque - SQLi comentarios", "ataque",
     "/rest/products/search?q=%27+OR%2f%2a%2a%2f1%3d1--", "", 5),
    ("Ataque - UNION SELECT", "ataque",
     "/rest/products/search?q=%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL--", "", 5),
    ("Ataque - XSS", "ataque",
     "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", 5),
    ("Evasion - 0R (burlo el WAF en Fase 2)", "ataque",
     "/rest/products/search?q=%27%200R%20%271%27%3D%271", "", 5),
]

rows = []
for label, tipo, url, body, rpm in test_cases:
    feats = extract(url, body, rpm)
    s = score(feats)
    anomalo = is_anomalous(feats)
    rows.append({
        "peticion": label,
        "tipo_real": tipo,
        "anomaly_score": round(s, 5),
        "es_anomalo": anomalo,
        "veredicto": "ANOMALIA" if anomalo else "NORMAL",
    })

df = pd.DataFrame(rows)
print(f"Umbral usado (ANOMALY_THRESHOLD): {ANOMALY_THRESHOLD}\n")
pd.set_option("display.max_colwidth", 45)
print(df[["peticion", "tipo_real", "anomaly_score", "veredicto"]].to_string(index=False))

# metricas
ataques = df[df["tipo_real"] == "ataque"]
normales = df[df["tipo_real"] == "normal"]
verdaderos_positivos = (ataques["es_anomalo"] == True).sum()
falsos_negativos = (ataques["es_anomalo"] == False).sum()
falsos_positivos = (normales["es_anomalo"] == True).sum()
verdaderos_negativos = (normales["es_anomalo"] == False).sum()

print(f"\nVerdaderos positivos (ataques detectados): {verdaderos_positivos}/5")
print(f"Falsos negativos (ataques NO detectados):   {falsos_negativos}/5")
print(f"Falsos positivos (normales mal marcados):   {falsos_positivos}/5")
print(f"Verdaderos negativos (normales OK):         {verdaderos_negativos}/5")

df.to_csv("logs/matrix_evaluacion_fase3.csv", index=False)
print("\nGuardado: logs/matrix_evaluacion_fase3.csv")
