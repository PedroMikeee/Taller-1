# compare_thresholds.py - compara 2 configuraciones de ANOMALY_THRESHOLD
import re, math
from urllib.parse import unquote
import pandas as pd, joblib

bundle = joblib.load('waap/ml/model.pkl')
model, scaler = bundle['model'], bundle['scaler']

def score(features):
    X = pd.DataFrame([features])
    return float(model.decision_function(scaler.transform(X))[0])

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
        "url_length": len(url), "body_length": len(body),
        "entropy": round(shannon_entropy(url + body), 4),
        "n_params": url.count("&") + 1 if "?" in url else 0,
        "has_suspicious_chars": int(bool(SUSPICIOUS.search(decoded))),
        "req_per_minute": req_per_minute,
    }

test_cases = [
    ("Normal - busqueda de producto", "normal", "/rest/products/search?q=apple", "", 133),
    ("Normal - detalle de producto", "normal", "/rest/products/1", "", 8),
    ("Normal - login valido", "normal", "/rest/user/login", '{"email":"user@test.com","password":"abc123"}', 5),
    ("Normal - ver carrito", "normal", "/rest/basket/1", "", 6),
    ("Normal - whoami", "normal", "/rest/user/whoami", "", 10),
    ("Ataque - SQLi basico", "ataque", "/rest/products/search?q=%27%20OR%20%271%27%3D%271", "", 5),
    ("Ataque - SQLi comentarios", "ataque", "/rest/products/search?q=%27+OR%2f%2a%2a%2f1%3d1--", "", 5),
    ("Ataque - UNION SELECT", "ataque", "/rest/products/search?q=%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL--", "", 5),
    ("Ataque - XSS", "ataque", "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", 5),
    ("Evasion - 0R (burlo el WAF)", "ataque", "/rest/products/search?q=%27%200R%20%271%27%3D%271", "", 5),
]

THRESHOLD_A = -0.05      # sugerido por el documento
THRESHOLD_B = -0.01285   # percentil 1 del trafico normal de entrenamiento

rows = []
for label, tipo, url, body, rpm in test_cases:
    s = score(extract(url, body, rpm))
    rows.append({
        "peticion": label, "tipo_real": tipo, "score": round(s, 5),
        f"veredicto_A({THRESHOLD_A})": "ANOMALIA" if s < THRESHOLD_A else "NORMAL",
        f"veredicto_B({THRESHOLD_B})": "ANOMALIA" if s < THRESHOLD_B else "NORMAL",
    })

df = pd.DataFrame(rows)
pd.set_option("display.max_colwidth", 45)
print(df.to_string(index=False))

for col, thr in [(f"veredicto_A({THRESHOLD_A})", THRESHOLD_A), (f"veredicto_B({THRESHOLD_B})", THRESHOLD_B)]:
    ataques = df[df["tipo_real"] == "ataque"]
    normales = df[df["tipo_real"] == "normal"]
    vp = (ataques[col] == "ANOMALIA").sum()
    fp = (normales[col] == "ANOMALIA").sum()
    print(f"\nUmbral {thr}: {vp}/5 ataques detectados, {fp}/5 falsos positivos")

df.to_csv("logs/comparacion_umbrales_fase3.csv", index=False)
print("\nGuardado: logs/comparacion_umbrales_fase3.csv")
