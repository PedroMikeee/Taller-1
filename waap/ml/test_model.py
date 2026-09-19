# test_model.py - prueba del modelo contra trafico normal y payloads de ataque
import re, math, joblib
from urllib.parse import unquote
import pandas as pd

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
    ("Normal - busqueda de producto",
     "/rest/products/search?q=apple", "", 133),
    ("Normal - login valido",
     "/rest/user/login", '{"email":"user@test.com","password":"abc123"}', 5),
    ("Ataque bloqueado - SQLi basico",
     "/rest/products/search?q=%27%20OR%20%271%27%3D%271", "", 5),
    ("Ataque bloqueado - comentarios SQL",
     "/rest/products/search?q=%27+OR%2f%2a%2a%2f1%3d1--", "", 5),
    ("Ataque bloqueado - UNION SELECT",
     "/rest/products/search?q=%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL--", "", 5),
    ("EVASION exitosa (0R) - no bloqueada por WAF",
     "/rest/products/search?q=%27%200R%20%271%27%3D%271", "", 5),
    ("Ataque bloqueado - XSS",
     "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "", 5),
]

model = joblib.load("waap/ml/isolation_forest_model.pkl")
scaler = joblib.load("waap/ml/scaler.pkl")

rows = []
for label, url, body, rpm in test_cases:
    feats = extract(url, body, rpm)
    rows.append({"label": label, **feats})

df = pd.DataFrame(rows)
X = df[["url_length", "body_length", "entropy", "n_params",
        "has_suspicious_chars", "req_per_minute"]].astype(float)
X_scaled = scaler.transform(X)

df["prediction"] = model.predict(X_scaled)
df["anomaly_score"] = model.decision_function(X_scaled)
df["veredicto"] = df["prediction"].map({1: "NORMAL", -1: "ANOMALIA"})

pd.set_option("display.max_colwidth", 40)
print(df[["label", "veredicto", "anomaly_score"]].to_string(index=False))

df.to_csv("logs/test_model_results.csv", index=False)
print("\nGuardado: logs/test_model_results.csv")
