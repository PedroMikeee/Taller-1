# simulate_bot.py - simula una rafaga de peticiones tipo bot y evalua req_per_minute
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

# Misma peticion (busqueda legitima de "apple"), variando SOLO req_per_minute
# para simular un bot que hace la misma consulta en rafaga
escenarios = [
    ("Usuario normal (5 req/min)", 5),
    ("Usuario activo (30 req/min)", 30),
    ("Bot moderado (100 req/min)", 100),
    ("Bot agresivo (500 req/min)", 500),
    ("Bot extremo (2000 req/min)", 2000),
]

THRESHOLD_A = -0.05
THRESHOLD_B = -0.01285

rows = []
for label, rpm in escenarios:
    s = score(extract("/rest/products/search?q=apple", "", rpm))
    rows.append({
        "escenario": label, "req_per_minute": rpm, "score": round(s, 5),
        "veredicto_A": "ANOMALIA" if s < THRESHOLD_A else "NORMAL",
        "veredicto_B": "ANOMALIA" if s < THRESHOLD_B else "NORMAL",
    })

df = pd.DataFrame(rows)
print(df.to_string(index=False))
df.to_csv("logs/simulacion_bot_fase3.csv", index=False)
print("\nGuardado: logs/simulacion_bot_fase3.csv")
