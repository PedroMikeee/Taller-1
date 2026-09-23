# consolidate_logs.py - centraliza eventos de las 3 capas (WAF, IA/ML, RASP)
# en un unico flujo JSON estructurado, con MTTD simulado por capa.
import json, re
from datetime import datetime

events = []

# ---------- Capa 1: WAF (Fase 2) ----------
# Eventos extraidos de docs/fase2-logs-completos.txt (bloqueos reales de ModSecurity)
waf_events = [
    {"payload": "' OR '1'='1", "endpoint": "/rest/products/search",
     "verdict": "BLOQUEADO", "rule_id": "942100", "mttd_ms": 3},
    {"payload": "' OR/**/1=1--", "endpoint": "/rest/products/search",
     "verdict": "BLOQUEADO", "rule_id": "942100", "mttd_ms": 3},
    {"payload": "<script>alert(1)</script>", "endpoint": "/rest/products/search",
     "verdict": "BLOQUEADO", "rule_id": "941xxx", "mttd_ms": 3},
    {"payload": "' 0R '1'='1", "endpoint": "/rest/products/search",
     "verdict": "NO_DETECTADO", "rule_id": None, "mttd_ms": None},
]
for e in waf_events:
    events.append({
        "timestamp": datetime.utcnow().isoformat(),
        "capa": "WAF",
        "payload": e["payload"],
        "endpoint": e["endpoint"],
        "veredicto": e["verdict"],
        "detalle": {"rule_id": e["rule_id"]},
        "mttd_ms_simulado": e["mttd_ms"],
    })

# ---------- Capa 2: IA/ML (Fase 3) ----------
# Nota: el modelo NO esta conectado al flujo de trafico en vivo, se ejecuta
# como script batch (score_request.py). El MTTD simulado asume un intervalo
# de ejecucion periodica de 5 minutos (300000 ms), no deteccion instantanea.
ml_events = [
    {"payload": "' OR '1'='1", "verdict": "NORMAL (no detectado)", "score": 0.00015},
    {"payload": "' UNION SELECT NULL...", "verdict": "ANOMALIA (detectado)", "score": -0.01555},
    {"payload": "<script>alert(1)</script>", "verdict": "ANOMALIA (detectado)", "score": -0.00751},
]
for e in ml_events:
    detectado = "ANOMALIA" in e["verdict"]
    events.append({
        "timestamp": datetime.utcnow().isoformat(),
        "capa": "IA/ML",
        "payload": e["payload"],
        "endpoint": "/rest/products/search",
        "veredicto": e["verdict"],
        "detalle": {"anomaly_score": e["score"], "threshold": -0.05},
        "mttd_ms_simulado": 300000 if detectado else None,
    })

# ---------- Capa 3: RASP (Fase 4) ----------
rasp_events = [
    {"payload": "' UNI...ON SELECT (fragmentado)", "verdict": "BLOQUEADO", "mttd_ms": 2},
    {"payload": "' OR '1'='1", "verdict": "NO_DETECTADO", "mttd_ms": None},
    {"payload": "' 0R '1'='1", "verdict": "NO_DETECTADO", "mttd_ms": None},
]
for e in rasp_events:
    events.append({
        "timestamp": datetime.utcnow().isoformat(),
        "capa": "RASP",
        "payload": e["payload"],
        "endpoint": "/search o /login (app propia)",
        "veredicto": e["verdict"],
        "detalle": {},
        "mttd_ms_simulado": e["mttd_ms"],
    })

with open("logs/eventos_consolidados.json", "w") as f:
    json.dump(events, f, indent=2, ensure_ascii=False)

print(f"Guardado: logs/eventos_consolidados.json ({len(events)} eventos)")
