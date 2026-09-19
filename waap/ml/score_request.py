# score_request.py - inferencia sobre una peticion entrante
import joblib, pandas as pd

bundle = joblib.load('waap/ml/model.pkl')
model, scaler = bundle['model'], bundle['scaler']

def score(features: dict) -> float:
    X = pd.DataFrame([features])
    X_scaled = scaler.transform(X)
    # decision_function: valores negativos => mas anomalo
    return float(model.decision_function(X_scaled)[0])

ANOMALY_THRESHOLD = -0.05

def is_anomalous(features: dict) -> bool:
    return score(features) < ANOMALY_THRESHOLD
