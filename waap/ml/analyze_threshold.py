# analyze_threshold.py - analiza la distribucion de scores del trafico normal
import pandas as pd, joblib, numpy as np

bundle = joblib.load('waap/ml/model.pkl')
model, scaler = bundle['model'], bundle['scaler']

df = pd.read_csv("logs/features_normal_traffic.csv")
X = df[["url_length", "body_length", "entropy", "n_params",
        "has_suspicious_chars", "req_per_minute"]].astype(float)
X_scaled = scaler.transform(X)
scores = model.decision_function(X_scaled)

print("Distribucion de anomaly_score sobre TRAFICO NORMAL (entrenamiento):")
print(f"  Minimo:      {scores.min():.5f}")
print(f"  Percentil 1: {np.percentile(scores, 1):.5f}")
print(f"  Percentil 5: {np.percentile(scores, 5):.5f}")
print(f"  Mediana:     {np.median(scores):.5f}")
print(f"  Maximo:      {scores.max():.5f}")
