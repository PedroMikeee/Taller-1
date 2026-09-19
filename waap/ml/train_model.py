# train_model.py - entrenamiento del modelo de deteccion de anomalias
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

df = pd.read_csv("logs/features_normal_traffic.csv")
X = df[["url_length", "body_length", "entropy", "n_params",
        "has_suspicious_chars", "req_per_minute"]].astype(float)

scaler = StandardScaler().fit(X)
X_scaled = scaler.transform(X)

model = IsolationForest(
    n_estimators=200, contamination=0.02, random_state=42
).fit(X_scaled)

joblib.dump(model, "waap/ml/isolation_forest_model.pkl")
joblib.dump(scaler, "waap/ml/scaler.pkl")

print(f"Modelo entrenado con {len(df)} muestras de trafico normal.")
print(f"Guardado: waap/ml/isolation_forest_model.pkl")
print(f"Guardado: waap/ml/scaler.pkl")
