# measure_latency.py - compara latencia con y sin agente RASP activo
import time, statistics, requests, csv

N = 30  # peticiones por escenario (minimo 20 pedido por el documento)
BASE = "http://localhost:5000"

def medir(endpoint, params, n=N):
    tiempos = []
    for _ in range(n):
        t0 = time.perf_counter()
        requests.get(f"{BASE}{endpoint}", params=params)
        t1 = time.perf_counter()
        tiempos.append((t1 - t0) * 1000)  # ms
    return tiempos

escenarios = [
    ("CON RASP - login", "/login", {"username": "admin", "password": "1234"}),
    ("SIN RASP - login", "/login-norasp", {"username": "admin", "password": "1234"}),
    ("CON RASP - search", "/search", {"part1": "apple", "part2": "juice"}),
    ("SIN RASP - search", "/search-norasp", {"part1": "apple", "part2": "juice"}),
]

resultados = []
for nombre, endpoint, params in escenarios:
    tiempos = medir(endpoint, params)
    resultados.append({
        "escenario": nombre,
        "n_peticiones": len(tiempos),
        "latencia_media_ms": round(statistics.mean(tiempos), 3),
        "latencia_mediana_ms": round(statistics.median(tiempos), 3),
        "latencia_min_ms": round(min(tiempos), 3),
        "latencia_max_ms": round(max(tiempos), 3),
    })
    print(f"{nombre}: media={resultados[-1]['latencia_media_ms']}ms "
          f"mediana={resultados[-1]['latencia_mediana_ms']}ms")

with open("../logs/latencia_rasp.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(resultados[0].keys()))
    writer.writeheader()
    writer.writerows(resultados)

print("\nGuardado: logs/latencia_rasp.csv")
