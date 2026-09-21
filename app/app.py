# app.py - mini aplicacion Flask objetivo para la Fase 4 (Agente RASP)
import logging, os
from flask import Flask, request, jsonify
from rasp_agent import rasp_guard_query

os.makedirs("../logs", exist_ok=True)
logging.basicConfig(
    filename="../logs/rasp.log",
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)

app = Flask(__name__)

# --- construccion de queries: version SIN decorar (logica compartida) ---
def _build_login_query(username, password):
    return f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"

def _build_search_query(part1, part2):
    return f"SELECT * FROM products WHERE name LIKE '%{part1}{part2}%'"

# --- version CON RASP activo ---
build_login_query_rasp = rasp_guard_query(_build_login_query)
build_search_query_rasp = rasp_guard_query(_build_search_query)


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    query = build_login_query_rasp(username, password)
    return jsonify({"status": "ok", "query_simulada": query})

@app.route("/login-norasp")
def login_norasp():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    query = _build_login_query(username, password)
    return jsonify({"status": "ok", "query_simulada": query})

@app.route("/search")
def search():
    part1 = request.args.get("part1", "")
    part2 = request.args.get("part2", "")
    query = build_search_query_rasp(part1, part2)
    return jsonify({"status": "ok", "query_simulada": query})

@app.route("/search-norasp")
def search_norasp():
    part1 = request.args.get("part1", "")
    part2 = request.args.get("part2", "")
    query = _build_search_query(part1, part2)
    return jsonify({"status": "ok", "query_simulada": query})


if __name__ == "__main__":
    # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
    # Riesgo aceptado y documentado: host="0.0.0.0" es necesario para que el
    # contenedor Docker sea alcanzable desde fuera de si mismo (mapeo de
    # puertos). La exposicion real se mitiga por el aislamiento de red de
    # Docker en este entorno de laboratorio. Ver docs/fase5-devsecops.md.
    app.run(host="0.0.0.0", port=5000)
