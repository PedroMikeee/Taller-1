#!/usr/bin/env bash
# deploy_waap_rules.sh
# Último paso del pipeline DevSecOps: solo se ejecuta si SAST, SCA,
# container scan, IaC scan y DAST pasaron. Aplica la política vigente
# (waap/policy/thresholds.yaml) y recarga el proxy WAAP.
set -euo pipefail

echo "=== Despliegue de reglas y política del WAAP ==="
echo "Política vigente (waap/policy/thresholds.yaml):"
cat waap/policy/thresholds.yaml

echo ""
echo "Recargando waap-proxy para tomar la configuración de OWASP CRS..."
if docker compose ps waap-proxy >/dev/null 2>&1; then
    docker compose restart waap-proxy
    echo "waap-proxy reiniciado correctamente."
else
    # Esperado en el runner de GitHub Actions: no hay entorno docker-compose
    # levantado de forma persistente fuera del job de DAST.
    echo "waap-proxy no está corriendo en este contexto (normal en el runner de CI)."
fi

echo "=== Despliegue completado ==="
