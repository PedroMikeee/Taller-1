# Fase 5 — Pipeline DevSecOps

## Objetivo

Construir un pipeline CI/CD que valide automáticamente el código de la
aplicación, sus dependencias, la imagen de contenedor, la configuración
de infraestructura y el comportamiento en ejecución, **antes** de
desplegar cualquier cambio a las reglas o a la política del WAAP.

## Diseño del pipeline (`.github/workflows/devsecops.yml`)

El job `security-gate` corre las puertas de seguridad en un único flujo
secuencial, de la más barata/rápida a la más costosa, para fallar rápido:

| # | Control | Herramienta | Qué protege en este repo |
|---|---|---|---|
| 1 | SAST | Semgrep (`p/owasp-top-ten`) | `app/app.py`, `app/rasp_agent.py` |
| 2 | SCA | pip-audit | `requirements.txt` |
| 3 | Build | `docker build` | Genera `taller-waap/app:<sha>` a partir de `app/Dockerfile` |
| 4 | Container scan | Trivy | La imagen recién construida |
| 5 | IaC scan | Checkov | `docker-compose.yml` y `app/Dockerfile` |
| 6 | Levantar entorno | `docker compose up -d` | `juice-shop` + `waap-proxy` (Fase 0) |
| 7 | DAST | OWASP ZAP baseline | `http://localhost:8080` (la app **ya protegida** por el WAAP de la Fase 2) |
| 8 | Despliegue | `scripts/deploy_waap_rules.sh` | Solo corre con `if: success()` — si cualquier paso anterior falla, GitHub Actions detiene el job y este paso nunca se ejecuta |

Con GitHub Actions no hace falta declarar manualmente que un paso
detiene al siguiente: por defecto, si un `step` termina con código de
salida distinto de cero, el job se marca en rojo y los pasos restantes
no se ejecutan (salvo que uses `continue-on-error: true`, que aquí no
se usa en ningún paso).

## Policy as code

`waap/policy/thresholds.yaml` versiona el `ANOMALY_THRESHOLD` y el
`contamination` del modelo de la Fase 3 (Umbral A, documentado ahí
mismo). El script `scripts/deploy_waap_rules.sh` lee este archivo y
reinicia `waap-proxy` para "aplicar" la política — cualquier cambio a
este YAML pasa primero por pull request y por las 7 puertas anteriores
del pipeline.

## Nota sobre dónde corre cada cosa

GitHub Actions ejecuta los runners en la nube de GitHub, no en tu VM.
Tu VM la necesitas para desarrollar y probar cada herramienta a mano
antes de subir el workflow (ver guía de la respuesta anterior), pero
una vez el `.yml` está en el repo, el pipeline corre solo con cada
`git push`.

---

## Pendiente por correr y documentar (entregable de la Fase 5)

Esto requiere ejecución real en tu repo de GitHub — no se puede generar
de antemano. Pasos:

1. **Push del workflow** y de todos los archivos nuevos (`app/Dockerfile`,
   `waap/policy/thresholds.yaml`, `scripts/deploy_waap_rules.sh`,
   `.github/workflows/devsecops.yml`) a tu repositorio.
2. **Captura del pipeline en verde**: entra a la pestaña *Actions* del
   repo y captura la ejecución completa con las 8 puertas en verde.
3. **Inyectar una vulnerabilidad deliberada**, por ejemplo:
   - Bajar la versión de una dependencia en `requirements.txt` a una
     con CVE público conocido (ej. una versión vieja de `Flask` o
     `Werkzeug`), para que lo detenga **pip-audit**; o
   - Volver a escribir `_build_login_query` en `app/app.py`
     concatenando el input directamente sin pasar por
     `rasp_guard_query`, para ver si **Semgrep** lo marca como SQL
     injection potencial.
4. **Capturar en qué etapa se detiene el pipeline** (rojo), con el log
   del error específico.
5. **Revertir el cambio** y confirmar que el pipeline vuelve a verde y
   llega hasta el paso de despliegue.

Cuando tengas esas capturas, las documentamos aquí junto con el
análisis (qué hubiera pasado en producción si esa etapa no existiera),
tal como se hizo en `docs/fase2-waf-reglas.md` y `docs/fase4-rasp.md`.
