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

## Bitacora real de ejecucion del pipeline

El pipeline requirio varias iteraciones reales de correccion antes de
lograr una linea base verde, cada una con un hallazgo legitimo:

| # | Hallazgo | Etapa que lo detecto | Correccion aplicada |
|---|---|---|---|
| 1 | Contenedor corriendo como root | Semgrep (SAST) | Usuario no-root en Dockerfile |
| 2 | `host="0.0.0.0"` en Flask | Semgrep (SAST) | Riesgo aceptado y documentado (`nosemgrep`), necesario para networking de Docker |
| 3 | requirements.txt de la raiz (con librerias de ML) incompatible con Python 3.11 | Build de Docker | requirements.txt propio y liviano para `app/` |
| 4 | 44 CVEs HIGH en el SO base (Debian/slim) | Trivy (container scan) | Cambio de imagen base a Alpine (0 CVEs de SO) |
| 5 | 2 CVEs en paquetes internos de pip (msgpack, setuptools vendidos) | Trivy | Riesgo aceptado y documentado (`.trivyignore`) |
| 6 | Falta `HEALTHCHECK` en el Dockerfile | Checkov (IaC scan) | Se agrego HEALTHCHECK |
| 7 | Permisos `write-all` implicitos en el workflow | Checkov | `permissions: contents: read` explicito |
| 8 | ZAP sin permiso para publicar su reporte (issue) | DAST (ZAP) | `permissions: issues: write` agregado |
| 9 | Bug conocido de `zaproxy/action-baseline` en la subida de artifacts | DAST (ZAP) | Reemplazo por invocacion directa de Docker |
| 10 | `zap-baseline.py` falla el pipeline por advertencias menores (no solo fallos criticos) | DAST (ZAP) | Flag `-I` agregada |

Cada uno de estos hallazgos, aunque no formaban parte del plan original,
representa exactamente el tipo de problema que un pipeline DevSecOps real
esta diseñado para exponer: configuraciones inseguras, incompatibilidades
de entorno, y practicas de menor rigor que pasan desapercibidas sin
automatizacion.

## Ejercicio de verificacion del pipeline (segun especificacion del documento)

### Paso 1: linea base verde
Lograda tras las 10 correcciones de la tabla anterior.
Evidencia: `docs/evidencias/fase5/historial-pipeline-verde.png` y
`docs/evidencias/fase5/linea-base-verde-detalle.png`.

### Paso 2: vulnerabilidad inyectada deliberadamente
Se downgradeo `app/requirements.txt` a `flask==2.2.0`, con 4
vulnerabilidades publicas conocidas (PYSEC-2023-62, PYSEC-2026-2151).

**Hallazgo inesperado durante el ejercicio**: la vulnerabilidad NO fue
detenida en la etapa esperada (SCA - pip-audit) en el primer intento,
sino en una etapa posterior (Trivy, container scan). La causa: el paso
de pip-audit auditaba unicamente el `requirements.txt` de la raiz del
repositorio, no el `app/requirements.txt` propio de esta aplicacion -- un
punto ciego real en la configuracion del pipeline. Esto demuestra que,
aun cuando una capa especifica falla en su cobertura, el pipeline en su
conjunto (defensa en profundidad) sigue deteniendo la vulnerabilidad por
otra via.

Se corrigio el punto ciego (agregando `pip-audit -r app/requirements.txt`
al workflow) y se repitio la prueba: esta vez la vulnerabilidad fue
detenida correctamente en la etapa esperada, SCA - pip-audit, mostrando
las 4 vulnerabilidades de Flask 2.2.0 con detalle completo.

Evidencia: `docs/evidencias/fase5/vulnerabilidad-detenida-pip-audit.png`.

### Paso 3: revertir y confirmar linea verde
Se revirtio `app/requirements.txt` a `flask>=3.0`. El pipeline volvio a
completar las 8 etapas exitosamente, incluyendo el despliegue final de
reglas del WAAP.

Evidencia: `docs/evidencias/fase5/pipeline-verde-tras-revertir.png`.

## Conclusion de la Fase 5

Mas alla de cumplir el entregable formal (evidencia de bloqueo +
evidencia de exito), el proceso real de puesta en marcha de este pipeline
expuso 10 problemas de configuracion genuinos que no habian sido
detectados manualmente en fases anteriores, validando el valor practico
de automatizar estas verificaciones en cada cambio de codigo.
