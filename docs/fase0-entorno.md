# Fase 0 — Preparación del entorno

## Entregable: evidencia de contenedores en ejecución y acceso vía WAAP

Entorno desplegado con `docker-compose.yml`, dos servicios:
- `juice-shop`: aplicación objetivo vulnerable (puerto 3000).
- `waap-proxy`: proxy WAAP con ModSecurity + OWASP CRS (puerto 8080).

Evidencia de ambos contenedores corriendo (`docker compose ps`), estado
`Up`, ver `docs/evidencias/fase0/docker-compose-ps.png`.

Acceso confirmado a la aplicación objetivo a través del proxy WAAP en
`http://localhost:8080`, verificado en la Fase 1 y usado como punto de
entrada principal en las fases posteriores (ver comparación con acceso
directo sin protección, puerto 3000, documentada en `docs/fase2-waf-reglas.md`).

## Notas de instalación relevantes

- Docker Engine y Docker Compose instalados desde el repositorio oficial
  de Docker (repo apuntado a `noble`, ya que la codename `resolute` del
  sistema aún no tenía paquetes publicados por Docker al momento de la
  instalación).
- Verificado que el entorno sobrevive correctamente a actualizaciones de
  kernel del sistema anfitrión (probado tras una actualización real).
