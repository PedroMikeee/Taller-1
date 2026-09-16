# Fase 1 — Línea base de vulnerabilidades (Juice Shop)

Entregable de la Fase 1: registro de las vulnerabilidades seleccionadas como
línea base para ser explotadas en las Fases 3 a 6 del taller.

| # | Reto (Score Board)   | Categoría OWASP Top 10          | Endpoint específico                  |
|---|-----------------------|----------------------------------|---------------------------------------|
| 1 | Login Admin           | Injection (SQL Injection)       | `POST /rest/user/login`               |
| 2 | DOM XSS               | Cross-Site Scripting (XSS)      | `GET /#/search?q=`                    |
| 3 | Admin Section         | Broken Access Control           | `GET /#/administration`               |
| 4 | Web3 Sandbox          | Improper Input Validation       | Sandbox de contratos expuesto         |
| 5 | Exposed Credentials   | Sensitive Data Exposure         | Código fuente cliente (`main.*.js`)   |

## Notas

- El reto **Login Admin** (SQL Injection) se usa como caso base para probar
  el motor de reglas WAF en la Fase 2, con el payload clásico `' OR '1'='1`.
- Entorno desplegado según `docker-compose.yml` (Fase 0): Juice Shop en el
  puerto 3000, proxy WAAP (ModSecurity + OWASP CRS) en el puerto 8080.
