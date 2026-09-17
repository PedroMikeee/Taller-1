## Verificación adicional: prueba directa contra el puerto 3000

Después de que ninguna de las 12 técnicas de evasión documentadas arriba
lograra pasar el motor de reglas en el puerto 8080, surgió una duda
razonable: ¿la robustez observada se debe a que el WAF es efectivo, o a que
el payload de prueba dejó de ser una inyección SQL real después de tantas
variaciones? Para descartar esta posibilidad, se decidió repetir el payload
base de SQLi directamente contra el puerto 3000 (Juice Shop sin el proxy
WAAP de por medio), como prueba de control.

| Payload | Puerto 3000 (Juice Shop directo, sin WAF) | Puerto 8080 (vía proxy WAAP) |
|---|---|---|
| `' OR '1'='1` | **200 OK.** La respuesta devuelve el catálogo completo de productos (58 ítems) en vez de un resultado de búsqueda filtrado, confirmando que la condición `OR '1'='1'` se interpretó como una tautología SQL real y that la vulnerabilidad de inyección sigue presente en la aplicación. | **403 Forbidden**, bloqueado por la regla 942100 (libinjection). |

Este resultado confirma que:
1. La vulnerabilidad de SQL Injection en Juice Shop es real y explotable
   cuando no hay ninguna capa de protección delante (puerto 3000).
2. La robustez observada en los 12 intentos de evasión contra el puerto
   8080 no se debe a que el payload haya dejado de ser un ataque válido,
   sino a que el motor de reglas (ModSecurity + CRS, PL1) efectivamente
   lo está deteniendo en todos los casos probados.


## Nota sobre el log de auditoría

El documento original sugiere `tail -f /var/log/modsec_audit.log` para
revisar el log de auditoría en tiempo real. Se verificó que esa ruta no
existe en la imagen `owasp/modsecurity-crs:nginx` utilizada (confirmado con
`find / -iname "*audit*log*"`, sin resultados). Esta imagen envía los logs
de ModSecurity a la salida estándar del contenedor en su lugar. El comando
equivalente utilizado fue:

    docker compose logs -f waap-proxy

El volcado completo de estos logs se encuentra en `docs/fase2-logs-completos.txt`.
