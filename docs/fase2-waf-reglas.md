## Hallazgo adicional: evasión de detección vs. explotación funcional

Durante pruebas exploratorias posteriores (usando la app en el navegador,
no solo curl), se encontró un caso donde una variante del payload
(sustituyendo la letra `O` de `OR` por el dígito cero: `' 0R '1'='1`)
sí logró evadir la detección de `libinjection`, devolviendo un
`500 Internal Server Error` de SQLite en vez de un `403 Forbidden` del WAF.

Sin embargo, análisis posterior reveló que esto **no constituye una
explotación exitosa**: SQLite rechazó la cadena por el mismo motivo que
el WAF dejó de reconocerla — `0R` no es una palabra clave SQL válida.
El WAF no la bloqueó porque, gramaticalmente, ya no era una inyección SQL
real.

### Prueba de hipótesis

Para confirmar si el patrón detectado era específico a la palabra `OR` o
a la técnica de tautología en general, se probaron variantes adicionales
manteniendo sintaxis SQL 100% válida:

| Variante | Técnica | Resultado |
|---|---|---|
| `' 0R '1'='1` (con cero) | Tautología, sintaxis rota | **500** — evade el WAF, pero no es SQL válido (no explota) |
| `'\tOR\t'1'='1` (con TAB real) | Tautología, sintaxis válida | 403 — Bloqueado |
| `' UNION SELECT NULL,...--` | UNION-based, sintaxis válida | 403 — Bloqueado |
| `' AND 'x'='x` | Tautología con AND, sintaxis válida | 403 — Bloqueado |

**Conclusión**: `libinjection` (regla 942100) no depende de coincidencias
de texto superficiales, sino de un análisis gramatical de la cadena SQL.
Toda variante que preserva una estructura SQL válida con intención de
alterar la lógica de la consulta fue detectada, independientemente de la
ofuscación aplicada. La única forma encontrada de evadir la detección fue
degradar el payload hasta el punto de que dejara de ser SQL válido,
anulando también su capacidad de explotación.

Con este hallazgo, el conteo total de intentos de SQL Injection contra el
puerto 8080 asciende a 16 (15 bloqueados + 1 evasión de detección sin
explotación funcional), además de las 815 peticiones automatizadas de
sqlmap (ver `docs/fase2-sqlmap-resultado.txt`), todas bloqueadas.
