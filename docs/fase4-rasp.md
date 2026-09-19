# Fase 4 — Integración RASP (Runtime Application Self-Protection)

## Diseño del agente

Se implementó `app/rasp_agent.py` tal como especifica el documento: un
decorador (`rasp_guard_query`) que envuelve funciones constructoras de
consultas SQL, inspeccionando la consulta final ya concatenada en
tiempo de ejecución (después de cualquier decodificación previa), a
diferencia del WAF, que inspecciona la petición HTTP entrante.

Se construyó una mini aplicación Flask propia (`app/app.py`, puerto 5000)
con dos endpoints funcionales por escenario (con y sin RASP, compartiendo
la misma lógica interna), para permitir comparaciones directas sin
necesidad de reiniciar el servidor.

## Prueba 1: ataque fragmentado en múltiples parámetros

Se envió un payload de UNION SELECT partido deliberadamente en dos
parámetros (part1="' UNI", part2="ON SELECT NULL--"), de forma que
ninguno de los dos, por separado, contiene la palabra completa UNION.

Resultado: bloqueado exitosamente (403). El log confirma la deteccion
con el mensaje: "RASP: consulta SQL bloqueada en tiempo de ejecucion:
SELECT * FROM products WHERE name LIKE '%' UNION SELECT NULL--%'"

Esto demuestra la ventaja conceptual del RASP frente al WAF: al inspeccionar
la cadena ya reconstruida dentro de la aplicación, detecta ataques que
dependen de fragmentar el payload entre múltiples parámetros de entrada.

## Prueba 2: repetir la evasión "0R" de la Fase 2

Se repitió el mismo payload que evadió la detección del motor de reglas
en la Fase 2 (' 0R '1'='1, sustituyendo la letra O por el digito cero)
directamente contra /login.

Resultado: NO detectado (200 OK). El RASP dejo pasar la consulta sin
bloquearla: SELECT * FROM users WHERE user='' 0R '1'='1' AND pass='x'

### Nota metodológica importante

Como ya se documentó en la Fase 2, "0R" (con cero) no es SQL valido;
por lo tanto esta prueba no representa una explotación funcional real, sino
una verificación de si las distintas capas de defensa comparten el mismo
punto ciego. El resultado confirma que si lo comparten: tanto el WAF
de reglas (Fase 2), el modelo de IA/ML (Fase 3, caracteristica
has_suspicious_chars con la misma limitacion de regex) y ahora el RASP,
fallan ante esta variante especifica porque los tres dependen, en algun
punto, de reconocer la palabra literal "OR". Es un hallazgo de valor: la
defensa en profundidad no es automaticamente inmune a debilidades
compartidas entre capas si estas usan logica de deteccion similar.

## Prueba 3: impacto en latencia (30 peticiones por escenario)

| Escenario | Latencia media (ms) | Latencia mediana (ms) |
|---|---|---|
| CON RASP - login | 2.523 | 2.389 |
| SIN RASP - login | 2.444 | 2.429 |
| CON RASP - search | 2.433 | 2.405 |
| SIN RASP - search | 2.467 | 2.395 |

Conclusion: la diferencia de latencia entre tener el RASP activo o no
es estadisticamente insignificante (diferencias de centesimas de
milisegundo, dentro del margen de ruido de medicion - en el caso de login,
la variante SIN RASP incluso salio marginalmente mas lenta). Esto es
esperable: el agente solo ejecuta una busqueda de expresion regular sobre
una cadena corta, una operacion de costo computacional practicamente
despreciable frente a la latencia de red y procesamiento HTTP general.

## Conclusión general de la Fase 4

El RASP demostro ser efectivo contra ataques fragmentados que dependen de
dividir el payload entre multiples parametros (ventaja real sobre el WAF
perimetral), con un costo de rendimiento practicamente nulo. Sin embargo,
comparte la misma limitacion de las capas anteriores frente a evasiones
que rompen la coincidencia literal de palabras clave (caso "0R"),
reforzando la conclusion de que ninguna capa individual -ni siquiera en
conjunto, cuando comparten logica de deteccion similar- garantiza
proteccion absoluta.
