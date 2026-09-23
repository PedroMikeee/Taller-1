# Fase 6 — Pruebas de efectividad y tecnicas de evasion

## Metodologia

Se consolidan resultados de las Fases 2 (WAF), 3 (IA/ML) y 4 (RASP), mas
5 pruebas adicionales necesarias para completar la matriz: SQLi clasico
y XSS contra RASP, codificacion URL contra RASP, rafaga de bot contra el
WAF, y SQLi fragmentado contra el modelo de IA/ML.

Nota metodologica importante: la "codificacion URL" es un concepto que
aplica de forma distinta segun la capa. El WAF inspecciona el texto HTTP
crudo tal como llega por la red, por lo que la codificacion si es
relevante para el. El RASP y el modelo de IA/ML, en cambio, operan sobre
valores ya procesados por el framework (Flask decodifica automaticamente
los parametros de query una sola vez), por lo que una codificacion simple
no representa una prueba distinta para ellos -- unicamente la doble
codificacion (que sobrevive a esa unica decodificacion automatica) genera
un caso de prueba genuinamente diferente en esas dos capas.

## Matriz de resultados

| Payload / tecnica | Bloqueado por reglas (Fase 2) | Detectado por IA/ML (Fase 3) | Bloqueado por RASP (Fase 4) |
|---|---|---|---|
| SQLi clasico `' OR '1'='1` | Si (regla 942100, libinjection) | No (score 0.0002, umbral -0.05) | No (patron RASP exige `OR 1=1` sin comillas) |
| SQLi con doble codificacion URL | Si (libinjection normaliza recursivamente) | No (el unico unquote() deja la comilla aun codificada) | No (Flask decodifica una sola vez; residuo de codificacion rompe el limite de palabra `\bUNION\b`) |
| SQLi fragmentado en 2 parametros | Si (proxy: HTTP Parameter Pollution, Fase 2) | No (score -0.0115, por encima del umbral) | Si (inspecciona la consulta ya reconstruida, Fase 4) |
| XSS reflejado basico | Si (motor de reglas 941) | Si (detectado como ANOMALIA) | No / N-A por diseno (el patron RASP solo cubre SQLi) |
| Rafaga de peticiones (bot) | No (100/100 peticiones pasaron sin bloqueo) | No (correlacion inversa: mas peticiones = score MAS normal) | N/A (sin caracteristica basada en tasa de peticiones) |

## Analisis escrito

### Que combinacion de capas ofrecio la mejor cobertura, y por que

Ninguna capa individual cubrio los 5 escenarios de forma completa, pero
la **combinacion WAF + RASP** ofrecio la cobertura mas solida de las tres
posibles combinaciones de a pares. El WAF de reglas fue, por si solo, la
capa mas efectiva de las tres (4 de 5 aciertos: fallo unicamente ante la
rafaga de bot), gracias a que `libinjection` analiza la gramatica SQL de
forma recursiva y normalizada, sin depender de que el payload llegue
"limpio". El RASP aporto una cobertura complementaria y no redundante en
el unico escenario donde el WAF depende de un proxy metodologico
imperfecto: el SQLi fragmentado en multiples parametros, donde el RASP
detecta el ataque en su forma final ya reconstruida dentro de la
aplicacion, un punto de visibilidad que el WAF perimetral no tiene por
diseno.

La capa de IA/ML, en cambio, resulto ser la menos efectiva de las tres en
esta implementacion: acerto unicamente en el escenario de XSS (1 de 5), y
mostro una limitacion particularmente seria en el caso de la rafaga de
bot, donde no solo no detecto el ataque, sino que su score se comporto de
forma inversa a la esperada (a mayor volumen de peticiones, el trafico se
veia "mas normal" para el modelo). Esto se debe a un problema de fondo ya
documentado en la Fase 3: el conjunto de entrenamiento estuvo dominado
por trafico de autocompletado de alta frecuencia, lo que enseno al modelo
a asociar rafagas de peticiones con normalidad en lugar de anomalia.

### Punto ciego compartido entre las tres capas

Es importante notar que ninguna de las tres capas, ni combinadas, cubre
la rafaga de peticiones tipo bot: el WAF no la bloqueo (su modulo de
proteccion DoS no se activo con este volumen/configuracion), el modelo de
IA/ML la clasifico como mas normal mientras mas intensa era, y el RASP no
tiene ninguna caracteristica relacionada con tasa de peticiones. Esto
representa una brecha de seguridad real en el sistema construido durante
este taller: un atacante que automatice peticiones en rafaga (por
ejemplo, para explotar fuerza bruta de credenciales o scraping masivo) no
encontraria resistencia en ninguna de las tres capas implementadas. Una
mitigacion real requeriria un componente dedicado de rate-limiting
(ausente en el alcance de este taller), independiente de las tres capas
evaluadas.

### Conclusion

La defensa en profundidad si demostro valor: en 4 de los 5 escenarios,
al menos una capa logro detener el ataque, y en el caso del SQLi
fragmentado, la combinacion de WAF+RASP cubrio lo que ninguna de las dos
por separado hubiera cubierto de forma completa. Sin embargo, la
evaluacion tambien expuso que "mas capas" no equivale automaticamente a
"mas seguridad" cuando las capas comparten la misma logica de deteccion
subyacente (como se vio con la palabra clave "OR" fallando de forma
identica en las tres capas ante variantes como "0R"), y que un vector de
ataque completamente distinto en naturaleza (volumetrico, no basado en
sintaxis) puede atravesar limpiamente un sistema diseñado principalmente
para detectar patrones de inyeccion.
