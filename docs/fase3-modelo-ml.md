# Fase 3 — Módulo de detección basado en IA/ML

## Metodología

Se entrenó un modelo `IsolationForest` (detección de anomalías no supervisada)
exclusivamente con tráfico legítimo, siguiendo la metodología del documento:
el modelo nunca ve ejemplos de ataques durante el entrenamiento; su función
es aprender el patrón estadístico de "lo normal" y señalar después cualquier
petición que se desvíe de ese patrón.

## Recolección de datos

- Navegación manual real durante 20 minutos a través del proxy WAAP (puerto 8080).
- Se excluyó el tráfico de `/socket.io/` (ruido de fondo de la app, sin valor
  estadístico) del conjunto de entrenamiento.
- Total de muestras de tráfico normal: **36,073** peticiones.
- El endpoint más frecuente fue `/rest/products/search` (66,915 peticiones
  antes del filtro), debido al autocompletado de Juice Shop, que dispara una
  petición HTTP por cada letra escrita en el buscador.

## Características extraídas

Siguiendo el esquema del documento: `url_length`, `body_length`, `entropy`,
`n_params`, `has_suspicious_chars`, `req_per_minute`.

## Bugs encontrados y corregidos durante la implementación

1. **Regex de caracteres sospechosos incompleta**: la expresión original del
   documento (`\bOR\b\s+1=1`) no reconoce el patrón real usado en los ataques
   de la Fase 2 (`' OR '1'='1'`, con comillas). Se amplió la expresión regular
   para cubrir este patrón.
2. **Falta de decodificación URL**: el análisis de caracteres sospechosos se
   aplicaba sobre la URL codificada (ej. `%27` en vez de `'`), por lo que
   nunca coincidía con ningún payload real enviado codificado, como los
   usados en las pruebas de curl de la Fase 2. Se agregó decodificación
   (`urllib.parse.unquote`) antes de aplicar la expresión regular.

## Resultado de la prueba contra payloads de ataque

| Caso de prueba | Veredicto del modelo | Score de anomalía |
|---|---|---|
| Búsqueda normal ("apple") | NORMAL | 0.086 (correcto) |
| Login válido | **ANOMALÍA** (falso positivo) | -0.034 |
| SQLi básico (`' OR '1'='1`) | **NORMAL** (falso negativo) | 0.0002 |
| SQLi con comentarios | ANOMALÍA (correcto) | -0.004 |
| UNION SELECT | ANOMALÍA (correcto) | -0.016 |
| Evasión "0R" (evadió el WAF en Fase 2) | **NORMAL** (falso negativo) | 0.003 |
| XSS básico | ANOMALÍA (correcto) | -0.008 |

## Conclusión: limitaciones reales del modelo, no errores de metodología

Después de corregir ambos bugs de implementación, el modelo **sigue sin
detectar** el SQL Injection básico ni la evasión que burló al WAF en la
Fase 2, a pesar de que la característica `has_suspicious_chars` se calcula
correctamente (`= 1`) para ambos casos. Se confirmó mediante inspección
directa de las características extraídas que el problema no es de código,
sino del propio modelo: `IsolationForest` evalúa las 6 características de
forma conjunta, y una sola señal binaria entre 6 dimensiones no genera
suficiente distancia estadística para aislar el punto como anómalo cuando
el resto de valores (longitud de URL, entropía, número de parámetros) caen
dentro de rangos observados como normales durante el entrenamiento.

Este resultado es consistente con literatura de seguridad: modelos de
detección de anomalías con pocas características genéricas no sustituyen
de forma confiable a un motor de reglas maduro y especializado como
ModSecurity + OWASP CRS (Fase 2), que analiza la gramática del ataque
directamente en vez de depender de estadísticas generales de la petición.

### Sobre por qué no se ajustó el hiperparámetro `contamination`

Se consideró bajar el valor de `contamination` (de 0.02 a un valor menor)
para forzar que el modelo fuera más estricto y así detectar el SQLi de
prueba. Se decidió **no aplicar este ajuste** por una razón metodológica
importante: `contamination` mueve el umbral de decisión de forma global
para *todo* el tráfico, no de forma dirigida al caso de ataque específico.
Ajustarlo únicamente para que un caso de prueba conocido pase a
clasificarse como anomalía constituye sobreajuste a posteriori (sesgar el
modelo a los datos de evaluación en vez de mejorar su capacidad real de
generalización), y tiene un costo real: **aumentaría el riesgo de marcar
tráfico legítimo de usuarios reales como anómalo** (como ya ocurrió con el
caso del login válido), lo cual en un sistema de producción se traduciría
en bloquear o friccionar el acceso de usuarios genuinos — un daño directo
a la experiencia del usuario a cambio de una mejora cosmética y no
generalizable en las métricas de prueba.

## Trabajo futuro (fuera del alcance de este taller)

Para que un modelo de este tipo fuera competitivo frente al WAF de reglas,
se necesitarían: más características (n-gramas de caracteres, proporción
de símbolos especiales, análisis de la estructura del payload), un conjunto
de datos etiquetado con ejemplos reales de ataques (aprendizaje supervisado
en vez de solo detección de anomalías), y ajuste de hiperparámetros
mediante validación cruzada con métricas de precision/recall — no por
prueba y error sobre un único caso.
