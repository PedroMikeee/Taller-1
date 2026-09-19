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

## Punto 2 del documento: comparación de dos configuraciones de umbral

Se compararon dos valores de `ANOMALY_THRESHOLD` contra los mismos 10 casos:

- **Umbral A (-0.05)**: el sugerido como punto de partida por el documento.
- **Umbral B (-0.01285)**: calculado estadísticamente como el percentil 1
  de los scores de todo el tráfico normal de entrenamiento (36,073
  muestras) — es decir, el punto donde queda el 1% más atípico del propio
  tráfico legítimo.

| Petición | Tipo real | Score | Umbral A (-0.05) | Umbral B (-0.01285) |
|---|---|---|---|---|
| Búsqueda de producto | normal | 0.086 | NORMAL | NORMAL |
| Detalle de producto | normal | -0.034 | NORMAL | **ANOMALIA (FP)** |
| Login válido | normal | -0.034 | NORMAL | **ANOMALIA (FP)** |
| Ver carrito | normal | -0.049 | NORMAL | **ANOMALIA (FP)** |
| Whoami | normal | -0.024 | NORMAL | **ANOMALIA (FP)** |
| SQLi básico | ataque | 0.0002 | NORMAL | NORMAL |
| SQLi comentarios | ataque | -0.004 | NORMAL | NORMAL |
| UNION SELECT | ataque | -0.016 | NORMAL | **ANOMALIA (correcto)** |
| XSS | ataque | -0.008 | NORMAL | NORMAL |
| Evasión "0R" | ataque | 0.003 | NORMAL | NORMAL |

**Resultado**: Umbral A → 0/5 detección, 0/5 falsos positivos. Umbral B →
1/5 detección, **4/5 falsos positivos**.

### Causa raíz: desbalance en los datos de entrenamiento

El umbral B, calculado con un método estadístico válido, resultó
inutilizable en la práctica: marcó como anómalos 4 de 5 tipos de tráfico
legítimo distintos a la búsqueda de productos. Esto se explica por la
composición del tráfico de entrenamiento: como se documentó en la sección
de recolección de datos, el endpoint de búsqueda dominó abrumadoramente
el conjunto (66,915 de las peticiones capturadas, por el autocompletado
letra-por-letra), mientras que otros endpoints legítimos (detalle de
producto, login, carrito, whoami) tuvieron una representación mucho menor.
El modelo, en consecuencia, aprendió a considerar "buscar productos" como
prácticamente la única actividad normal, penalizando cualquier otro tipo
de interacción legítima con la tienda en cuanto se endurece el umbral.

## Punto 3 del documento: simulación de ráfaga de bot/automatización

Se simuló el mismo payload legítimo (`/rest/products/search?q=apple`)
variando únicamente `req_per_minute`, de 5 (usuario normal) hasta 2000
(bot extremo):

| Escenario | req/min | Score | Umbral A | Umbral B |
|---|---|---|---|---|
| Usuario normal | 5 | 0.081 | NORMAL | NORMAL |
| Usuario activo | 30 | 0.081 | NORMAL | NORMAL |
| Bot moderado | 100 | 0.086 | NORMAL | NORMAL |
| Bot agresivo | 500 | 0.092 | NORMAL | NORMAL |
| Bot extremo | 2000 | 0.101 | NORMAL | NORMAL |

**Hallazgo inesperado**: el score de anomalía **aumenta** (se vuelve más
"normal") a medida que `req_per_minute` crece, en vez de disminuir. Esto es
lo opuesto al comportamiento deseado de un detector de bots. La causa es
la misma que el hallazgo anterior: el tráfico de entrenamiento incluyó
ráfagas legítimas de alta frecuencia (hasta 133 peticiones/minuto, producto
del autocompletado), por lo que el modelo aprendió que un `req_per_minute`
alto es característico del tráfico normal observado, y no logra generalizar
que un volumen extremo (2000/min) es indicativo de automatización.

## Conclusión general de la Fase 3

Los tres hallazgos (baja tasa de detección de inyecciones, alta tasa de
falsos positivos al endurecer el umbral, e insensibilidad — incluso
inversa — a ráfagas de bot) apuntan a una misma causa raíz: el conjunto de
entrenamiento, aunque numeroso (36,073 muestras), está fuertemente
desbalanceado hacia un único patrón de tráfico (búsquedas de autocompletado),
lo cual limita severamente la capacidad del modelo para generalizar tanto
a otros tipos de tráfico legítimo como a tráfico malicioso. Un trabajo
futuro debería diversificar deliberadamente la recolección de tráfico
normal (asegurando representación balanceada de cada endpoint) antes de
considerar ajustes de umbral o de hiperparámetros.
