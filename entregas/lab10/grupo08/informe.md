# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

> **Nota de armado.** La entrega se divide en 3 partes:
> - **Parte 1** (R1 Blue + R2 Red) — *completa en este commit.*
> - **Parte 2** (R3 Blue + R4 Red + fila `sqli-union` de la tabla) — pendiente.
> - **Parte 3** (R5 + preguntas P1–P5 + `research.md`) — pendiente.

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en la Parte 1: levantar el entorno monitoreado, acceder a la vista del SOC (R1, Blue) y provocar una detección por User-Agent de scanner leyendo la alerta del IDS (R2, Red); borrador de la redacción de esas secciones, evidencias y fila `scanner-ua` de la tabla de firmas. | `informe.md`: sección 1 (flags R1–R2), sección 2.1 y 2.2, fila `scanner-ua` de la tabla de firmas y bloque de la Parte 1 de la bitácora. | Las salidas pegadas corresponden a la ejecución real del entorno (`make lab N=10`, `docker exec cyberlab-attacker curl ...`). Las flags `FLAG{soc_log_access}` y `FLAG{detection_triggered}` se validaron contra el evaluador con `./ctf submit 10 R1/R2` (progreso 2/5). El grupo revisó técnicamente el contenido y comprende las implicancias de detección y evasión. |

> Las Partes 2 y 3 completarán esta tabla con sus propias filas al sumar su trabajo.

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas (salida de `./ctf status 10`)

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 10                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Acceso a la vista del SOC
   ✓  R2     Disparar una deteccion (te vieron)
   ·  R3     Conocer el ruleset del IDS
   ·  R4     Evadir una firma de deteccion
   ·  R5     Encontrar la intrusion en el ruido

  ████████████░░░░░░░░░░░░░░░░░░  2/5 (40%)
```

> Estado al cierre de la Parte 1. R3–R5 los completan las Partes 2 y 3.

---

## 2. Detección y evasión — evidencias

| Reto | Cara | Qué se hizo | Comando | Evidencia | Lectura defensiva |
|---|---|---|---|---|---|
| R1 | Blue | Acceder a la vista del SOC (consola de eventos). | `curl -s http://phantomcorp/soc` | `FLAG{soc_log_access}` | El SOC es el punto de partida del defensor: toda actividad queda registrada ahí. |
| R2 | Red | Provocar una detección con User-Agent de scanner y **leer la alerta** que la delató. | `curl -s -A sqlmap http://phantomcorp/` | 403 · `ALERTA IDS · firma 'scanner-ua'` → `FLAG{detection_triggered}` | La alerta nombra **qué firma** disparó: para el defensor es un evento; para el atacante, un mapa de qué esquivar. |

### 2.1 R1 (Blue) — Acceso a la vista del SOC

PhantomCorp expone la consola del SOC en `/soc`. Esta ruta **no** se inspecciona como ataque: es la vista del defensor sobre el tráfico. Acceder a ella es el primer paso del análisis.

```console
$ docker exec cyberlab-attacker curl -s http://phantomcorp/soc | head -5
=== PhantomCorp SOC · vista de eventos ===
Acceso a la consola del SOC concedido. FLAG{soc_log_access}
Tip: filtrá por ALERT. Hay UNA intrusion real que no disparaste vos.
------------------------------------------------------------
10.0.1.21 - GET /catalogo?item=1 200 BENIGN
```

El encabezado confirma el acceso y entrega `FLAG{soc_log_access}`. El log mezcla ~120 líneas de tráfico benigno con alertas; el análisis fino (la intrusión del R5) queda para la Parte 3.

### 2.2 R2 (Red) — Disparar una detección y leer la alerta

Del lado rojo, lo más fácil de delatar es la **identidad declarada**: la User-Agent. El IDS tiene la firma `scanner-ua` que matchea `sqlmap|nikto|nmap|dirb`. Un simple request anunciándose como `sqlmap` ya dispara la alerta.

```console
$ docker exec cyberlab-attacker curl -s -A sqlmap http://phantomcorp/
🚨 ALERTA IDS · firma 'scanner-ua' disparada.
Tu request fue DETECTADA y logueada. FLAG{detection_triggered}
Para ver todas las reglas: GET /soc/reglas
```

Respuesta **403** + `FLAG{detection_triggered}`. La alerta dice explícitamente qué firma disparó (`scanner-ua`) y hacia dónde seguir (`/soc/reglas`, que es el R3 de la Parte 2). Clave: el IDS detectó **quién decís ser**, no **qué hacés** — esa es justamente la debilidad que la fila `scanner-ua` de la tabla analiza, y la base de la evasión.

---

## 3. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| scanner-ua | La firma mira sólo el header `User-Agent` contra una lista fija (`sqlmap\|nikto\|nmap\|dirb`). Se evade **cambiando la UA** por la de un navegador legítimo (`curl -A "Mozilla/5.0 ..."`): el mismo scan pasa desapercibido porque la firma inspecciona *quién decís ser*, no *qué hacés*. | No confiar en la identidad autodeclarada. Correlacionar **comportamiento**: tasa de requests por IP, cantidad de 404/403 en ráfaga, recorrido de rutas no enlazadas, timing automático. Un escaneo se delata por su *patrón*, no por su etiqueta. (Detalle y PoC de evasión → Parte 2.) |
| sqli-union | *(Parte 2 — R4.)* | *(Parte 2 — R4.)* |

---

## 4. Preguntas P1–P5

*(Parte 3 — se responden junto con el R5 y el `research.md`.)*

- **P1.** ¿Por qué la detección por firmas es evadible por diseño? ¿Qué la complementa? — *pendiente.*
- **P2.** Reescribir la regla `sqli-union` para que no se evada con `/**/`. ¿Se puede una firma "perfecta"? — *pendiente.*
- **P3.** Detección por User-Agent: ¿por qué es débil? ¿Qué mirarías en lugar de "quién dice ser"? — *pendiente (apoyarse en la fila `scanner-ua` de la §3).* 
- **P4.** El R5: ¿qué habría hecho que la intrusión se detecte automáticamente? — *pendiente.*
- **P5.** Cierre del curso: ¿por qué red y blue son el mismo conocimiento? — *pendiente.*

---

## 5. Bitácora

### Parte 1 — Blue inicial + primera detección (R1, R2)

1. Se levantó el entorno monitoreado con `make lab N=10` (contenedores `cyberlab-attacker` + `cyberlab-phantomcorp` sobre `labnet`).
2. **R1 (Blue):** `curl -s http://phantomcorp/soc` → acceso a la consola del SOC → `FLAG{soc_log_access}`. Validada con `./ctf submit 10 R1`.
3. **R2 (Red):** `curl -s -A sqlmap http://phantomcorp/` → 403, firma `scanner-ua` disparada → `FLAG{detection_triggered}`. Validada con `./ctf submit 10 R2`.
4. Se registró la fila `scanner-ua` en la tabla de firmas (evasión por cambio de UA + mejora por correlación de comportamiento).
5. Progreso al cierre: **2/5**. Siguiente: R3 (ruleset) y R4 (evasión `sqli-union`) en la Parte 2.

### Parte 2 — Ruleset + evasión (R3, R4)
*(pendiente)*

### Parte 3 — Intrusión en el ruido + análisis (R5, P1–P5, research)
*(pendiente)*
