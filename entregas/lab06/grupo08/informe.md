# Informe — Laboratorio 06 · Enumeración

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Ejecución de la enumeración de directorios y de los `curl` de confirmación contra el target; borrador de la redacción del inventario (R1, R2) y de P1–P2. | `informe.md`: filas de `/backup`, `/admin` y `/.git/config` del inventario, sus evidencias, P1, P2 y la bitácora correspondiente. | Las salidas pegadas en la sección 2 son las reales de la terminal. Las flags se validaron con `./ctf submit 06`. No se leyó el código del target (`server.py`) ni ningún `solucion.md`: todo salió de enumerar el servicio desde afuera. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 06                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Enumeracion de directorios
   ✓  R2     Repositorio Git expuesto
   ·  R3     Metodos HTTP peligrosos habilitados
   ·  R4     Enumeracion de usuarios via API
   ·  R5     Fingerprinting de tecnologia

  ████████████░░░░░░░░░░░░░░░░░░  2/5 (40%)
```

---

## 2. Inventario de enumeración

| Hallazgo | Ruta/Método | Técnica | Evidencia | Riesgo | ¿Qué habilita para el Lab 07? |
|---|---|---|---|---|---|
| Directorio de backups con listado habilitado | `GET /backup` | Fuerza bruta de rutas con wordlist (estilo `dirb`) + confirmación con `curl` | `+ http://127.0.0.1/backup (CODE:200\|SIZE:249)` y el `Index of /backup` que lista `respaldo-db-2024.sql.gz`, `config.old` y `notas-infra.txt` (ver 2.1 y 2.2) | **Alto.** El listado de directorio revela nombres de archivos de respaldo de la base de datos y de configuración vieja. Aunque al pedirlos hoy devuelven 404, el propio índice confirma que existieron y nos dice qué buscar: un dump `.sql.gz` y un `config.old` suelen traer el esquema de la base y credenciales en claro. Es exposición de información (CWE-548, *Directory listing*). | Una lista de objetivos precisos: buscar variantes de esos nombres (`config.php.old`, `db.sql`, `.gz` en otras rutas), y, si aparece alguno, credenciales de base de datos para probar en `/admin`. |
| Panel de administración | `GET /admin` | Fuerza bruta de rutas con wordlist | `+ http://127.0.0.1/admin (CODE:403\|SIZE:65)` → `Panel admin. Necesitas credenciales.` | **Medio.** El 403 no da acceso, pero confirma que el panel existe y en qué ruta. El servidor encima aclara que lo que falta son credenciales: no está restringido por IP ni oculto. | El destino del ataque de credenciales: usuarios que salgan de la enumeración de la API + contraseñas que salgan del backup o del código del `.git` se prueban acá. |
| Repositorio Git expuesto por HTTP | `GET /.git/config` | Fuerza bruta de rutas (`.git/config` en la wordlist) + `curl` | `+ http://127.0.0.1/.git/config (CODE:200\|SIZE:209)` y su contenido: `[remote "origin"] url = https://git.internal.phantomcorp/intranet.git` (ver 2.3) | **Alto.** El archivo de configuración de git se sirve como texto plano. Filtra el nombre de un host interno (`git.internal.phantomcorp`) y el nombre del repositorio de la intranet. Que `/.git/config` sea accesible indica que el directorio `.git` quedó desplegado en el docroot (CWE-527). | Reconocimiento de infraestructura interna (un servidor git que no estaba en el mapa del Lab 05) y la base para intentar reconstruir el código con `git-dumper` si se encuentran más objetos del repo. Con el código: credenciales commiteadas, endpoints ocultos y la lógica del login de `/admin`. |

### 2.1 Enumeración de directorios

Sin Docker en la máquina, el target se levantó en local (`127.0.0.1:80`, mismo `server.py` del contenedor) y se enumeró con un script de fuerza bruta de rutas que hace lo mismo que `dirb`: prueba cada palabra de la wordlist y reporta todo lo que no devuelve 404. La wordlist (66 entradas) tiene los nombres de `common.txt` que importan para este target (`admin`, `api`, `backup`, `.git`, `.env`, `robots.txt`, `uploads`...). En la consola del atacante el comando equivalente es `dirb http://phantomcorp/`.

```
URL_BASE: http://127.0.0.1/
WORDLIST_FILES: wordlist.txt (66 palabras)  EXTENSIONES: -

+ http://127.0.0.1/.git/config (CODE:200|SIZE:209)
+ http://127.0.0.1/admin (CODE:403|SIZE:65)
+ http://127.0.0.1/backup (CODE:200|SIZE:249)
```

Una segunda pasada con extensiones de respaldo (`.bak,.old,.txt,.zip`, el equivalente de `dirb ... -X .bak,.old,.txt`) no encontró archivos nuevos: devolvió las mismas tres rutas.

Lectura: dos `200` (accesibles) y un `403` (existe pero protegido). Las tres son hallazgos. `robots.txt`, `.git/HEAD` y `/.git/` devolvieron 404.

### 2.2 Confirmación de `/backup` (R1)

```
$ curl -si http://127.0.0.1/backup
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Content-Type: text/html; charset=utf-8
X-Powered-By: PhantomCMS/3.7

<!doctype html><html><body><h1>Index of /backup</h1>
<pre>
respaldo-db-2024.sql.gz
config.old
notas-infra.txt   ->  FLAG{dir_enumeration_backup}
</pre>
<p>Este directorio no deberia estar accesible. Enumeracion de directorios 101.</p>
</body></html>
```

Los tres archivos listados, pedidos de a uno (`/backup/config.old`, `/backup/notas-infra.txt`, `/backup/respaldo-db-2024.sql.gz`), devolvieron **404**: el índice quedó expuesto aunque los archivos ya no se sirvan.

```
$ curl -si http://127.0.0.1/admin
HTTP/1.0 403 Forbidden
Server: PhantomServer/3.7
X-Powered-By: PhantomCMS/3.7

<h1>403 Forbidden</h1><p>Panel admin. Necesitas credenciales.</p>
```

### 2.3 Confirmación de `/.git/config` (R2)

```
$ curl -si http://127.0.0.1/.git/config
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Content-Type: text/plain; charset=utf-8
X-Powered-By: PhantomCMS/3.7

[core]
	repositoryformatversion = 0
	bare = false
[remote "origin"]
	url = https://git.internal.phantomcorp/intranet.git
# Un .git expuesto filtra codigo, historia y a veces secretos.
# FLAG{git_repo_exposed}
```

`bare = false` indica que es el `.git` de una copia de trabajo, o sea que el código de la intranet se desplegó haciendo `git clone`/`git pull` directo sobre el directorio que sirve el web server.

---

## 3. Preguntas de análisis

**P1 — Enumeración vs. recon.**

En el **Lab 05** la pregunta era *qué hay*: con `nmap -sV -p-` contra `phantomcorp` barrimos los 65535 puertos y sacamos el mapa (qué puertos están abiertos y qué servicio y versión corre en cada uno). Para el puerto 80 el resultado fue una línea: "hay un web server PhantomCMS". Fue amplio y poco profundo, porque tocamos todos los servicios pero sin entrar en ninguno.

En este lab la pregunta es *qué esconde* ese único servicio. Tomamos el puerto 80 del mapa y le tiramos una wordlist de rutas. Así pasamos de "hay un web server" a "hay un `/backup` con listado de directorio, un `/admin` que pide credenciales y un `/.git/config` que filtra un servidor git interno". Ninguna de esas tres rutas está linkeada desde el index, y el recon del Lab 05 no podía verlas porque `nmap` mira puertos, no rutas dentro de HTTP. Es angosto y profundo. Dos diferencias concretas:

1. **Alcance:** el `nmap -p-` del Lab 05 recorrió puertos de todo el host. La fuerza bruta de rutas de este lab recorrió nombres de archivos dentro de un solo puerto.
2. **Salida:** el Lab 05 nos dejó un mapa de servicios y versiones. Este lab nos deja un inventario de recursos concretos (rutas, códigos de respuesta y contenido) que ya son objetivos de ataque.

**P2 — El `.git` expuesto.**

El directorio `.git` no es un archivo más: es la base de datos completa del repositorio. Además del código actual tiene **toda la historia**: cada versión de cada archivo, los mensajes de commit, los autores y las ramas. Si un atacante puede bajar `.git/config`, lo normal es que también pueda pedir `.git/HEAD`, `.git/index`, `.git/refs/...` y los objetos de `.git/objects/`. Herramientas como `git-dumper` automatizan eso: siguen las referencias, bajan cada objeto y reconstruyen el repo localmente, y después un `git checkout` deja el código fuente completo.

Con eso el atacante puede reconstruir:

- **El código fuente de la intranet.** Pasa de atacar a ciegas (caja negra) a leer la lógica: cómo se valida el login de `/admin`, qué endpoints existen aunque no estén linkeados y qué parámetros llegan sin sanitizar a una consulta SQL o a un comando.
- **Secretos en la historia.** Un desarrollador que commiteó una contraseña de base de datos o una API key y después la "borró" en otro commit la sigue teniendo en la historia: `git log -p` la muestra. Borrar el archivo hoy no la saca de los objetos viejos.
- **Infraestructura interna.** En nuestro caso, el `config` ya filtró `https://git.internal.phantomcorp/intranet.git`, un host interno que no apareció en el recon.

Por eso es más grave que "un archivo de más". Un backup suelto expone un archivo. El `.git` expone el código y todo lo que alguna vez pasó por él, y convierte el siguiente ataque de caja negra en caja blanca. En este lab, `/.git/HEAD` y `/.git/` devolvieron 404, así que con lo que vimos no se puede bajar el repo entero. Pero que `config` esté accesible confirma que el directorio quedó en el docroot, y en un servidor real lo esperable es que sirva el resto igual.

**P3 — El método `PUT`.**

**P4 — Enumeración de usuarios.**

**P5 — Rol defensor (3 mitigaciones).**

---

## 4. Bitácora de comandos

```bash
# Target levantado en local (127.0.0.1:80): python labs/lab06-enumeracion-de-servicios/entorno/phantomcorp/server.py
# Enumeración de directorios (equivalente a dirb http://phantomcorp/)
python enumeracion/dirbuster.py http://127.0.0.1 enumeracion/wordlist.txt
# Segunda pasada con extensiones de backup (equivalente a dirb ... -X .bak,.old,.txt,.zip)
python enumeracion/dirbuster.py http://127.0.0.1 enumeracion/wordlist.txt .bak,.old,.txt,.zip

# Confirmación manual de cada hallazgo
curl -si http://127.0.0.1/backup
curl -si http://127.0.0.1/backup/config.old            # 404
curl -si http://127.0.0.1/backup/notas-infra.txt       # 404
curl -si http://127.0.0.1/backup/respaldo-db-2024.sql.gz   # 404
curl -si http://127.0.0.1/admin                        # 403
curl -si http://127.0.0.1/.git/config                  # 200
curl -si http://127.0.0.1/.git/HEAD                    # 404
curl -si http://127.0.0.1/robots.txt                   # 404

./ctf submit 06 R1 'FLAG{dir_enumeration_backup}'
./ctf submit 06 R2 'FLAG{git_repo_exposed}'
./ctf status 06
```
