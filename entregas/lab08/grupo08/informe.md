# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en la exploración del host víctima (`situational awareness`), análisis de notas de deploy y loot de credenciales de la Parte 1; borrador de la redacción de las secciones correspondientes de la tabla, evidencias 2.1 y 2.2, y respuesta P3. | `informe.md`: filas de Recon del host y Loot de la tabla, secciones 2.1 y 2.2, respuesta P3 y bitácora de la Parte 1. | Las salidas pegadas en la sección 2 corresponden a la terminal del host comprometido. Las flags capturadas se validaron contra el evaluador del laboratorio con `./ctf submit 08`. El grupo revisó técnicamente el contenido y comprende las implicancias operativas y defensivas del análisis. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 08                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Reconocimiento del host comprometido
   ✓  R2     Loot de credenciales
   ·  R3     Escalada de privilegios (SUID)
   ·  R4     Pivoting al host interno
   ·  R5     Automatizacion (fuerza bruta de legajos)

  ████████████░░░░░░░░░░░░░░░░░░  2/5 (40%)
```

---

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host (R1) | Relevamiento de identidad y entorno (`situational awareness`), inspección del árbol de directorios administrativos en `/opt`. | `id`, `whoami`, `hostname`, `uname -a`, `env`, `ls -la /opt` y lectura con `cat /opt/phantom-deploy/DEPLOY_NOTES.txt`. | Usuario `operador` (uid=1000), hostname `phantomcorp`, entorno `DEPLOY_ENV=produccion`. Nota de despliegue con token activo: `FLAG{post_situational_awareness}`. | **Mínimo privilegio en filesystem y limpieza de artefactos**. No dejar notas de aprovisionamiento en hosts de producción; restringir permisos de lectura a directorios administrativos (`chmod 700 /opt/...`) accesibles únicamente por `root`. |
| Loot de credenciales (R2) | Búsqueda de secretos estáticos de aplicación en archivos de configuración (`.env`) y lectura del historial de comandos del usuario (`~/.bash_history`). | `cat /var/www/.env` y `cat /home/operador/.bash_history`. | Archivo `.env` exponiendo base de datos interna (`DB_HOST=phantomcorp-db`, `DB_USER=phantom_app`, contraseña `Ph@ntom-DB-2024`) y `APP_SECRET=FLAG{loot_credentials_found}`. El historial confirmó acceso previo a `http://phantomcorp-db/`. | **Gestión centralizada de secretos**. No guardar credenciales en archivos planos en el filesystem. Usar un gestor de secretos (HashiCorp Vault, AWS Secrets Manager) que inyecte secretos efímeros en memoria en tiempo de ejecución. Restringir permisos (`chmod 600`) y deshabilitar o sanitizar `HISTFILE`. |
| Privesc (SUID) (R3) | *(pendiente — parte del compañero que realice R3 en la Parte 2)* | | | |
| Pivoting (R4) | *(pendiente — parte del compañero que realice R4 en la Parte 2)* | | | |

### 2.1 R1 — Reconocimiento del host comprometido

Al obtener acceso inicial sobre el sistema víctima (`make shell-victima`), asumimos el control como el usuario sin privilegios `operador`.

El primer paso metodológico de post-explotación es responder **¿Quién soy?** y **¿Dónde estoy?** (*situational awareness*):

```
$ id
uid=1000(operador) gid=1000(operador) grupos=1000(operador)

$ whoami
operador

$ hostname
phantomcorp

$ uname -a
Linux phantomcorp 6.6.137+rpt-rpi-2712 #1 SMP PREEMPT Debian 1:6.6.137-1+rpt1 (2026-05-15) aarch64 GNU/Linux

$ env | grep -E 'DEPLOY|USER|SHELL'
DEPLOY_ENV=produccion
USER=operador
SHELL=/bin/bash
```

Con la identidad confirmada, procedemos a enumerar el sistema de archivos buscando directorios no estándar donde suelen depositarse scripts o configuraciones de infraestructura. Inspeccionamos `/opt`:

```
$ ls -la /opt
total 12
drwxr-xr-x 3 root root 4096 Oct 30 10:00 .
drwxr-xr-x 1 root root 4096 Oct 30 10:00 ..
drwxr-xr-x 2 root root 4096 Oct 30 10:00 phantom-deploy

$ ls -la /opt/phantom-deploy
total 12
drwxr-xr-x 2 root root 4096 Oct 30 10:00 .
drwxr-xr-x 3 root root 4096 Oct 30 10:00 ..
-rw-r--r-- 1 root root   91 Oct 30 10:00 DEPLOY_NOTES.txt
```

El archivo `DEPLOY_NOTES.txt` posee permisos de lectura para todos los usuarios (`chmod 644`). Lo leemos:

```
$ cat /opt/phantom-deploy/DEPLOY_NOTES.txt
PhantomCorp - notas de despliegue (NO borrar)
deploy_token=FLAG{post_situational_awareness}
```

El archivo revela una nota descuidada de aprovisionamiento con el token de despliegue y la flag `FLAG{post_situational_awareness}`.

### 2.2 R2 — Loot de credenciales

El objetivo de la fase de *Credential Access / Looting* es extraer contraseñas, tokens y claves de acceso que faciliten la escalada de privilegios o el movimiento lateral.

Las aplicaciones web habitualmente guardan configuraciones en `/var/www/`. Revisamos el directorio y encontramos un archivo `.env`:

```
$ ls -la /var/www
total 12
drwxr-xr-x 2 root root 4096 Oct 30 10:00 .
drwxr-xr-x 1 root root 4096 Oct 30 10:00 ..
-rw-r--r-- 1 root root  117 Oct 30 10:00 .env
```

El archivo es legible por cualquier usuario del sistema. Su contenido expone la configuración completa de conexión:

```
$ cat /var/www/.env
DB_HOST=phantomcorp-db
DB_USER=phantom_app
DB_PASS=Ph@ntom-DB-2024
APP_SECRET=FLAG{loot_credentials_found}
```

El `.env` revela:
- La existencia de un host interno en la red: `phantomcorp-db`.
- Credenciales de la base de datos: usuario `phantom_app` y contraseña `Ph@ntom-DB-2024`.
- El secreto de la aplicación con la flag `FLAG{loot_credentials_found}`.

Adicionalmente, un atacante siempre inspecciona los comandos previos ejecutados por los operadores del sistema leyendo el historial de bash:

```
$ cat /home/operador/.bash_history
ls -la
cat /var/www/.env
curl http://phantomcorp-db/
```

El historial confirma que el host `phantomcorp-db` es alcanzable vía HTTP desde este equipo (`curl http://phantomcorp-db/`), sirviendo como pista directa para la fase de pivoting.

---

## 3. Automatización

*(pendiente — parte del compañero que complete `src/recolector.py` y ejecute R5 en la Parte 2)*

---

## 4. Preguntas de análisis

**P1 — SUID y el flag `-p`.**

*(pendiente — parte del compañero que realice R3 en la Parte 2)*

**P2 — El pivoting (por qué el atacante no llegaba y vos sí).**

*(pendiente — parte del compañero que realice R4 en la Parte 2)*

**P3 — Cómo evitar secretos en `.env`/`.bash_history`.**

El hallazgo de secretos en texto claro dentro de `/var/www/.env` y en `~/.bash_history` ilustra una de las fallas operativas más comunes en entornos de producción (CWE-312 / CWE-522). Para evitar que las credenciales queden expuestas ante cualquier proceso o usuario con acceso local, se deben aplicar las siguientes prácticas de desarrollo y DevSecOps:

1. **Gestión centralizada de secretos (Secret Managers) en lugar de archivos planos:**
   - En entornos de producción modernos no deben existir archivos `.env` en disco. Las aplicaciones deben consumir credenciales mediante un gestor de secretos centralizado (como HashiCorp Vault, AWS Secrets Manager, Google Cloud Secret Manager o Azure Key Vault).
   - En contenedores Docker / Kubernetes, los secretos deben inyectarse directamente en la memoria del proceso en tiempo de arranque (a través de variables de entorno montadas desde Kubernetes Secrets o secretos en memoria `tmpfs`), evitando que residan en el sistema de archivos persistente donde cualquier usuario local con permisos de lectura (`chmod 644`) pueda extraerlos.
2. **Protección y sanitización del historial de shell (`.bash_history`):**
   - **No escribir credenciales en la línea de comandos:** Parámetros como `-p<contraseña>` o tokens en llamadas `curl` quedan grabados en texto plano en el historial. Se deben usar archivos de configuración protegidos, variables de sesión temporales o prompts interactivos que no dejen rastro.
   - **Configuración de variables de shell:** Configurar `HISTCONTROL=ignorespace` (para que cualquier comando precedido por un espacio no se guarde en el historial) o deshabilitar directamente el guardado en sesiones automatizadas o de cuentas de servicio mediante `unset HISTFILE` o `export HISTFILESIZE=0`.
   - **Permisos estrictos:** En caso de mantenerse el historial para propósitos de auditoría, debe contar con permisos restrictivos (`chmod 600 ~/.bash_history`), y para auditoría forense formal debe utilizarse un mecanismo del kernel como `auditd` o telemetría eBPF, nunca un archivo de texto en el home del usuario que este mismo puede manipular o leer.
3. **Controles estáticos en el pipeline de desarrollo (CI/CD) y `.gitignore`:**
   - Asegurar que `.env`, `.env.local` y cualquier archivo con claves privadas estén incluidos en `.gitignore` desde el primer commit para impedir que lleguen al repositorio de código fuente.
   - Implementar hooks de pre-commit y escaneo automatizado en el pipeline de integración continua mediante herramientas de detección de secretos (como TruffleHog, Gitleaks o git-secrets), bloqueando cualquier commit o despliegue que contenga patrones de tokens, contraseñas o claves API.

**P4 — Qué decidiste vos que el script no decide solo.**

*(pendiente — parte del compañero que realice R5 en la Parte 2)*

**P5 — Defensa para SUID y para pivoting.**

*(pendiente — parte del compañero de la Parte 2)*

---

## 5. Bitácora de comandos

```bash
# ==============================================================================
# PARTE 1 · Reconocimiento del host y Loot de credenciales (R1 y R2)
# ==============================================================================

# Conexión al host comprometido como usuario 'operador'
make shell-victima

# 1. Situational awareness (R1)
id                                                  # uid=1000(operador) gid=1000(operador)
whoami                                              # operador
hostname                                            # phantomcorp
uname -a                                            # Linux phantomcorp ... aarch64 GNU/Linux
env | grep -E 'DEPLOY|USER|SHELL'                   # DEPLOY_ENV=produccion

# Búsqueda de artefactos en /opt
ls -la /opt
ls -la /opt/phantom-deploy
cat /opt/phantom-deploy/DEPLOY_NOTES.txt             # deploy_token=FLAG{post_situational_awareness}

# 2. Loot de credenciales (R2)
ls -la /var/www
cat /var/www/.env                                   # DB_HOST, DB_USER, DB_PASS, APP_SECRET=FLAG{loot_credentials_found}
cat /home/operador/.bash_history                    # curl http://phantomcorp-db/

# ==============================================================================
# Validación de flags capturadas desde la raíz del repositorio
# ==============================================================================
./ctf submit 08 R1 'FLAG{post_situational_awareness}'
./ctf submit 08 R2 'FLAG{loot_credentials_found}'
./ctf status 08                                     # Progreso: 2/5 (40%)
```
