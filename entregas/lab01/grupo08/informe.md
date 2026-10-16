# Laboratorio 01 — Informe

---

## Identificación

| | |
|---|---|
| **Grupo** | 08 |
| **Caso asignado (Parte A)** | Caso 2 — Target (brecha de datos de tarjetas), 2013 |
| **Tema del mini-research** | |
| **Fecha de entrega** | |

### Integrantes

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Marco Cordoba | 14232 | @MarcoCordoba |
| Thomas Koncurat | 14831 | @Koncu1 |
| Lucas Leone | 14700 | @LucasLeone |
| Geronimo Marquez | 14235 | @Geromarquezz |
| Joaquin Moyano | 14622 | @Joaco919 |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

Los números entre corchetes remiten a la lista de fuentes de la sección A.6.

| Fecha | Hecho | Fuente |
|---|---|---|
| Sep.–oct. 2013 (al menos dos meses antes del robo) | Un correo con malware compromete a Fazio Mechanical Services, contratista de refrigeración de Target, y le roban las credenciales que usaba para acceder a los sistemas de facturación de Target. | [1], [4] |
| 12 nov. 2013 | Los atacantes ingresan por primera vez a la red interna de Target usando las credenciales robadas al proveedor. | [1], [7] |
| 15–28 nov. 2013 | Instalan malware de captura de tarjetas (una variante de *BlackPOS*) en un número reducido de terminales de punto de venta (POS); para el 30 de noviembre la mayoría de los POS estaba infectada. | [1] |
| 28 nov.–3 dic. 2013 | El antivirus Symantec y la herramienta FireEye de Target generan alertas sobre el malware y sobre el servidor comprometido. El equipo de seguridad no actúa sobre ellas. | [1], [5] |
| 2 dic. 2013 | Empieza la exfiltración: los datos salen por FTP, a través de otro servidor interno comprometido, hacia servidores externos (uno de ellos en Rusia). En unas dos semanas se llevan unos 11 GB. | [1] |
| 12 dic. 2013 | El Departamento de Justicia de EE.UU. notifica a Target. Según declaró la propia empresa, hasta ese momento no sabía que la estaban atacando. | [1] |
| 18 dic. 2013 | Brian Krebs publica la existencia de la brecha antes de que Target la anuncie. | [3] |
| 19 dic. 2013 | Target confirma que hasta 40 millones de tarjetas de crédito y débito pudieron verse afectadas en sus tiendas físicas de EE.UU. entre el 27 de noviembre y el 15 de diciembre. | [2] |
| 10 ene. 2014 | Target informa además el robo de nombre, domicilio, teléfono o correo electrónico de hasta 70 millones de personas. | [6] |
| 23 may. 2017 | Target firma un acuerdo de USD 18,5 millones con más de 40 estados y el Distrito de Columbia, y se obliga a mantener un programa de seguridad de la información. | [7] |

---

## A.2 — Activo afectado

**Activo principal:** Los datos de las tarjetas de pago de los clientes que compraron en las tiendas físicas de Target en EE.UU. entre el 27 de noviembre y el 15 de diciembre de 2013. Concretamente, el contenido de la banda magnética (*track data*: número de tarjeta, fecha de vencimiento y código de verificación, además del nombre del titular) de unos 40 millones de tarjetas de crédito y débito [2], [3]. Ese dato existía sin cifrar en la memoria RAM de las terminales POS durante el instante en que se procesaba el pago, y de ahí lo extrajo el malware [1].

**Por qué es el principal:** Fue el objetivo del ataque y el dato que tiene valor directo para el atacante. Con el *track data* se pueden clonar tarjetas y venderlas en el mercado negro [3]. Todo el resto de la operación (robar la credencial del proveedor, moverse dentro de la red, comprometer servidores intermedios) fue un medio para llegar a las terminales que procesaban ese dato. Además es el activo cuya exposición generó el mayor costo: reemplazo de tarjetas por parte de los bancos, fraude, litigios y el acuerdo con los estados [7].

**Otros activos afectados (por orden de prioridad):**

1. **Datos personales de contacto de hasta 70 millones de clientes** (nombre, domicilio, teléfono o correo electrónico) [6]. Va en segundo lugar porque no permiten cometer fraude con tarjetas directamente, pero exponen a los clientes a *phishing* dirigido y robo de identidad, y amplían mucho la cantidad de personas afectadas.
2. **Bloques de PIN cifrados de tarjetas de débito.** Target confirmó que se los llevaron, pero estaban cifrados con Triple DES desde el teclado y la clave de descifrado nunca estuvo en sus sistemas [8]. Su exposición real es baja, por eso van en tercer lugar.
3. **La credencial de acceso del proveedor Fazio y la propia infraestructura de Target** (servidores internos y software de las terminales POS). No es información de clientes, pero fue el activo que habilitó el ataque. Lo listamos aparte para no confundirlo con el activo protegido: es el vector, no el objetivo.

---

## A.3 — Matriz CIA

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | **Sí** | Unos 40 millones de números de tarjeta con su *track data* y hasta 70 millones de registros de contacto fueron copiados y enviados a servidores externos controlados por los atacantes: unos 11 GB exfiltrados por FTP desde el 2 de diciembre [1], [2], [6]. Personas no autorizadas accedieron a información que solo debían conocer el titular, Target y el emisor de la tarjeta. Es la propiedad central del incidente. |
| **Integridad** | **Parcial** | Ningún dato de clientes fue alterado: los números de tarjeta y los registros de contacto se copiaron, no se modificaron, y las transacciones se procesaron normalmente. Lo que sí se alteró sin autorización fue el **software de las terminales POS**: se les instaló el malware *BlackPOS*, y se actualizaron las variantes de exfiltración el 2 y el 3 de diciembre. También se reconfiguró un servidor interno para que funcionara como punto de acopio y salida de los datos [1]. La integridad del sistema se violó; la integridad de la información protegida, no. |
| **Disponibilidad** | **No** | Las tiendas siguieron vendiendo y los sistemas de pago siguieron funcionando durante toda la ventana del ataque (27 nov.–15 dic.). De hecho, el ataque *necesitaba* que los POS funcionaran para capturar tarjetas [1], [2]. No se cifraron ni borraron datos y no hubo interrupción del servicio. Que después los bancos reemplazaran tarjetas es una consecuencia de la pérdida de confidencialidad, no una violación de la disponibilidad causada por el atacante. |

**Justificación ampliada de la propiedad más discutible:**

La más difícil de determinar fue la **integridad**. La consigna pide mostrar *qué dato fue alterado*, y si se mira solo la información de los clientes la respuesta sería «No»: el ataque fue de robo, no de manipulación. Nadie cambió un número de tarjeta ni un monto, y el informe del Senado describe solo acceso no autorizado, robo y exfiltración [1].

Igual marcamos «Parcial» porque ISO/IEC 27000 define la integridad como la propiedad de exactitud y completitud, y esa propiedad aplica a cualquier activo de información, no solo a los datos de negocio. El software instalado en una terminal POS es un activo de información. En este caso hay un dato alterado y lo podemos nombrar: el conjunto de ejecutables de las terminales POS de Target, al que se le agregó un programa no autorizado (la variante de *BlackPOS*) que cambió su comportamiento para copiar a memoria y enviar los datos de cada tarjeta [1]. Lo mismo vale para el servidor interno que los atacantes reconfiguraron como depósito intermedio.

Distinguimos las dos cosas a propósito. La violación de la integridad del sistema fue el **medio**, y la violación de la confidencialidad de los datos de tarjetas fue el **fin**. Por eso no ponemos «Sí» a secas: el activo principal (A.2) no sufrió ninguna alteración.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

```
amenaza  →  explota  →  vulnerabilidad  →  sobre  →  activo  →  produce  →  impacto
```

| Elemento | En este caso |
|---|---|
| **Amenaza** | Un grupo de ciberdelincuentes con motivación económica que buscaba revender datos de tarjetas en el mercado negro. Usó malware comercializado en foros clandestinos (*BlackPOS*) y servidores de exfiltración ubicados en Rusia [1], [5]. |
| **Vulnerabilidad** | Principal: la red de Target no aislaba el entorno de pagos de las zonas a las que accedían los proveedores, y el acceso remoto de proveedores no exigía autenticación de dos factores. Con una credencial de un contratista de facturación se pudo llegar a las terminales POS [1]. Agravantes: las alertas de FireEye y Symantec no se atendieron y la salida de datos hacia el exterior no estaba restringida [1], [5]. (El *exploit* fue el uso de la credencial robada y la instalación del malware: no es la vulnerabilidad.) |
| **Activo** | Los datos de banda magnética de unos 40 millones de tarjetas, procesados en las terminales POS de las tiendas de EE.UU., y en segundo término los datos de contacto de hasta 70 millones de clientes [2], [6]. |
| **Impacto** | Para los clientes: exposición a fraude con tarjetas clonadas y a *phishing* dirigido. Para Target: un costo total de la brecha que la empresa estimó en USD 202 millones, un acuerdo de USD 18,5 millones con más de 40 estados y el Distrito de Columbia [7], y la salida de su CIO en marzo de 2014 y de su CEO en mayo de 2014 [9], [10]. |

**Redacción:**

Un grupo criminal con motivación económica (la **amenaza**) le robó con un correo malicioso las credenciales a Fazio Mechanical, un contratista de Target, y con ellas entró a la red de la empresa. Ahí **explotó** dos debilidades de diseño: los proveedores accedían por acceso remoto sin segundo factor, y la red no separaba las zonas a las que llegaba un proveedor de facturación del entorno donde se procesaban las tarjetas. Esa falta de segmentación es la **vulnerabilidad** central [1]. Usó esa debilidad para instalar *BlackPOS* en las terminales de punto de venta, que es el *exploit* y no la vulnerabilidad. El ataque recayó **sobre** el **activo** que Target tenía que proteger: los datos de banda magnética de unos 40 millones de tarjetas, que el malware leía de la memoria de los POS en el momento del pago, además de los datos de contacto de hasta 70 millones de personas [2], [6]. Las alertas de las herramientas de detección no se atendieron y la salida de datos por FTP no estaba bloqueada, así que nada cortó la cadena antes de la exfiltración [1], [5]. El resultado **produjo** un **impacto** doble. Los clientes quedaron expuestos a fraude y robo de identidad. Target asumió un costo que estimó en USD 202 millones, pagó un acuerdo de USD 18,5 millones con los estados [7] y perdió a su CIO y a su CEO [9], [10].

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | Segmentación de red del entorno de datos de tarjetas (*cardholder data environment*, como exige PCI DSS), combinada con acceso de proveedores restringido y autenticado con dos factores. El proveedor solo llega a la aplicación que necesita (el portal de facturación), desde una zona aislada y con reglas de firewall que le impiden cualquier conexión hacia los servidores y terminales de pago. |
| **Propiedad de la tríada que protege** | **Confidencialidad** de los datos de tarjetas. |
| **Por qué habría funcionado en este caso concreto** | El ataque dependió de que una credencial pensada para facturación y gestión de proyectos sirviera para moverse hasta las terminales POS. El informe del Senado identifica justamente que Target no aislaba sus activos más sensibles y que no pedía doble factor a proveedores de bajo nivel [1]. Con segundo factor, la contraseña robada a Fazio por correo no habría alcanzado para entrar. Y aunque entraran, desde la zona del proveedor no habría existido una ruta de red hacia los POS: el atacante habría quedado contenido en el portal de facturación, sin acceso al dato de tarjeta. |

### Control 2

| | |
|---|---|
| **Qué es** | Lista blanca de aplicaciones (*application allowlisting*) en las terminales POS: la terminal solo ejecuta los binarios aprobados y firmados por Target y bloquea cualquier otro ejecutable. Se complementa con una lista blanca de salida: los servidores del entorno de pagos solo pueden conectarse a destinos autorizados, como el procesador de pagos. |
| **Propiedad de la tríada que protege** | **Integridad** del software de las terminales POS y, como consecuencia, **confidencialidad** de los datos de tarjetas. |
| **Por qué habría funcionado en este caso concreto** | Una terminal POS es un equipo de propósito único con un conjunto de programas fijo y conocido, que es el escenario ideal para una lista blanca. *BlackPOS* era un ejecutable nuevo que había que instalar y actualizar en las terminales (el 30 de noviembre y el 2 y 3 de diciembre) [1]. Con la lista blanca no se habría ejecutado y no habría capturado ninguna tarjeta, aunque el atacante ya estuviera dentro de la red. El informe del Senado señala la falta de listas blancas de procesos y de servidores FTP como una oportunidad perdida [1]. La lista blanca de salida cubre la segunda mitad del ataque: los 11 GB salieron por FTP hacia servidores externos, uno en Rusia, un destino que un servidor del entorno de pagos nunca necesita contactar [1]. |

---

## A.6 — Fuentes consultadas (Parte A)

1. U.S. Senate Committee on Commerce, Science, and Transportation, Majority Staff. (2014, 26 de marzo). *A "kill chain" analysis of the 2013 Target data breach* [Informe del personal del comité]. Reproducido en *Protecting personal consumer information from cyber attacks and data breaches* (S. Hrg. 113-531). U.S. Government Publishing Office. https://www.govinfo.gov/content/pkg/CHRG-113shrg92594/html/CHRG-113shrg92594.htm — **Primaria** (informe oficial del Senado de EE.UU.).
2. Target Corporation. (2013, 19 de diciembre). *Target confirms unauthorized access to payment card data in U.S. stores* [Comunicado de prensa]. https://corporate.target.com/press/release/2013/12/target-confirms-unauthorized-access-to-payment-card-data-in-u-s-stores — **Primaria** (comunicado de la empresa afectada).
3. Krebs, B. (2013, 18 de diciembre). Sources: Target investigating data breach. *Krebs on Security*. https://krebsonsecurity.com/2013/12/sources-target-investigating-data-breach/ — **Secundaria** (periodismo de investigación).
4. Krebs, B. (2014, 5 de febrero). Target hackers broke in via HVAC company. *Krebs on Security*. https://krebsonsecurity.com/2014/02/target-hackers-broke-in-via-hvac-company/ — **Secundaria**. Complementada con Krebs, B. (2014, 12 de febrero). Email attack on vendor set up breach at Target. https://krebsonsecurity.com/2014/02/email-attack-on-vendor-set-up-breach-at-target/
5. Riley, M., Elgin, B., Lawrence, D. y Matlack, C. (2014, 13 de marzo). Missed alarms and 40 million stolen credit card numbers: How Target blew it. *Bloomberg Businessweek*. https://www.bloomberg.com/news/articles/2014-03-13/target-missed-warnings-in-epic-hack-of-credit-card-data — **Secundaria**.
6. Target Corporation. (2014, 10 de enero). *Target provides update on data breach and financial performance* [Comunicado de prensa]. https://corporate.target.com/press/release/2014/01/target-provides-update-on-data-breach-and-financial-performance — **Primaria**.
7. Office of the Attorney General for the District of Columbia. (2017, 23 de mayo). *Attorney General Racine announces $18.5 million multistate settlement with Target Corporation over 2013 data breach* [Comunicado de prensa]. https://oag.dc.gov/node/128 — **Primaria** (documento oficial de una fiscalía). El costo total de USD 202 millones lo informó Target y lo recoge la cobertura del acuerdo de Associated Press: https://www.fox4news.com/news/target-states-reach-18-5-million-settlement-on-data-breach — **Secundaria**.
8. Target Corporation. (2013, 27 de diciembre). *Target data security media update #4* [Comunicado de prensa]. https://corporate.target.com/press/release/2013/12/target-data-security-media-update-4 — **Primaria**.
9. Christian Science Monitor. (2014, 5 de marzo). Target Corp. tech chief resigns amid security overhaul. https://www.csmonitor.com/Business/2014/0305/Target-Corp.-tech-chief-resigns-amid-security-overhaul — **Secundaria**.
10. The Global Treasurer. (2014, 5 de mayo). Target CEO resigns in wake of data breach. https://www.theglobaltreasurer.com/2014/05/05/target-ceo-resigns-in-wake-of-data-breach/ — **Secundaria**.
11. ISO/IEC. (2018). *ISO/IEC 27000:2018 — Information technology — Security techniques — Information security management systems — Overview and vocabulary*. International Organization for Standardization. — **Primaria** (norma; definiciones de la tríada usadas en A.3).

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

*Pegá la salida real de cada comando. No la transcribas a mano: copiala tal
cual sale de la terminal.*

### Generación del manifiesto

```
$ python3 src/integridad.py generar --dir data/muestra --salida manifest.sha256

(pegar salida)
```

### Verificación sobre un directorio íntegro

```
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"

(pegar salida)
```

### Detección de la modificación de un byte

*Esta prueba es obligatoria y tiene una penalización específica en la rúbrica
si falla.*

```
$ printf 'X' >> data/muestra/transferencia.txt
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"

(pegar salida — debe reportar MODIFICADO y salir con 1)
```

### Detección de archivo faltante y de archivo nuevo

```
(pegar los comandos que usaron y la salida)
```

### Efecto avalancha

```
$ python3 src/integridad.py avalancha --a "transferencia: $1000" --b "transferencia: $1001"

(pegar salida)
```

**Distancia obtenida:** ____ bits de 256 (____ %)

*¿Coincide con lo esperado? ¿Qué esperaban antes de correrlo?*

### HMAC

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000"

(pegar salida)
```

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar <tag válido>
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar <tag alterado>

(pegar ambas salidas)
```

---

## B.2 — Decisiones de implementación

*Qué decisiones tuvieron que tomar que el enunciado no resolvía por ustedes.
Ejemplos: cómo trataron los enlaces simbólicos, qué hicieron con los archivos
vacíos, cómo excluyeron el manifiesto del recorrido, qué pasa si el directorio
está vacío. Una o dos oraciones por decisión.*

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| | | |
| | | |

---

## B.3 — Preguntas de análisis

> **Se responden con fundamento técnico, no con opinión.** Dos o tres párrafos
> cada una. Las respuestas de una línea no suman puntos.

### 1. El manifiesto por sí solo no alcanza

*Un atacante con acceso de escritura al directorio también puede escribir
`manifest.sha256`. ¿Qué le impide modificar un archivo y regenerar el
manifiesto para que todo dé `OK`? ¿Qué habría que cambiar en el esquema para
que ese ataque no funcione?*

**Respuesta:**

---

### 2. Qué agrega HMAC y qué no

*¿Qué propiedad de seguridad aporta HMAC que un hash simple no aporta? Y la
parte importante: ¿qué **no** resuelve HMAC? Pensá en el no repudio y en
quién conoce la clave.*

**Respuesta:**

---

### 3. MD5 y SHA-1

*Ambos siguen apareciendo en software en producción. ¿Qué propiedad
criptográfica se les rompió, exactamente? ¿Hay algún uso en el que todavía
sean aceptables, o ninguno? Fundamentá con al menos una fuente.*

**Respuesta:**

**Fuente:**

---

### 4. Comparación en tiempo constante

*¿Por qué comparar un tag de autenticación con `==` puede filtrar información
al atacante, y cómo lo evita `hmac.compare_digest()`? Describí el ataque
concreto que esto previene.*

**Respuesta:**

---

### 5. SHA-256 para contraseñas: mala idea

*SHA-256 es una función de hash criptográfica sólida. ¿Por qué, entonces, es
una mala elección para almacenar contraseñas? ¿Qué se usa en su lugar y qué
propiedad tienen esas funciones que SHA-256 no tiene?*

**Respuesta:**

---

# Cierre

## Dificultades encontradas

*Qué les costó, dónde se trabaron, qué decidieron y por qué. Esta sección se
lee y suma. No es relleno: es donde se ve si entendieron el problema.*

---

## Distribución del trabajo

*Quién hizo qué. Tiene que ser consistente con el historial de commits.*

| Integrante | Aportes |
|---|---|
| | |
| | |
| | |
| | |
| | |

---

## Declaración de uso de asistentes de IA

> **Obligatoria.** No está prohibido usar asistentes de IA. Lo que se evalúa es
> que entiendan lo que entregan. La omisión de esta declaración es **causal de
> rechazo automático** de la entrega. Una declaración honesta no baja la nota.

**¿El grupo usó asistentes de IA en este trabajo?**  Sí / No

*Si la respuesta es No, firmen igual la sección y pasen al final.*

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| | | | |
| | | | |

**Declaración:**

*El grupo declara que comprende el contenido íntegro de lo entregado y que
puede explicar y defender oralmente cualquier parte del código y del análisis,
independientemente de la asistencia recibida.*

---

## Fuentes consultadas (general)

*Todas las fuentes del trabajo, en formato APA. Las de la Parte A pueden
repetirse acá o referenciarse a la sección A.6.*

1.
2.
3.
