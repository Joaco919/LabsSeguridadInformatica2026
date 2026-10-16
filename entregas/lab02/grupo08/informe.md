# Informe — Laboratorio 02 · Criptografía

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:**

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

Usamos asistentes de IA (Claude, de Anthropic) como herramienta de apoyo durante todo el laboratorio, con estos fines:

- **Aprender y repasar conceptos** que no dominábamos: resistencia a colisiones, colisiones de prefijo elegido, el funcionamiento de las firmas sobre certificados X.509, HMAC y el ataque de *length-extension*.
- **Buscar información y fuentes** sobre los temas que no conocíamos, en particular sobre el caso asignado en la Parte A.
- **Apoyo en el desarrollo**: redacción de borradores del informe (en particular la Parte A) y orientación al implementar el código.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo verificamos el resultado |
|---|---|---|---|
| Claude (Anthropic) | Explicación de conceptos, búsqueda de fuentes y redacción de un borrador | Parte A | Entramos a cada una de las fuentes citadas para confirmar que existen y que dicen lo que se les atribuye; revisamos el texto y lo ajustamos hasta poder explicarlo con nuestras palabras. |
| Claude (Anthropic) | Explicación de conceptos y apoyo en la implementación | Parte B | Ejecutamos el código, lo probamos con `src/verificar.py` y revisamos cada función hasta entender qué hace y por qué. |

En ningún caso tomamos lo que devolvía la IA sin revisarlo: verificamos el contenido, lo contrastamos con las fuentes y nos aseguramos de entender lo que entregamos. El grupo declara que comprende el contenido íntegro de este trabajo.

## 1. Parte A — Análisis de la falla

**Caso:** 3 — MD5 / colisiones: uso de una función de hash rota para firmar certificados (asignado por `08 mod 5 = 3`).

Analizamos dos incidentes reales que comparten la misma falla. El principal es el certificado de CA falso obtenido de RapidSSL en 2008 [1], [2]. El segundo es el certificado de Microsoft falsificado por el malware Flame en 2012 [5], [6]. Los números entre corchetes remiten a las fuentes al final de esta sección.

### A.1 — Qué prometía el sistema

Una infraestructura de clave pública (PKI) promete **autenticidad**: si un certificado X.509 está firmado por una autoridad de certificación (CA) confiable, entonces la clave pública que contiene pertenece realmente a quien dice el certificado, y la CA verificó y aprobó exactamente ese contenido. Sobre esa promesa se apoyan HTTPS (el navegador confía en que `banco.com` es `banco.com`) y la firma de código (Windows confía en que un programa viene de Microsoft).

La firma de una CA no se aplica sobre el certificado completo, sino sobre su **hash**. Por eso la promesa de autenticidad depende de una propiedad de la función de hash: la **resistencia a colisiones**, es decir, que nadie pueda fabricar dos certificados distintos con el mismo hash. Si eso se puede, una firma legítima sobre un certificado sirve también para el otro. En los dos casos el hash usado era MD5 (algoritmo de firma `md5WithRSAEncryption`) [2], [6].

### A.2 — El mal uso

El problema no fue que «MD5 es un mal algoritmo». MD5 sigue funcionando como suma de verificación contra errores accidentales. El mal uso fue **seguir usando MD5 para firmas digitales, que es justo el uso que requiere resistencia a colisiones, años después de que se demostrara públicamente que esa propiedad estaba rota**. A eso se sumó firmar contenido **predecible** para el atacante.

- **Las advertencias eran públicas.** Las colisiones prácticas de MD5 se publicaron en 2004 y se formalizaron en 2005 [3]. En 2007 se demostraron colisiones de prefijo elegido y certificados X.509 colisionantes con identidades distintas [4]. Aun así, en 2008 seis CAs seguían emitiendo certificados firmados con MD5, y el 97 % de esos certificados venía de RapidSSL [2].
- **RapidSSL firmaba contenido predecible.** Emitía el certificado unos 6 segundos después de la compra, de forma automática, y con números de serie **secuenciales**. Así el atacante podía calcular de antemano, byte por byte, qué contenido iba a firmar la CA, que es el requisito del ataque [2].
- **Microsoft (caso Flame) repitió el patrón en 2012.** El servicio de licencias de Terminal Server firmaba certificados con MD5, con números de serie y períodos de validez predecibles. Además, por un error de configuración, esos certificados servían para **firmar código** aunque solo hacían falta para licencias [5], [6].

### A.3 — Propiedad rota y cómo se explotó

**Propiedad rota: autenticidad**, y con ella la integridad de lo que la firma garantiza. La confidencialidad no se ve afectada directamente: nadie descifró nada, se falsificó una identidad.

**Cómo se explotó (RapidSSL, 2008)** [1], [2]:

1. Los investigadores prepararon dos certificados con **prefijos distintos que eligieron ellos**. El primero era un certificado común para un sitio web, como el que RapidSSL firmaría sin dudar. El segundo era un certificado de **CA intermedia** (`CA = TRUE`), con la clave pública de los atacantes.
2. Con un ataque de **colisión de prefijo elegido** sobre MD5 calcularon unos bloques que, agregados a cada certificado, hacen que los dos tengan **el mismo hash MD5**. El cálculo corrió en más de 200 PlayStation 3 y tardó unas 18 horas [2].
3. Para que el certificado que firmaría la CA coincidiera exactamente con el que habían calculado, aprovecharon el número de serie secuencial y el tiempo de emisión fijo de RapidSSL [2].
4. Compraron el certificado de sitio web legítimo. RapidSSL lo firmó, es decir, firmó su hash MD5.
5. **Copiaron esa firma al certificado de CA falso.** Como los dos tienen el mismo hash, la firma es válida para ambos. El resultado fue una CA intermedia en la que confiaban todos los navegadores y que podía emitir certificados válidos para **cualquier** sitio, por ejemplo para hacer *man-in-the-middle* sobre HTTPS sin ninguna advertencia.

Los investigadores le pusieron al certificado falso una validez vencida a propósito (2004) para que no pudiera abusarse de él [2]. CERT/CC publicó la nota VU#836068 sobre el problema [7].

**Mismo ataque en un uso real y malicioso (Flame, 2012)** [5], [6], [8]: los atacantes usaron una **variante hasta entonces desconocida** del ataque de prefijo elegido sobre MD5 [8]. Fabricaron un certificado que encadenaba hasta la raíz de Microsoft y que funcionaba **en todas las versiones de Windows** [6]. Con él, el malware Flame quedaba firmado como si fuera software legítimo de Microsoft. Microsoft tuvo que invalidar toda la jerarquía de CAs de licencias de Terminal Server [5].

### A.4 — Lo correcto

Firmar certificados con una función de hash que siga siendo resistente a colisiones (SHA-256 o superior) y abandonar MD5 para firmas apenas se publicó su ruptura, como establece la RFC 6151 [9]. Como defensa adicional, agregar **aleatoriedad impredecible al contenido firmado**, por ejemplo números de serie aleatorios, para que el atacante no pueda anticipar qué va a firmar la CA [2].

### Fuentes (Parte A)

1. Stevens, M., Sotirov, A., Appelbaum, J., Lenstra, A., Molnar, D., Osvik, D. A. y de Weger, B. (2009). Short chosen-prefix collisions for MD5 and the creation of a rogue CA certificate. En S. Halevi (Ed.), *Advances in Cryptology — CRYPTO 2009* (LNCS 5677, pp. 55–69). Springer. https://doi.org/10.1007/978-3-642-03356-8_4 — **Arbitrada** (paper con revisión por pares).
2. Sotirov, A., Stevens, M., Appelbaum, J., Lenstra, A., Molnar, D., Osvik, D. A. y de Weger, B. (2008, 30 de diciembre). *MD5 considered harmful today: Creating a rogue CA certificate* [Presentación en el 25th Chaos Communication Congress, Berlín]. https://marc-stevens.nl/research/hashclash/rogue-ca/ — **Primaria** (publicación de los propios investigadores).
3. Wang, X. y Yu, H. (2005). How to break MD5 and other hash functions. En R. Cramer (Ed.), *Advances in Cryptology — EUROCRYPT 2005* (LNCS 3494, pp. 19–35). Springer. https://doi.org/10.1007/11426639_2 — **Arbitrada**.
4. Stevens, M., Lenstra, A. y de Weger, B. (2007). Chosen-prefix collisions for MD5 and colliding X.509 certificates for different identities. En M. Naor (Ed.), *Advances in Cryptology — EUROCRYPT 2007* (LNCS 4515, pp. 1–22). Springer. https://doi.org/10.1007/978-3-540-72540-4_1 — **Arbitrada**.
5. Microsoft. (2012, 3 de junio). *Microsoft Security Advisory 2718704: Unauthorized digital certificates could allow spoofing*. https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2718704 — **Primaria** (documento del fabricante).
6. Ness, J. (2012, 6 de junio). Flame malware collision attack explained. *Microsoft Security Response Center Blog*. https://www.microsoft.com/en-us/msrc/blog/2012/06/flame-malware-collision-attack-explained/ — **Primaria** (análisis técnico del fabricante).
7. CERT Coordination Center. (2008, 31 de diciembre). *Vulnerability Note VU#836068: MD5 vulnerable to collision attacks*. https://kb.cert.org/vuls/id/836068 — **Primaria** (aviso oficial).
8. Stevens, M. (2013). Counter-cryptanalysis. En *Advances in Cryptology — CRYPTO 2013* (LNCS 8042, pp. 129–146). Springer. Versión de acceso abierto: https://eprint.iacr.org/2013/358 — **Arbitrada**.
9. Turner, S. y Chen, L. (2011). *Updated security considerations for the MD5 message-digest and the HMAC-MD5 algorithms* (RFC 6151). IETF. https://www.rfc-editor.org/rfc/rfc6151 — **Primaria** (estándar).

## 2. Parte B.1 — Romper el XOR
*(clave hallada, mensaje en claro, y por qué el cifrado clásico falla)*

## 3. Parte B.2 — Autenticación
**B.2.1 length-extension · B.2.2 cómo lo resuelve HMAC · B.2.3 tiempo constante**

## 4. Bitácora
```bash
# python3 src/cripto.py romper --hex ...
```
