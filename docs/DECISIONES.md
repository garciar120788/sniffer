# Capturador y analizador de tráfico IPv4

**Documento de decisiones técnicas, versión 1.0**

---

## Índice

1. [Introducción](#1-introducción)
2. [Resumen de decisiones](#2-resumen-de-decisiones)
3. [Arquitectura](#3-arquitectura)
4. [Base de datos](#4-base-de-datos)
5. [Captura y procesamiento de paquetes](#5-captura-y-procesamiento-de-paquetes)
6. [Despliegue con Docker](#6-despliegue-con-docker)
7. [Limitaciones conocidas y mejoras propuestas](#7-limitaciones-conocidas-y-mejoras-propuestas)
8. [Verificación](#8-verificación)

---

## 1. Introducción

### 1.1 Propósito

Este documento describe y justifica las decisiones técnicas adoptadas en el diseño del **Capturador y analizador de tráfico IPv4**. Su objetivo es explicar no solo cómo está construida la solución, sino también por qué se eligió cada componente frente a las alternativas disponibles.

### 1.2 Alcance

El documento abarca:

- La arquitectura general de la aplicación.
- El diseño de la base de datos.
- El mecanismo de captura y procesamiento de paquetes.
- La configuración del despliegue en contenedores.
- Las limitaciones conocidas y el procedimiento de verificación.

Las instrucciones de instalación y uso se encuentran en el **[Manual de usuario](../README.md)**.

---

## 2. Resumen de decisiones

| Aspecto | Decisión adoptada | Justificación principal |
|---|---|---|
| Lenguaje | Python 3.12 | Lenguaje preferente según los requerimientos, con un ecosistema maduro para el análisis de redes |
| Captura | Scapy 2.6 (`AsyncSniffer`) | Herramienta sugerida en los requerimientos; interpreta IPv4, TCP y UDP sin necesidad de analizadores propios |
| Filtrado IPv4 | Filtro BPF `ip` en el kernel, validación en Python y restricción `CHECK` en la base de datos | Tres niveles de control que combinan eficiencia y garantía de integridad |
| Base de datos | PostgreSQL 16 | Tipo de dato `INET` nativo, carga masiva mediante `COPY` y agregaciones eficientes |
| Escritura | Hilo dedicado con cola y escritura por lotes mediante `COPY` | Evita que la base de datos limite la velocidad de captura |
| Estadísticas | Cálculo en memoria (tiempo real) y en SQL (histórico) | Respuesta inmediata durante la captura y consulta posterior por sesión |
| Contenedores | Docker Compose con los servicios `db` y `sniffer` | Despliegue con un único comando y aislamiento de la base de datos en un servicio propio |
| Red | `network_mode: host` | Permite al contenedor acceder a las interfaces físicas del equipo |
| Privilegios | `cap_drop: ALL` y `cap_add: NET_RAW` | Aplicación del principio de mínimo privilegio, en lugar de `privileged: true` |
| Configuración | Archivo `.env` (interfaz en la línea 25) | Punto único de configuración, sin modificar el código fuente |

---

## 3. Arquitectura

### 3.1 Diagrama general

```
                         EQUIPO LINUX (host)
 ┌────────────────────────────────────────────────────────────────────┐
 │  Interfaces físicas (p. ej. enp1s0, enp2s0, wlp3s0)                │
 │     │        │        │                                            │
 │     └────────┼────────┘   Kernel: filtro BPF "ip" (descarta IPv6,  │
 │              │            ARP y otros antes de llegar a Python)    │
 │  ┌───────────▼───────────────────────────────────────────┐         │
 │  │ Contenedor sniffer   (network_mode: host, NET_RAW)    │         │
 │  │                                                       │         │
 │  │  Hilo Scapy ──► parse_packet() ──► TrafficStats       │         │
 │  │  (AsyncSniffer)       │            (contadores en     │         │
 │  │                       │             memoria)          │         │
 │  │                       ▼                               │         │
 │  │               queue.Queue (100 000)                   │         │
 │  │                       │                               │         │
 │  │  Hilo DBWriter ◄──────┘  lotes de 500 o cada 1 s      │         │
 │  │        │  COPY ... FROM STDIN                         │         │
 │  └────────┼──────────────────────────────────────────────┘         │
 │           │ 127.0.0.1:5432                                         │
 │  ┌────────▼──────────────────┐                                     │
 │  │ Contenedor db (PostgreSQL)│◄── volumen pgdata (persistente)     │
 │  └───────────────────────────┘                                     │
 └────────────────────────────────────────────────────────────────────┘
```

### 3.2 Módulos

| Módulo | Responsabilidad |
|---|---|
| `config.py` | Lectura de la configuración desde variables de entorno (`.env`) |
| `parser.py` | Conversión de cada paquete Scapy en un registro (`PacketRecord`) y descarte del tráfico no IPv4 |
| `stats.py` | Contadores seguros para concurrencia entre hilos y presentación de resultados en tablas |
| `writer.py` | Hilo consumidor responsable de la escritura por lotes |
| `db.py` | Creación del esquema, gestión de sesiones, carga mediante `COPY` y consultas de estadísticas |
| `capture.py` | Control de la captura: Scapy, señales del sistema, límites y cierre ordenado |
| `cli.py` | Interfaz de línea de comandos: `capture`, `stats`, `sessions` e `interfaces` |

Cada módulo tiene una única responsabilidad. Esta separación permite probar el análisis de paquetes y el cálculo de estadísticas de forma aislada, sin red ni base de datos.

---

## 4. Base de datos

### 4.1 Selección del motor

Se evaluaron dos alternativas: SQLite y PostgreSQL.

| Criterio | SQLite | PostgreSQL (seleccionado) |
|---|---|---|
| Tipo de dato para direcciones IP | `TEXT` | **`INET`**: valida el formato, admite la restricción `CHECK (family(ip) = 4)` y permite búsquedas por subred (`ip << '10.0.0.0/8'`) |
| Inserción masiva | `executemany` | **`COPY`**: decenas de miles de filas por segundo |
| Concurrencia | Un único escritor, con bloqueo del archivo | Lectura simultánea durante la captura (`stats` mientras se ejecuta `capture`) |
| Integración con Docker | Archivo en un volumen | Servicio independiente con verificación de estado (*healthcheck*) |
| Escalabilidad | Limitada | Particionado, réplicas e integración con herramientas de monitoreo |

SQLite habría sido suficiente para el volumen de datos de una prueba. Se seleccionó PostgreSQL porque el tipo `INET` y el mecanismo `COPY` se ajustan directamente a los requerimientos y porque representa una configuración cercana a un entorno de producción.

### 4.2 Modelo de datos

```
┌──────────────────────────────┐          ┌───────────────────────────────────┐
│ capture_sessions             │          │ packets                           │
├──────────────────────────────┤          ├───────────────────────────────────┤
│ id              BIGSERIAL PK │◄────┐    │ id              BIGSERIAL PK      │
│ interfaces      TEXT[]       │     └────┤ session_id      BIGINT FK         │
│ bpf_filter      TEXT         │   1 : N  │ captured_at     TIMESTAMPTZ       │
│ started_at      TIMESTAMPTZ  │          │ interface       TEXT              │
│ ended_at        TIMESTAMPTZ  │          │ src_ip          INET  (IPv4)  *   │
│ total_packets   BIGINT       │          │ dst_ip          INET  (IPv4)  *   │
│ dropped_packets BIGINT       │          │ protocol        VARCHAR(10)   *   │
└──────────────────────────────┘          │ length          INTEGER       *   │
                                          │ protocol_number SMALLINT          │
                                          │ src_port        INTEGER NULL      │
                                          │ dst_port        INTEGER NULL      │
                                          └───────────────────────────────────┘
                                           * = campos exigidos en los requerimientos
```

La definición completa y comentada del esquema se encuentra en el archivo [`sql/schema.sql`](../sql/schema.sql).

### 4.3 Justificación del diseño

#### Tabla `capture_sessions`

- **Una sesión por ejecución.** Cada captura se registra como una sesión independiente. Así es posible analizar y comparar por separado las capturas realizadas en distintas interfaces (`stats --session N`), en lugar de acumular todo el tráfico sin contexto.
- **Trazabilidad.** Se almacenan el filtro BPF y las interfaces utilizadas, de modo que cada captura es auditable y reproducible.
- **Capturas interrumpidas.** Un valor nulo en `ended_at` identifica las capturas que no finalizaron correctamente, por ejemplo por un corte de energía.
- **Pérdidas.** El campo `dropped_packets` registra los paquetes descartados por saturación.

#### Tabla `packets`

- **Direcciones IP (`src_ip`, `dst_ip`) de tipo `INET` en lugar de `TEXT`:**
  - Ocupan 7 bytes, frente a los 7 a 15 bytes de su representación en texto.
  - Validan el formato y se ordenan numéricamente (`10.0.0.9` antes que `10.0.0.10`).
  - Admiten operadores de red, como la pertenencia a una subred.
- **Restricción `CHECK (family(src_ip) = 4)`.** La propia base de datos rechaza direcciones IPv6, aun si un error en la aplicación intentara insertarlas. Este comportamiento se verificó durante las pruebas (`ERROR: new row ... violates check constraint "packets_dst_ipv4"`).
- **Protocolo en dos campos.** `protocol` almacena el nombre (TCP, UDP, ICMP), lo que facilita la lectura y las agrupaciones. `protocol_number` conserva el valor numérico exacto cuando el protocolo se clasifica como `OTHER`.
- **Tamaño (`length`).** Corresponde a la longitud de la trama capturada (`len(pkt)`), incluida la cabecera Ethernet. Es el mismo valor que muestran Wireshark y tcpdump en la columna *Length* y constituye la medida estándar del tráfico en el enlace. La alternativa, la longitud del datagrama IP (`ip.len`), excluiría la capa de enlace.
- **Puertos (`src_port`, `dst_port`) opcionales.**
  - Solo se registran para TCP y UDP, ya que los demás protocolos carecen de ellos.
  - Su costo de almacenamiento es mínimo y su valor analítico es alto, por ejemplo para identificar los servicios utilizados.
  - Los fragmentos IPv4 no iniciales no contienen cabecera de transporte, por lo que se registran como `NULL` en lugar de asignar valores incorrectos.
- **Marca de tiempo (`captured_at`).** Corresponde al instante de captura registrado por el kernel (`pkt.time`), en UTC, y no al momento de inserción, que puede diferir por la escritura en lotes.
- **Interfaz (`interface`).** Es imprescindible para distinguir el origen de cada paquete cuando se capturan varias interfaces simultáneamente.
- **Borrado en cascada (`ON DELETE CASCADE`).** Al eliminar una sesión se eliminan automáticamente sus paquetes asociados.

#### Índices

Todas las consultas de estadísticas siguen el mismo patrón: filtran por sesión y agrupan por un campo. Por ello, los índices son compuestos y tienen `session_id` como primera columna:

| Índice | Consulta optimizada |
|---|---|
| `(session_id, src_ip)` | Cinco direcciones IP de origen con más tráfico |
| `(session_id, dst_ip)` | Cinco direcciones IP de destino con más tráfico |
| `(session_id, protocol)` | Distribución de paquetes por protocolo |
| `(captured_at)` | Consultas por rango de tiempo |

No se definieron índices adicionales, porque cada índice incrementa el costo de inserción en una tabla de escritura intensiva.

#### Normalización

Las direcciones IP y los protocolos no se separaron en tablas independientes. Con el tipo `INET`, cada dirección ocupa un espacio comparable al de una clave foránea; separarlas solo añadiría una operación `JOIN` en cada consulta e inserción, sin beneficio en almacenamiento.

### 4.4 Creación del esquema

La aplicación ejecuta el archivo `sql/schema.sql` en cada inicio. Todas sus sentencias utilizan la cláusula `IF NOT EXISTS`, por lo que la operación es idempotente.

Se descartó el mecanismo de inicialización de la imagen oficial de PostgreSQL (`/docker-entrypoint-initdb.d`), porque **solo se ejecuta cuando el volumen de datos está vacío**: ante un cambio de esquema, una base de datos existente no se actualizaría. El enfoque adoptado mantiene una única fuente de verdad que se aplica siempre.

---

## 5. Captura y procesamiento de paquetes

### 5.1 Selección de la herramienta de captura

| Alternativa | Motivo del descarte |
|---|---|
| Sockets `AF_PACKET` nativos | Requiere implementar manualmente la interpretación de IPv4, TCP y UDP, con mayor volumen de código y riesgo de errores |
| PyShark | Depende de `tshark`, lo que incrementa el tamaño de la imagen en cientos de megabytes y reduce el rendimiento |
| tcpdump con análisis de su salida en texto | Solución frágil ante cambios de formato y difícil de mantener |
| **Scapy (seleccionada)** | Sugerida en los requerimientos; interpreta protocolos, admite filtros BPF y captura en varias interfaces |

La captura se realiza con `AsyncSniffer`, que se ejecuta en un hilo propio. De este modo, el hilo principal permanece disponible para mostrar el progreso, controlar el tiempo límite y atender la señal de interrupción (Ctrl+C).

### 5.2 Restricción a IPv4: control en tres niveles

1. **Kernel (filtro BPF `ip`).** El filtro se compila e instala en el socket de captura, de modo que el tráfico IPv6, ARP, LLDP y de otros tipos **no llega a la aplicación**, con el consiguiente ahorro de procesamiento. Cualquier filtro adicional definido por el usuario se combina como `ip and (<filtro>)`, lo que impide incluir tráfico no IPv4.
2. **Aplicación (`parse_packet`).** Cada paquete se valida explícitamente (`if IP not in pkt: return None`). Este control cubre la lectura de archivos `.pcap`, donde no interviene el filtro del kernel.
3. **Base de datos (`CHECK family = 4`).** Constituye la garantía final de integridad de los datos almacenados.

### 5.3 Rendimiento: modelo productor-consumidor

La inserción individual de cada paquete, con su propia transacción, tiene un costo del orden de milisegundos. Con tasas de cientos de paquetes por segundo, la captura se bloquearía y el kernel descartaría paquetes. Para evitarlo se adoptó un modelo productor-consumidor:

- **Hilo de captura (productor).** Analiza el paquete, actualiza los contadores y lo deposita en una cola mediante `put_nowait()`, una operación del orden de microsegundos.
- **Hilo de escritura (consumidor).** Agrupa los paquetes en lotes de `BATCH_SIZE` elementos (500 por defecto), o los escribe cada `FLUSH_INTERVAL` segundos (1 por defecto), mediante **`COPY`**, el mecanismo de carga más rápido de PostgreSQL.
- **Cola de capacidad limitada (100 000 elementos).** Si la base de datos deja de estar disponible o no procesa al ritmo necesario, los paquetes excedentes se descartan **y se contabilizan** en `dropped_packets`, en lugar de consumir toda la memoria disponible. Se prioriza una degradación controlada y visible frente a una falla por agotamiento de memoria.

En las pruebas se sostuvo una tasa aproximada de 500 paquetes por segundo (una descarga de 33 MB) sin ninguna pérdida.

### 5.4 Cálculo de estadísticas

Las estadísticas se calculan por dos vías complementarias:

- **En memoria** (`TrafficStats`, con contadores protegidos por un bloqueo). Permite mostrar el progreso en tiempo real y presentar el informe final de inmediato, sin consultar la base de datos.
- **En SQL** (comando `stats`). Permite consultar cualquier sesión anterior, o el conjunto de todas ellas, mediante agregaciones ejecutadas por PostgreSQL.

Ambas vías generan la misma estructura de resultados (`StatsSnapshot`) y se presentan con la misma función, por lo que el formato de salida es idéntico.

**Criterio para "direcciones IP con más tráfico".** El requerimiento admite dos interpretaciones: mayor número de paquetes o mayor volumen en bytes. Se presentan **ambas clasificaciones**, porque reflejan comportamientos distintos: un escaneo de red genera numerosos paquetes de pequeño tamaño, mientras que una descarga genera pocos paquetes de gran volumen. Cada tabla incluye, además, los porcentajes sobre el total.

### 5.5 Cierre ordenado

La aplicación intercepta las señales `SIGINT` (Ctrl+C) y `SIGTERM` (`docker stop`). Al recibir cualquiera de ellas, ejecuta la siguiente secuencia:

1. Detiene la captura de Scapy.
2. Vacía la cola y escribe el último lote en la base de datos.
3. Registra el cierre de la sesión, con su hora de finalización y los totales.
4. Presenta las estadísticas finales.

En el archivo `docker-compose.yml`, los parámetros `stop_signal: SIGINT` y `stop_grace_period: 30s` aseguran que `docker compose stop` produzca el mismo comportamiento que la interrupción manual.

---

## 6. Despliegue con Docker

### 6.1 Modo de red `host`

Con la red predeterminada de Docker (*bridge*), el contenedor solo dispone de una interfaz virtual y observa únicamente su propio tráfico. Para capturar el tráfico de las interfaces físicas, el contenedor debe compartir la pila de red del equipo anfitrión.

Como consecuencia, la aplicación accede a la base de datos a través de `127.0.0.1`. Por ese motivo, PostgreSQL se publica **exclusivamente en `127.0.0.1`** y no en `0.0.0.0`, de modo que no es accesible desde otros equipos de la red.

### 6.2 Principio de mínimo privilegio

La alternativa más sencilla habría sido ejecutar el contenedor con `privileged: true`, que le otorga acceso a todos los dispositivos y capacidades del sistema anfitrión. En su lugar se adoptó la siguiente configuración:

- Se eliminan **todas** las capacidades de Linux (`cap_drop: ALL`).
- Se añade únicamente **`NET_RAW`**, necesaria para abrir sockets de captura `AF_PACKET`.
- **No se requiere `NET_ADMIN`**, ya que Scapy activa el modo promiscuo mediante `setsockopt(PACKET_ADD_MEMBERSHIP)` sobre el propio socket de captura, y no mediante `ioctl(SIOCSIFFLAGS)`.

Esta configuración se verificó experimentalmente:

- Sin capacidades, la captura falla por falta de permisos y la aplicación informa el error de forma explícita.
- Con la capacidad `NET_RAW` como única excepción, la captura funciona correctamente.

El proceso se ejecuta como `root` dentro del contenedor, pero sin capacidades adicionales a `NET_RAW`, por lo que su margen de acción sobre el sistema es muy reducido.

### 6.3 Imagen de la aplicación

- **Imagen base `python:3.12-slim-bookworm`.** Distribución Debian mínima con una versión estable de Python y soporte a largo plazo. Se fija la versión de Debian (`bookworm`) para que la construcción no cambie cuando la etiqueta genérica `slim` pase a apuntar a una versión distinta.
- **Paquetes del sistema:**
  - `tcpdump`, que instala `libpcap` como dependencia. Scapy los utiliza para **compilar los filtros BPF**; sin ellos, el filtrado no funciona.
  - `iproute2`, para tareas de diagnóstico de red.
- **Orden de las capas.** Las dependencias (`requirements.txt`) se instalan antes de copiar el código fuente, de modo que una modificación del código no obliga a reinstalarlas.
- **Versiones fijadas** (`scapy==2.6.1` y demás). Garantizan construcciones reproducibles.
- **Exclusión de credenciales.** El archivo `.dockerignore` excluye `.env`, de modo que las credenciales no quedan incorporadas en la imagen.

### 6.4 Orquestación de servicios

- **Dependencia con verificación de estado.** `depends_on` con `condition: service_healthy` y `pg_isready` impide que el capturador se inicie antes de que la base de datos acepte conexiones. Adicionalmente, la aplicación reintenta la conexión hasta 10 veces.
- **Persistencia.** El volumen `pgdata` conserva los datos tras la ejecución de `docker compose down`.
- **Terminal interactiva.** Los parámetros `tty` y `stdin_open` permiten la presentación con colores y la interrupción con Ctrl+C en `docker compose run`.
- **Carpeta `samples`.** Se monta en el contenedor para que el usuario pueda procesar sus propios archivos `.pcap` con la opción `--pcap`.

### 6.5 Configuración mediante `.env`

Toda la configuración se centraliza en el archivo `.env`, y la interfaz de red, en particular, en **una única línea** (la 25), delimitada por un bloque de comentarios. Esta decisión se fundamenta en lo siguiente:

- El cambio de interfaz no requiere modificar el código, reconstruir la imagen ni editar archivos YAML.
- Se ajusta al principio de configuración por entorno de la metodología *Twelve-Factor App*.
- La opción `--iface` de la línea de comandos tiene prioridad, lo que facilita las pruebas puntuales.

---

## 7. Limitaciones conocidas y mejoras propuestas

| Limitación | Descripción | Mejora propuesta |
|---|---|---|
| Rendimiento de Scapy | Al estar implementado en Python, es adecuado para tasas de cientos a pocos miles de paquetes por segundo, pero no para enlaces saturados de alta capacidad (10 Gbps) | Captura mediante `AF_PACKET` con `TPACKET_V3`, o un componente de captura en Go o Rust |
| Interfaces inalámbricas en modo *managed* | Solo se observa el tráfico del propio equipo | Modo monitor, que requiere un adaptador compatible y captura tramas 802.11 |
| Interfaces Ethernet conectadas a un switch | Solo se observa el tráfico propio y el de difusión | Configurar un puerto de réplica (*port mirroring* o SPAN) en el switch |
| Agrupación de segmentos en la tarjeta de red (GRO/TSO) | Pueden registrarse paquetes de más de 1500 bytes, porque el kernel agrupa segmentos antes de la captura | Desactivar la agrupación con `ethtool -K <interfaz> gro off` cuando se requiera el tamaño exacto en el medio físico |
| Filtro BPF en el procesamiento de archivos `.pcap` | Scapy aplicaría el filtro mediante `tcpdump -r`, que intenta cambiar de usuario (`setuid`) y falla sin la capacidad `CAP_SETUID`. En este modo solo se aplica el filtrado IPv4 de la aplicación | Filtrar previamente el archivo con tcpdump o Wireshark en el equipo anfitrión |
| Crecimiento de la tabla `packets` | No existe una política de retención de datos | Particionar la tabla por fecha o implementar una tarea periódica de depuración |
| Credenciales | Se almacenan en texto plano en el archivo `.env` | Utilizar Docker Secrets o un gestor de secretos |
| Captura en las interfaces `lo` o `docker0` | Se registra el propio tráfico de escritura hacia la base de datos | Capturar en interfaces físicas o aplicar el filtro `not port 5432` |

---

## 8. Verificación

La solución se validó mediante las siguientes pruebas:

| Prueba | Resultado |
|---|---|
| Pruebas automatizadas (pytest) | 12 pruebas superadas, tanto en el entorno local como dentro del contenedor |
| Captura real en una interfaz Ethernet con tráfico HTTPS, DNS e ICMP | 5 217 paquetes capturados y 5 217 almacenados, sin pérdidas |
| Captura simultánea en dos interfaces | Distribución correcta del tráfico por interfaz |
| Detención mediante Ctrl+C y `docker compose stop` | En ambos casos se almacenaron los paquetes pendientes y se presentaron las estadísticas finales |
| Restricción IPv4 en la base de datos | Se rechazó el intento manual de insertar la dirección IPv6 `::1` |
| Capacidades del contenedor | La captura funciona solo con `NET_RAW` y, sin ella, falla con un mensaje explícito |
| Procesamiento del archivo de ejemplo | Resultado exacto: 60 paquetes IPv4 (30 TCP, 20 UDP y 10 ICMP); se descartaron 5 paquetes IPv6 y 3 ARP |
