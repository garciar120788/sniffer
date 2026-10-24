# Capturador y analizador de tráfico IPv4

**Manual de usuario, versión 1.0**

---

> **Aviso importante: selección de la interfaz de red**
>
> La interfaz de red que se va a monitorear se configura en un único lugar: el archivo **`.env`**, **línea 25** (variable `CAPTURE_IFACE`). No es necesario modificar el código fuente ni el archivo `docker-compose.yml`. El procedimiento completo se describe en la sección [4.2 Selección de la interfaz de red](#42-selección-de-la-interfaz-de-red).

---

## Índice

1. [Introducción](#1-introducción)
2. [Requisitos del sistema](#2-requisitos-del-sistema)
3. [Instalación](#3-instalación)
4. [Configuración](#4-configuración)
5. [Operación](#5-operación)
6. [Interpretación de los resultados](#6-interpretación-de-los-resultados)
7. [Procedimiento de prueba en varias interfaces](#7-procedimiento-de-prueba-en-varias-interfaces)
8. [Consulta directa de la base de datos](#8-consulta-directa-de-la-base-de-datos)
9. [Pruebas automatizadas](#9-pruebas-automatizadas)
10. [Solución de problemas](#10-solución-de-problemas)
11. [Detención y mantenimiento](#11-detención-y-mantenimiento)
12. [Anexo: estructura del proyecto](#12-anexo-estructura-del-proyecto)

---

## 1. Introducción

### 1.1 Propósito

Este documento describe la instalación, configuración y operación del **Capturador y analizador de tráfico IPv4**, una aplicación desarrollada en Python que captura paquetes de red, los almacena en una base de datos PostgreSQL y genera estadísticas sobre el tráfico observado.

### 1.2 Alcance

La aplicación se ejecuta en contenedores Docker sobre un sistema operativo Linux. Procesa **exclusivamente tráfico IPv4**: los paquetes IPv6, ARP y de cualquier otro tipo se descartan antes de su análisis.

### 1.3 Funcionalidades

**Captura de paquetes.** La aplicación escucha una o varias interfaces de red y registra, por cada paquete:

| Campo | Descripción |
|---|---|
| Dirección IP de origen | Dirección IPv4 del emisor |
| Dirección IP de destino | Dirección IPv4 del receptor |
| Protocolo | TCP, UDP, ICMP u otro protocolo de transporte |
| Tamaño del paquete | Longitud de la trama en bytes |
| Datos complementarios | Fecha y hora de captura, interfaz de red y puertos TCP/UDP |

**Análisis de tráfico.** Al finalizar cada captura, la aplicación presenta:

- El número total de paquetes capturados.
- El número de paquetes por protocolo.
- Las cinco direcciones IP de origen con más tráfico, por número de paquetes y por volumen en bytes.
- Las cinco direcciones IP de destino con más tráfico, por número de paquetes y por volumen en bytes.
- La distribución por interfaz, cuando se capturan varias simultáneamente.

**Almacenamiento.** Todos los paquetes capturados se guardan en una base de datos PostgreSQL, organizados por sesión de captura, para su consulta posterior.

### 1.4 Documentación relacionada

La justificación de las decisiones técnicas, el diseño de la base de datos y las limitaciones conocidas se encuentran en el documento **[docs/DECISIONES.md](docs/DECISIONES.md)**.

---

## 2. Requisitos del sistema

| Componente | Requisito |
|---|---|
| Sistema operativo | Linux, cualquier distribución compatible con Docker |
| Motor de contenedores | Docker Engine 24 o superior |
| Orquestador | Plugin Docker Compose v2 |
| Conectividad | Acceso a Internet durante la primera instalación, para descargar las imágenes `python:3.12-slim-bookworm` y `postgres:16-alpine` |
| Permisos | Usuario con privilegios de administración (`sudo`) o perteneciente al grupo `docker` |

> **Nota:** la aplicación debe ejecutarse en un sistema **Linux nativo**. En Docker Desktop para macOS o Windows, el modo de red `host` no tiene acceso a las interfaces físicas del equipo, por lo que la captura no reflejaría el tráfico real.

---

## 3. Instalación

### 3.1 Instalación de Docker

Si Docker no está instalado en el equipo, se recomienda seguir la guía oficial de Docker Engine correspondiente a la distribución utilizada, disponible en <https://docs.docker.com/engine/install/>. Dicha guía incluye la instalación del plugin Docker Compose.

Como alternativa, Docker proporciona un script de instalación oficial que detecta la distribución automáticamente:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

Para ejecutar Docker sin `sudo`, agregue su usuario al grupo `docker` y vuelva a iniciar sesión:

```bash
sudo usermod -aG docker $USER
```

Para verificar la instalación, ejecute:

```bash
docker --version
docker compose version
```

Ambos comandos deben mostrar el número de versión instalada.

### 3.2 Obtención del proyecto

Clone el repositorio y acceda a la carpeta del proyecto:

```bash
git clone https://github.com/garciar120788/sniffer.git
cd sniffer
```

Todos los comandos indicados en este manual deben ejecutarse desde esta carpeta.

### 3.3 Construcción de la imagen

Ejecute el siguiente comando para construir la imagen de la aplicación:

```bash
docker compose build
```

Este paso solo es necesario la primera vez o cuando se modifique el código fuente.

---

## 4. Configuración

### 4.1 Archivo de configuración

Toda la configuración de la aplicación se define en el archivo **`.env`**, ubicado en la raíz del proyecto. Docker Compose lee este archivo automáticamente y transfiere sus valores al contenedor.

### 4.2 Selección de la interfaz de red

La interfaz que se va a monitorear se define en la **línea 25** del archivo `.env`:

```
sniffer/
└── .env        <-- línea 25:  CAPTURE_IFACE=enp1s0
```

Para facilitar su localización, la línea está delimitada por un bloque de comentarios:

```ini
# #####################################################################
# >>>>>>>>>>>>>>>  MODIFIQUE AQUÍ LA INTERFAZ DE RED  <<<<<<<<<<<<<<<<
# #####################################################################
...
CAPTURE_IFACE=enp1s0
```

No es necesario modificar el código fuente ni el archivo `docker-compose.yml`, que únicamente lee esta variable (`CAPTURE_IFACE: ${CAPTURE_IFACE}`, línea 53).

#### Paso 1: identificar las interfaces disponibles

Ejecute el siguiente comando para listar las interfaces de red del equipo:

```bash
ip -br addr
```

El resultado tiene un formato similar al siguiente (los nombres varían según el equipo):

```
lo        UNKNOWN  127.0.0.1/8
enp1s0    UP       192.168.1.50/24      <- Ethernet 1
enp2s0    UP       10.0.0.20/24         <- Ethernet 2
wlp3s0    UP       192.168.1.80/24      <- Wi-Fi
docker0   DOWN     172.17.0.1/16        <- interfaz virtual de Docker
```

Las distribuciones Linux actuales asignan nombres predecibles a las interfaces:

| Prefijo | Tipo de interfaz |
|---|---|
| `en...` (p. ej. `enp1s0`) | Ethernet por cable |
| `wl...` (p. ej. `wlp3s0`) | Inalámbrica (Wi-Fi) |
| `eth...` / `wlan...` | Nomenclatura tradicional, presente en algunos sistemas |
| `lo`, `docker0`, `br-...`, `veth...` | Interfaces virtuales; no se recomienda su uso para la captura |

La aplicación ofrece también un comando que lista las interfaces con su tipo y dirección IPv4:

```bash
docker compose run --rm sniffer interfaces
```

#### Paso 2: asignar la interfaz

Existen tres métodos para indicar la interfaz:

| Método | Procedimiento | Uso recomendado |
|---|---|---|
| **A. Archivo `.env`** (recomendado) | Modificar la línea 25, p. ej. `CAPTURE_IFACE=wlp3s0` | Configuración permanente |
| **B. Línea de comandos** | `docker compose run --rm sniffer capture --iface wlp3s0` | Pruebas puntuales, sin modificar archivos |
| **C. Variable de entorno** | `CAPTURE_IFACE=wlp3s0 docker compose run --rm sniffer` | Automatización mediante scripts |

Si se utilizan varios métodos al mismo tiempo, se aplica el siguiente orden de prioridad: **línea de comandos > variable de entorno > archivo `.env`**.

Para capturar en varias interfaces simultáneamente, separe sus nombres con comas:

```ini
CAPTURE_IFACE=enp1s0,enp2s0,wlp3s0
```

En este caso, cada paquete registra la interfaz por la que fue recibido y los resultados incluyen la tabla "Paquetes por interfaz".

### 4.3 Parámetros de configuración

| Parámetro | Valor por defecto | Descripción |
|---|---|---|
| `CAPTURE_IFACE` | *(según el equipo)* | Interfaz o interfaces de red que se van a capturar |
| `CAPTURE_FILTER` | *(vacío)* | Filtro BPF adicional. Siempre se combina con `ip` para restringir la captura a IPv4 |
| `CAPTURE_COUNT` | `0` | Número de paquetes tras el cual se detiene la captura (`0` = sin límite) |
| `CAPTURE_TIMEOUT` | `0` | Duración máxima de la captura en segundos (`0` = sin límite) |
| `STATS_INTERVAL` | `5` | Intervalo en segundos entre los mensajes de progreso (`0` = desactivado) |
| `BATCH_SIZE` | `500` | Número de paquetes por lote de escritura en la base de datos |
| `FLUSH_INTERVAL` | `1` | Tiempo máximo en segundos antes de escribir un lote incompleto |
| `QUEUE_SIZE` | `100000` | Capacidad de la cola interna de paquetes pendientes de escritura |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD` | `sniffer` | Credenciales de la base de datos |
| `DB_PORT` | `5432` | Puerto de PostgreSQL, publicado únicamente en `127.0.0.1` |

---

## 5. Operación

### 5.1 Inicio de la base de datos

Inicie el servicio de base de datos en segundo plano:

```bash
docker compose up -d db
```

Este paso es opcional: el servicio se inicia automáticamente al ejecutar una captura si no estaba activo.

### 5.2 Ejecución de una captura

Para iniciar una captura con la configuración definida en `.env`, ejecute:

```bash
docker compose run --rm sniffer
```

Durante la captura, la aplicación muestra periódicamente una línea de progreso con el número de paquetes, el volumen y la distribución por protocolo.

### 5.3 Finalización de una captura

La captura finaliza en cualquiera de los siguientes casos:

- El usuario presiona **Ctrl+C**.
- Se alcanza el número de paquetes indicado en `CAPTURE_COUNT` o `--count`.
- Se cumple el tiempo indicado en `CAPTURE_TIMEOUT` o `--timeout`.

Al finalizar, la aplicación realiza las siguientes acciones:

1. Guarda en la base de datos los paquetes pendientes.
2. Registra el cierre de la sesión de captura.
3. Presenta las estadísticas finales.

### 5.4 Ejecución en segundo plano

Para capturas de larga duración, la aplicación puede ejecutarse como servicio:

| Acción | Comando |
|---|---|
| Iniciar la captura en segundo plano | `docker compose up -d sniffer` |
| Consultar el progreso | `docker compose logs -f sniffer` |
| Detener la captura de forma ordenada | `docker compose stop sniffer` |
| Consultar las estadísticas finales | `docker compose logs sniffer` |

### 5.5 Comandos disponibles

| Comando | Descripción |
|---|---|
| `docker compose run --rm sniffer` | Inicia una captura con la configuración de `.env` |
| `docker compose run --rm sniffer capture [opciones]` | Inicia una captura con opciones específicas |
| `docker compose run --rm sniffer stats` | Muestra las estadísticas de la última sesión |
| `docker compose run --rm sniffer stats --session N` | Muestra las estadísticas de la sesión N |
| `docker compose run --rm sniffer stats --all` | Muestra las estadísticas acumuladas de todas las sesiones |
| `docker compose run --rm sniffer sessions` | Lista las sesiones de captura registradas |
| `docker compose run --rm sniffer interfaces` | Lista las interfaces de red disponibles |
| `docker compose run --rm sniffer --help` | Muestra la ayuda general |
| `docker compose run --rm sniffer capture --help` | Muestra la ayuda del comando de captura |

### 5.6 Opciones del comando `capture`

| Opción | Parámetro equivalente | Descripción |
|---|---|---|
| `-i`, `--iface IFACE` | `CAPTURE_IFACE` | Interfaz o interfaces. Admite repetición (`-i a -i b`) o lista separada por comas (`-i a,b`) |
| `-f`, `--filter BPF` | `CAPTURE_FILTER` | Filtro BPF adicional, combinado siempre con `ip` |
| `-c`, `--count N` | `CAPTURE_COUNT` | Detiene la captura tras N paquetes IPv4 |
| `-t`, `--timeout SEG` | `CAPTURE_TIMEOUT` | Detiene la captura tras SEG segundos |
| `--stats-interval SEG` | `STATS_INTERVAL` | Intervalo de los mensajes de progreso |
| `--pcap ARCHIVO` | — | Procesa un archivo `.pcap` en lugar de una interfaz |
| `--no-db` | — | Muestra estadísticas sin guardar los paquetes en la base de datos |

### 5.7 Ejemplos de uso

```bash
# Captura de 30 segundos en la interfaz inalámbrica
docker compose run --rm sniffer capture --iface wlp3s0 --timeout 30

# Captura de 1000 paquetes en la segunda interfaz Ethernet
docker compose run --rm sniffer capture -i enp2s0 -c 1000

# Captura exclusiva de tráfico HTTPS
docker compose run --rm sniffer capture -i enp1s0 -f "tcp port 443"

# Captura que excluye el tráfico SSH (recomendado en sesiones remotas)
docker compose run --rm sniffer capture -i enp1s0 -f "not port 22"

# Captura simultánea en varias interfaces durante 1 minuto
docker compose run --rm sniffer capture -i enp1s0,enp2s0,wlp3s0 -t 60

# Procesamiento del archivo de ejemplo (no requiere tráfico de red)
docker compose run --rm sniffer capture --pcap samples/ejemplo.pcap
```

---

## 6. Interpretación de los resultados

### 6.1 Información durante la captura

Al iniciar, la aplicación muestra los parámetros de la sesión y, a continuación, una línea de progreso cada `STATS_INTERVAL` segundos:

```
──────────────────────── Capturador de paquetes IPv4 ────────────────────────
Fuente:      enp1s0
Filtro BPF:  ip
Límites:     paquetes=sin límite  tiempo=60 s
Base datos:  sesión #1
Pulsa Ctrl+C para detener la captura y ver las estadísticas.
[     5s] paquetes=1199  bytes=10.72 MB  (385.8 paq/s)  TCP=1195  UDP=4
[    10s] paquetes=3140  bytes=21.75 MB  (513.7 paq/s)  TCP=3134  UDP=6
```

| Campo | Significado |
|---|---|
| Fuente | Interfaz o interfaces en captura |
| Filtro BPF | Filtro efectivo aplicado en el kernel |
| Límites | Condiciones de finalización configuradas |
| Base datos | Número de la sesión asignada en la base de datos |
| Línea de progreso | Tiempo transcurrido, paquetes, volumen, tasa por segundo y distribución por protocolo |

### 6.2 Informe final

Al concluir la captura, se presenta el informe de estadísticas. El siguiente ejemplo corresponde a una ejecución real (se omiten algunas tablas):

```
────────────────────────── Estadísticas de la captura ──────────────────────────
Número total de paquetes capturados: 5,217    Volumen total: 33.54 MB
Paquetes por protocolo
┏━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ # ┃ Protocolo ┃ Paquetes ┃ % paq. ┃    Bytes ┃ % bytes ┃
┡━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ 1 │ TCP       │    5,211 │ 99.9 % │ 33.54 MB │ 100.0 % │
│ 2 │ UDP       │        6 │  0.1 % │    588 B │   0.0 % │
└───┴───────────┴──────────┴────────┴──────────┴─────────┘
Top 5 IP de ORIGEN (por número de paquetes)
┏━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┓
┃ # ┃ IP origen      ┃ Paquetes ┃ % paq. ┃     Bytes ┃ % bytes ┃
┡━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━┩
│ 1 │ 151.101.64.223 │    3,390 │ 65.0 % │  33.41 MB │  99.6 % │
│ 2 │ 192.0.2.2      │    1,758 │ 33.7 % │ 117.88 KB │   0.3 % │
│ 3 │ 160.79.104.10  │       66 │  1.3 % │  10.91 KB │   0.0 % │
│ 4 │ 8.8.8.8        │        3 │  0.1 % │     358 B │   0.0 % │
└───┴────────────────┴──────────┴────────┴───────────┴─────────┘
Top 5 IP de ORIGEN (por bytes)          ...
Top 5 IP de DESTINO (por número de paquetes)   ...
Top 5 IP de DESTINO (por bytes)         ...
Guardados en BD: 5,217 paquetes (sesión #1). Descartados por cola llena: 0. Fallidos al insertar: 0.
```

El informe se compone de los siguientes elementos:

| Elemento | Contenido |
|---|---|
| Total de paquetes y volumen | Número de paquetes IPv4 capturados y bytes acumulados |
| Paquetes por protocolo | Distribución por protocolo, en valores absolutos y porcentuales |
| Paquetes por interfaz | Se muestra solo cuando la captura incluye más de una interfaz |
| Top 5 IP de origen y de destino | Dos clasificaciones para cada caso: por número de paquetes y por volumen en bytes |
| Resumen de almacenamiento | Paquetes guardados en la base de datos, descartados por saturación de la cola y fallidos al insertar |

> **Nota:** se presentan dos clasificaciones porque reflejan comportamientos distintos. Una dirección con muchos paquetes pequeños (por ejemplo, un escaneo) puede tener poco volumen, mientras que una descarga genera pocos paquetes de gran tamaño.

---

## 7. Procedimiento de prueba en varias interfaces

Esta sección describe el procedimiento para validar la captura en cada una de las interfaces del equipo. Se recomienda realizar una sesión de captura por interfaz y comparar los resultados al final.

El procedimiento requiere **dos terminales** abiertas en el equipo. En los ejemplos se utilizan los nombres `enp1s0`, `enp2s0` y `wlp3s0`; sustitúyalos por los obtenidos en la sección [4.2](#42-selección-de-la-interfaz-de-red).

### 7.1 Prueba de la primera interfaz Ethernet

En la terminal 1, inicie la captura:

```bash
docker compose run --rm sniffer capture --iface enp1s0 --timeout 60
```

En la terminal 2, genere tráfico a través de la misma interfaz:

```bash
./scripts/generar_trafico.sh enp1s0
```

### 7.2 Prueba de la segunda interfaz Ethernet

```bash
# Terminal 1
docker compose run --rm sniffer capture --iface enp2s0 --timeout 60

# Terminal 2
./scripts/generar_trafico.sh enp2s0
```

### 7.3 Prueba de la interfaz inalámbrica

```bash
# Terminal 1
docker compose run --rm sniffer capture --iface wlp3s0 --timeout 60

# Terminal 2
./scripts/generar_trafico.sh wlp3s0
```

### 7.4 Prueba simultánea

```bash
docker compose run --rm sniffer capture --iface enp1s0,enp2s0,wlp3s0 --timeout 60
```

### 7.5 Comparación de resultados

Cada prueba genera una sesión independiente en la base de datos. Para compararlas, ejecute:

```bash
docker compose run --rm sniffer sessions            # lista de sesiones
docker compose run --rm sniffer stats --session 1   # estadísticas de una sesión
docker compose run --rm sniffer stats --all         # estadísticas acumuladas
```

### 7.6 Consideraciones

- **Generación de tráfico por interfaz.** Linux envía el tráfico por la interfaz asociada a la ruta por defecto (`ip route show default`). Si se captura en una interfaz distinta, solo se observará tráfico de difusión o residual. Por este motivo, el script `generar_trafico.sh` fuerza la interfaz de salida mediante `ping -I` y `curl --interface`.
- **Interfaces sin conexión.** Una interfaz sin cable conectado o sin dirección IPv4 no recibe tráfico. En ese caso, la aplicación emite el aviso `AVISO: la interfaz ... no tiene dirección IPv4`.
- **Interfaces inalámbricas.** En modo normal (*managed*), solo es posible observar el tráfico del propio equipo, no el de otros dispositivos de la red inalámbrica, aunque el modo promiscuo esté activado. Se trata de una limitación del estándar Wi-Fi, no de la aplicación.
- **Interfaces Ethernet conectadas a un switch.** Se observa el tráfico propio del equipo y el de difusión (*broadcast* y *multicast*). Para capturar el tráfico de otros equipos se requiere un puerto de réplica (*port mirroring* o SPAN) en el switch.

---

## 8. Consulta directa de la base de datos

Para acceder a la consola de PostgreSQL, ejecute:

```bash
docker compose exec db psql -U sniffer -d sniffer
```

Las siguientes consultas ilustran el uso de la información almacenada:

```sql
-- Últimos 20 paquetes registrados
SELECT captured_at, interface, src_ip, dst_ip, protocol, length, src_port, dst_port
FROM packets ORDER BY id DESC LIMIT 20;

-- Paquetes por protocolo en la última sesión
SELECT protocol, count(*) AS paquetes, sum(length) AS bytes
FROM packets WHERE session_id = (SELECT max(id) FROM capture_sessions)
GROUP BY protocol ORDER BY paquetes DESC;

-- Cinco direcciones IP de origen con mayor volumen (todas las sesiones)
SELECT host(src_ip) AS ip, count(*) AS paquetes, sum(length) AS bytes
FROM packets GROUP BY src_ip ORDER BY bytes DESC LIMIT 5;

-- Comparación entre interfaces
SELECT interface, count(*) AS paquetes, sum(length) AS bytes
FROM packets GROUP BY interface;

-- Tráfico originado en una subred
SELECT count(*) FROM packets WHERE src_ip << '192.168.1.0/24';
```

La base de datos también es accesible desde el propio equipo con cualquier cliente PostgreSQL, en la dirección `127.0.0.1:5432` y con las credenciales definidas en `.env`. Por seguridad, no es accesible desde otros equipos de la red.

---

## 9. Pruebas automatizadas

La aplicación incluye un conjunto de pruebas automatizadas que no requieren tráfico de red, permisos especiales ni base de datos. Utilizan paquetes generados con Scapy y un archivo `.pcap` sintético que contiene, de forma intencional, tráfico IPv6 y ARP para verificar su descarte.

Para ejecutarlas, utilice el siguiente comando:

```bash
docker compose run --rm --no-deps --entrypoint python sniffer -m pytest -v
```

Las pruebas verifican lo siguiente:

- La extracción correcta de campos en paquetes TCP, UDP, ICMP, de protocolos no identificados y fragmentados.
- El descarte de paquetes IPv6 y ARP.
- La inclusión obligatoria del filtro `ip` en cualquier filtro BPF.
- El cálculo de las clasificaciones por número de paquetes y por volumen.
- El procesamiento completo de un archivo `.pcap`, con el resultado esperado de 60 paquetes IPv4 (30 TCP, 20 UDP y 10 ICMP) y 8 descartados.
- El cumplimiento del límite establecido con `--count`.

---

## 10. Solución de problemas

| Síntoma | Causa probable | Acción correctiva |
|---|---|---|
| `ERROR: la(s) interfaz(es) X no existe(n)` | El nombre indicado en `.env` no corresponde a ninguna interfaz del equipo | Verificar los nombres con `ip -br addr` y corregir la línea 25 de `.env` |
| `AVISO: la interfaz X no tiene dirección IPv4` | Cable desconectado o red inalámbrica no asociada | Conectar la interfaz o seleccionar otra |
| No se captura ningún paquete | El tráfico se envía por otra interfaz (ruta por defecto) | Generar tráfico con `./scripts/generar_trafico.sh <interfaz>` |
| `ERROR: permiso denegado para capturar` | Se eliminó la capacidad `NET_RAW` del archivo `docker-compose.yml` | Restablecer `cap_add: [NET_RAW]` en el servicio `sniffer` |
| `Bind for 127.0.0.1:5432 failed: port is already allocated` | Otro servicio PostgreSQL utiliza el puerto 5432 | Asignar otro puerto en `.env`, p. ej. `DB_PORT=5433` |
| `No fue posible conectar a PostgreSQL` | El servicio de base de datos no está activo | Ejecutar `docker compose up -d db` y verificar con `docker compose ps` |
| Paquetes de tamaño superior a 1500 bytes | La tarjeta de red agrupa segmentos antes de la captura (GRO/TSO) | Comportamiento normal. Para obtener el tamaño real en el medio físico: `sudo ethtool -K <interfaz> gro off` |
| Se registran paquetes hacia el puerto 5432 | La captura incluye `lo` o `docker0`, por donde circula la escritura en la base de datos | Capturar en interfaces físicas o aplicar el filtro `-f "not port 5432"` |

---

## 11. Detención y mantenimiento

| Acción | Comando | Efecto |
|---|---|---|
| Detener los servicios | `docker compose down` | Detiene y elimina los contenedores. Los datos se conservan |
| Eliminar los datos | `docker compose down -v` | Detiene los servicios y **elimina de forma permanente** la base de datos |
| Reconstruir la imagen | `docker compose build` | Aplica modificaciones del código fuente |

> **Precaución:** la opción `-v` elimina el volumen de datos de PostgreSQL. Esta acción no puede deshacerse.

---

## 12. Anexo: estructura del proyecto

```
sniffer/
├── .env                      Configuración (interfaz en la línea 25)
├── docker-compose.yml        Servicios: db (PostgreSQL) y sniffer (captura)
├── Dockerfile                Definición de la imagen de la aplicación
├── requirements.txt          Dependencias de Python
├── requirements-dev.txt      Dependencias para pruebas (pytest)
├── sql/
│   └── schema.sql            Esquema de la base de datos
├── sniffer/                  Código fuente de la aplicación
│   ├── cli.py                Interfaz de línea de comandos
│   ├── capture.py            Control de la captura con Scapy
│   ├── parser.py             Extracción de campos (solo IPv4)
│   ├── stats.py              Cálculo y presentación de estadísticas
│   ├── writer.py             Escritura por lotes en la base de datos
│   ├── db.py                 Acceso a PostgreSQL y consultas
│   └── config.py             Lectura de la configuración
├── scripts/
│   ├── generar_trafico.sh    Generación de tráfico por una interfaz específica
│   └── generar_pcap_ejemplo.py  Generación del archivo de ejemplo
├── samples/
│   └── ejemplo.pcap          Tráfico sintético para pruebas sin red
├── tests/                    Pruebas automatizadas (pytest)
└── docs/
    └── DECISIONES.md         Decisiones técnicas y diseño de la base de datos
```
