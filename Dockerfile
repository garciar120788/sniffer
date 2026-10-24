# =====================================================================
# Imagen del capturador de paquetes IPv4
# =====================================================================
# Se fija la versión de Debian (bookworm) para garantizar construcciones reproducibles.
FROM python:3.12-slim-bookworm

# tcpdump (incluye la biblioteca libpcap como dependencia): Scapy los utiliza
# para compilar los filtros BPF; sin ellos, el parámetro filter= de sniff() no funciona.
# iproute2: proporciona el comando `ip` para el diagnóstico de interfaces.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump iproute2 \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Las dependencias se instalan antes de copiar el código para aprovechar la caché de capas
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY sniffer/ ./sniffer/
COPY sql/ ./sql/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY samples/ ./samples/

# El proceso se ejecuta como root dentro del contenedor, ya que la apertura de
# sockets de captura (AF_PACKET) requiere CAP_NET_RAW. Los privilegios se
# restringen en docker-compose.yml: cap_drop ALL y cap_add NET_RAW (sin --privileged).
ENTRYPOINT ["python", "-m", "sniffer"]
CMD ["capture"]
