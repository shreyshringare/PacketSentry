# PacketSentry CLI — Network Intrusion Detection System
# Usage: docker build -t packetsentry . && docker run --rm -it packetsentry --help
#
# Live capture requires host networking + NET_ADMIN capability:
#   docker run --rm -it --network host --cap-add NET_ADMIN packetsentry live
#
# PCAP replay (no privileges needed):
#   docker run --rm -it -v /path/to/pcaps:/pcaps packetsentry replay /pcaps/attack.pcap

FROM python:3.12-slim

WORKDIR /app

# libpcap-dev required for Scapy raw socket capture
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY packetsentry/ ./packetsentry/
COPY signatures/ ./signatures/

# Install PacketSentry and all ML deps
RUN pip install --no-cache-dir -e .

# Create data and models dirs (volumes mount here at runtime)
RUN mkdir -p /app/data /app/models

ENTRYPOINT ["packetsentry"]
CMD ["--help"]
