FROM python:3.12-slim

WORKDIR /app

# Install system deps for scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install packetsentry from repo root
COPY ../../pyproject.toml ../../packetsentry/ ./packetsentry/
RUN pip install --no-cache-dir -e . 2>/dev/null || true

# Install backend deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
