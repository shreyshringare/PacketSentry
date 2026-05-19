FROM python:3.12-slim

WORKDIR /app

# Install system deps for scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy core python package and install it
COPY pyproject.toml ./
COPY packetsentry/ ./packetsentry/
RUN pip install --no-cache-dir -e .

# Copy models from repo root to where os.chdir("../../") from /app will look (the container root /models)
COPY models/ /models/

# Copy backend-specific files and install dependencies
COPY packetsentry-web/backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend application source code
COPY packetsentry-web/backend/ .

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
