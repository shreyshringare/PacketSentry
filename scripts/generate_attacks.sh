#!/bin/bash
# PacketSentry Posture Validation Simulator
# Triggers both Deterministic Rules (Gate 1) and ML Anomalies (Gate 2)

echo "🛡️ Starting PacketSentry Hybrid Posture Validation..."

echo "========================================="
echo "GATE 1: DETERMINISTIC FILTER TESTS"
echo "========================================="

echo "[+] Simulating Banned Payload (SQL Injection)..."
# Using hping3 or curl if an endpoint exists, but let's just send raw netcat payloads
echo "select * from users" | nc -q 1 127.0.0.1 8000 &
sleep 1

echo "[+] Simulating Banned Payload (Path Traversal)..."
echo "GET ../../../etc/passwd HTTP/1.1" | nc -q 1 127.0.0.1 8000 &
sleep 1

echo "[+] Simulating Rate Limiting (SYN Flood)..."
if command -v hping3 &> /dev/null; then
    sudo hping3 -S -p 8000 --flood -c 1000 127.0.0.1 &
    PID=$!
    sleep 2
    sudo kill $PID
else
    echo "⚠️ hping3 not found. Skipping SYN Flood."
fi

echo ""
echo "========================================="
echo "GATE 2: PROBABILISTIC ENSEMBLE TESTS"
echo "========================================="

echo "[+] Simulating Statistical Anomaly (Large random payload)..."
dd if=/dev/urandom bs=1024 count=1000 | nc -q 1 127.0.0.1 8000 &
sleep 2

echo "[+] Simulating Port Scan (Horizontal)..."
if command -v nmap &> /dev/null; then
    nmap -sS -p 1-1000 -T4 127.0.0.1 > /dev/null &
else
    echo "⚠️ nmap not found. Skipping Port Scan."
fi

echo ""
echo "✅ Validation complete! Check the PacketSentry UI for alerts."
