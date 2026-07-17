#!/bin/bash

source venv/bin/activate

trap "kill 0" EXIT

echo ""
echo "INITIATING IDS PIPELINE..."


echo "[1/4] Compiling C Sniffer..."
gcc -o sniffer sniffer.c -lpcap

echo "[2/4] Starting Python Backend Server..."
python3 backend.py &

sleep 4

open http://127.0.0.1:5000 &

sleep 2

echo "[3/4] Starting C Sensor (Requires password for promiscuous mode)..."
sudo ./sniffer

