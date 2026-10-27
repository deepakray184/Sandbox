#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=========================================================="
echo "  VANGUARD MSA // SOC MALWARE SANDBOX & EMAIL ANALYZER"
echo "=========================================================="

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    ./venv/bin/pip install fastapi uvicorn python-multipart jinja2 aiofiles pefile requests
fi

echo "[*] Initializing Vanguard SOC Engine..."
PORT=${PORT:-8000}
HOST=${HOST:-0.0.0.0}

echo "[+] Starting Web Console at: http://localhost:${PORT}"
echo "[+] SOC API Documentation: http://localhost:${PORT}/docs"
echo "=========================================================="

exec ./venv/bin/uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
