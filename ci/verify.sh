#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== Demo ===" && python run_demo.py
echo "=== Tests ===" && python -m pytest tests/ -v
echo "=== All passed ==="
