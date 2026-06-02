#!/usr/bin/env bash
# install.sh — Quick dev setup for spring2shell
set -euo pipefail

PYTHON=${PYTHON:-python3}

echo "==> Checking Python version..."
$PYTHON --version

echo "==> Creating virtual environment..."
$PYTHON -m venv .venv
source .venv/bin/activate

echo "==> Installing package in editable mode with dev extras..."
pip install --upgrade pip
pip install -e ".[dev]"

echo ""
echo "==> Done! Activate the environment with:"
echo "    source .venv/bin/activate"
echo ""
echo "==> Then run:"
echo "    spring2shell --help"
echo "    make test"
