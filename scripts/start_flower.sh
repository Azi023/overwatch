#!/bin/bash
set -e

echo "Starting Flower..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."

cd "$PROJECT_ROOT"
source venv/bin/activate
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

celery -A src.overwatch_core.orchestrator.celery_app flower --port=5555
