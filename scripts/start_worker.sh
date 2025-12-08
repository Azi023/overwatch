#!/bin/bash
set -e

echo "Starting Overwatch Celery Worker..."

# 1) Figure out where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."

# 2) Go to project root
cd "$PROJECT_ROOT"

# 3) Activate venv
source venv/bin/activate

# 4) Make sure Python can import 'src'
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# 5) Start Celery worker
celery -A src.overwatch_core.orchestrator.celery_app worker --loglevel=info
