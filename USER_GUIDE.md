# Overwatch User Guide

## Installation

### Prerequisites

- Docker Desktop
- Python 3.11+
- PostgreSQL
- Redis

### Setup

```bash
# Clone repository
git clone https://github.com/Azi023/overwatch.git
cd overwatch

# Run setup
./setup.sh

# Start services
docker-compose up -d

# Start API
poetry run uvicorn src.overwatch_core.api.main:app --reload

# Start worker
./scripts/start_worker.sh
