# Overwatch Quick Start

## Prerequisites

- Docker Desktop
- Python 3.11+
- PostgreSQL, Redis (via Docker)

## Installation
```bash
git clone https://github.com/Azi023/overwatch.git
cd overwatch
./setup.sh
```

## Running Overwatch

### Terminal 1: Start Services
```bash
docker-compose up -d
```

### Terminal 2: Start API
```bash
source venv/bin/activate
poetry run uvicorn src.overwatch_core.api.main:app --reload --port 8000
```

### Terminal 3: Start Worker
```bash
source venv/bin/activate
./scripts/start_worker.sh
```

### Terminal 4: Start Flower (Optional)
```bash
source venv/bin/activate
./scripts/start_flower.sh
```

## Using the API

Visit: http://localhost:8000/docs

### Create a Target
```bash
curl -X POST http://localhost:8000/api/v1/targets/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Target",
    "ip_address": "192.168.1.50",
    "allowed_hosts": ["192.168.1.50"],
    "allowed_ports": [80, 443]
  }'
```

### Run a Scan
```bash
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_type": "nmap",
    "config": {"profile": "balanced"}
  }'
```

### Check Scan Status
```bash
curl http://localhost:8000/api/v1/scans/1
```

## Monitoring

- **API Docs**: http://localhost:8000/docs
- **Flower Dashboard**: http://localhost:5555
- **Database**: `docker exec -it overwatch_postgres psql -U overwatch -d overwatch_db`

## Troubleshooting

See `docs/TROUBLESHOOTING.md`
