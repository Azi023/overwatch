#!/bin/bash
# OVERWATCH AUTOMATED SETUP SCRIPT
# This script sets up your development environment automatically
# Run this from the root of your overwatch repository

set -e  # Exit on any error

echo "🚀 OVERWATCH SETUP SCRIPT"
echo "========================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running from correct directory
if [ ! -f "src/overwatch_core/__init__.py" ]; then
    echo -e "${RED}❌ Error: Please run this script from the root of the overwatch repository${NC}"
    exit 1
fi

echo "✓ Running from correct directory"

# Check prerequisites
echo ""
echo "📋 Checking prerequisites..."

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}❌ Python 3 not found. Please install Python 3.11+${NC}"
    exit 1
fi

# Check Docker
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
    echo -e "${GREEN}✓ Docker $DOCKER_VERSION found${NC}"
    
    # Check if Docker daemon is running
    if docker ps &> /dev/null; then
        echo -e "${GREEN}✓ Docker daemon is running${NC}"
    else
        echo -e "${RED}❌ Docker daemon is not running. Please start Docker Desktop${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ Docker not found. Please install Docker Desktop${NC}"
    exit 1
fi

# Check Git
if command -v git &> /dev/null; then
    GIT_VERSION=$(git --version | cut -d' ' -f3)
    echo -e "${GREEN}✓ Git $GIT_VERSION found${NC}"
else
    echo -e "${RED}❌ Git not found. Please install Git${NC}"
    exit 1
fi

# Create virtual environment
echo ""
echo "🐍 Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}⚠ Virtual environment already exists${NC}"
fi

# Activate virtual environment
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Upgrade pip
echo ""
echo "📦 Upgrading pip..."
pip install --upgrade pip --quiet
echo -e "${GREEN}✓ Pip upgraded${NC}"

# Install Poetry
echo ""
echo "📦 Installing Poetry..."
if command -v poetry &> /dev/null; then
    echo -e "${YELLOW}⚠ Poetry already installed${NC}"
else
    pip install poetry --quiet
    echo -e "${GREEN}✓ Poetry installed${NC}"
fi

# Initialize Poetry if pyproject.toml doesn't exist or is empty
echo ""
echo "📦 Initializing Poetry..."
if [ ! -s "pyproject.toml" ]; then
    echo "Creating pyproject.toml..."
    cat > pyproject.toml << 'EOF'
[tool.poetry]
name = "overwatch"
version = "0.1.0"
description = "AI-powered penetration testing platform"
authors = ["Atheeque <atheeque@example.com>"]
readme = "README.md"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.109.0"
uvicorn = {extras = ["standard"], version = "^0.27.0"}
sqlalchemy = "^2.0.25"
alembic = "^1.13.1"
psycopg2-binary = "^2.9.9"
asyncpg = "^0.29.0"
anthropic = "^0.18.0"
pydantic-settings = "^2.1.0"
python-dotenv = "^1.0.0"
click = "^8.1.7"
aiofiles = "^23.2.1"
httpx = "^0.26.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.4"
pytest-asyncio = "^0.23.3"
pytest-cov = "^4.1.0"
black = "^23.12.1"
isort = "^5.13.2"
mypy = "^1.8.0"
pylint = "^3.0.3"
bandit = "^1.7.6"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
EOF
    echo -e "${GREEN}✓ pyproject.toml created${NC}"
fi

# Install dependencies
echo ""
echo "📦 Installing dependencies (this may take a few minutes)..."
poetry install
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Create .env file
echo ""
echo "🔐 Setting up environment variables..."
if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# Database
DATABASE_URL=postgresql://overwatch:overwatch_pass@localhost:5432/overwatch_db

# Claude API (REPLACE WITH YOUR KEY!)
ANTHROPIC_API_KEY=your_api_key_here

# Security
SECRET_KEY=dev-secret-key-change-in-production
DEBUG=True

# Redis
REDIS_URL=redis://localhost:6379/0

# S3/MinIO
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=overwatch-artifacts

# Logging
LOG_LEVEL=INFO
EOF
    echo -e "${GREEN}✓ .env file created${NC}"
    echo -e "${YELLOW}⚠ IMPORTANT: Edit .env and add your ANTHROPIC_API_KEY${NC}"
else
    echo -e "${YELLOW}⚠ .env file already exists, skipping${NC}"
fi

# Update .gitignore
echo ""
echo "📝 Updating .gitignore..."
cat >> .gitignore << 'EOF'

# Python
venv/
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.egg-info/
dist/
build/
.pytest_cache/
.coverage
htmlcov/

# Environment
.env
.env.local

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Data
data/engagements/
data/reports/

# Alembic
alembic/versions/*.pyc
EOF
echo -e "${GREEN}✓ .gitignore updated${NC}"

# Create docker-compose.yml
echo ""
echo "🐳 Setting up Docker Compose..."
if [ ! -f "docker-compose.yml" ]; then
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: overwatch_postgres
    environment:
      POSTGRES_DB: overwatch_db
      POSTGRES_USER: overwatch
      POSTGRES_PASSWORD: overwatch_pass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U overwatch"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: overwatch_redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    container_name: overwatch_minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
  redis_data:
  minio_data:
EOF
    echo -e "${GREEN}✓ docker-compose.yml created${NC}"
else
    echo -e "${YELLOW}⚠ docker-compose.yml already exists, skipping${NC}"
fi

# Start Docker services
echo ""
echo "🐳 Starting Docker services..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be healthy (30 seconds)..."
sleep 30

# Check service health
echo ""
echo "🏥 Checking service health..."

if docker-compose ps | grep -q "postgres.*healthy"; then
    echo -e "${GREEN}✓ PostgreSQL is healthy${NC}"
else
    echo -e "${RED}❌ PostgreSQL is not healthy${NC}"
fi

if docker-compose ps | grep -q "redis.*healthy"; then
    echo -e "${GREEN}✓ Redis is healthy${NC}"
else
    echo -e "${RED}❌ Redis is not healthy${NC}"
fi

if docker-compose ps | grep -q "minio.*healthy"; then
    echo -e "${GREEN}✓ MinIO is healthy${NC}"
else
    echo -e "${RED}❌ MinIO is not healthy${NC}"
fi

# Test database connection
echo ""
echo "🔌 Testing database connection..."
if docker exec overwatch_postgres psql -U overwatch -d overwatch_db -c "SELECT 1" &> /dev/null; then
    echo -e "${GREEN}✓ Database connection successful${NC}"
else
    echo -e "${RED}❌ Database connection failed${NC}"
fi

# Create pytest.ini
echo ""
echo "🧪 Setting up pytest..."
if [ ! -f "pytest.ini" ]; then
    cat > pytest.ini << 'EOF'
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
addopts = -v --strict-markers
markers =
    asyncio: mark test as async
    slow: mark test as slow
    integration: mark test as integration test
EOF
    echo -e "${GREEN}✓ pytest.ini created${NC}"
fi

# Create directory structure
echo ""
echo "📁 Creating directory structure..."
mkdir -p tests/unit/test_scanners
mkdir -p tests/unit/test_agents
mkdir -p tests/integration
mkdir -p tests/e2e
mkdir -p logs
mkdir -p data/engagements
mkdir -p data/reports

# Create __init__.py files
touch tests/__init__.py
touch tests/unit/__init__.py
touch tests/unit/test_scanners/__init__.py
touch tests/unit/test_agents/__init__.py
touch tests/integration/__init__.py
touch tests/e2e/__init__.py

echo -e "${GREEN}✓ Directory structure created${NC}"

# Summary
echo ""
echo "════════════════════════════════════════"
echo "✅ SETUP COMPLETE!"
echo "════════════════════════════════════════"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Edit .env file and add your ANTHROPIC_API_KEY:"
echo "   ${YELLOW}nano .env${NC}"
echo ""
echo "2. Verify services are running:"
echo "   ${YELLOW}docker-compose ps${NC}"
echo ""
echo "3. Activate virtual environment (if not already active):"
echo "   ${YELLOW}source venv/bin/activate${NC}"
echo ""
echo "4. Follow the implementation guide:"
echo "   ${YELLOW}cat OVERWATCH_IMPLEMENTATION_GUIDE.md${NC}"
echo ""
echo "5. Start with Phase 1 (Database Setup)"
echo ""
echo "🆘 Need help? Check the troubleshooting section in:"
echo "   ${YELLOW}QUICK_START_CHECKLIST.md${NC}"
echo ""
echo "════════════════════════════════════════"
echo ""
echo "🎉 Happy hacking! You're ready to build Overwatch!"
echo ""
