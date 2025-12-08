# OVERWATCH IMPLEMENTATION GUIDE
## Complete Step-by-Step Plan with Safeguards

**Goal**: Transform the current basic Overwatch prototype into a production-ready AI-powered penetration testing platform that surpasses XBow.

**Current State**: 
- ✅ Basic nmap scanning works
- ✅ Simple CLI interface exists
- ✅ Project structure is established
- ❌ No database layer
- ❌ No real AI integration
- ❌ No API
- ❌ No tests
- ❌ Many empty placeholder files

---

## 🎯 PHASE 0: ENVIRONMENT SETUP (Days 1-2)
**Goal**: Get your development environment working properly before touching any code

### Step 0.1: Prerequisites Check

**On your local machine, verify you have:**

```bash
# Check Python version (need 3.11+)
python3 --version

# Check Docker is installed and running
docker --version
docker ps

# Check Git is configured
git config --global user.name
git config --global user.email

# Check you have a code editor (VS Code recommended)
code --version
```

**If anything is missing:**

1. **Python 3.11+**: 
   - Ubuntu/Debian: `sudo apt update && sudo apt install python3.11 python3.11-venv python3-pip`
   - Windows: Download from python.org
   - macOS: `brew install python@3.11`

2. **Docker Desktop**:
   - Download from docker.com
   - Make sure Docker daemon is running: `docker ps` should work

3. **VS Code** (recommended):
   - Download from code.visualstudio.com
   - Install extensions: Python, Docker, GitLens

### Step 0.2: Clone Repository Locally

```bash
# Navigate to your workspace
cd ~/workspace  # or wherever you keep projects

# Clone your repository
git clone https://github.com/Azi023/overwatch.git
cd overwatch

# Verify you can see your files
ls -la
```

### Step 0.3: Set Up Python Virtual Environment

**🚨 CRITICAL: Always use a virtual environment to avoid dependency conflicts**

```bash
# Create virtual environment (do this inside the overwatch directory)
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate  # Windows

# Your prompt should now show (venv) at the beginning

# Upgrade pip
pip install --upgrade pip

# Install Poetry (better dependency management than pip)
pip install poetry

# Verify Poetry is installed
poetry --version
```

### Step 0.4: Initialize Poetry Configuration

```bash
# Initialize poetry (this will create/update pyproject.toml)
poetry init --no-interaction --name overwatch --python "^3.11"

# Add core dependencies
poetry add fastapi uvicorn sqlalchemy alembic psycopg2-binary anthropic pydantic-settings python-dotenv click

# Add development dependencies
poetry add --group dev pytest pytest-asyncio pytest-cov black isort mypy pylint bandit

# Install all dependencies
poetry install

# Verify installation
poetry run python --version
```

### Step 0.5: Create Essential Configuration Files

**Create `.env` file** (this stores secrets - NEVER commit to Git):

```bash
cat > .env << 'EOF'
# Database
DATABASE_URL=postgresql://overwatch:overwatch_pass@localhost:5432/overwatch_db

# Claude API
ANTHROPIC_API_KEY=your_api_key_here

# Security
SECRET_KEY=your-secret-key-here-change-in-production
DEBUG=True

# Redis (for task queue)
REDIS_URL=redis://localhost:6379/0

# S3/MinIO (for artifact storage)
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=overwatch-artifacts
EOF

# Add .env to .gitignore if not already there
echo ".env" >> .gitignore
echo "venv/" >> .gitignore
echo "__pycache__/" >> .gitignore
echo "*.pyc" >> .gitignore
echo ".pytest_cache/" >> .gitignore
echo ".coverage" >> .gitignore
```

### Step 0.6: Set Up Docker Compose for Development

**Create `docker-compose.yml`** in the root directory:

```bash
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
```

### Step 0.7: Start Development Infrastructure

```bash
# Start all services in the background
docker-compose up -d

# Wait for services to be healthy (takes ~30 seconds)
sleep 30

# Verify all services are running
docker-compose ps

# You should see:
# - overwatch_postgres (healthy)
# - overwatch_redis (healthy)
# - overwatch_minio (healthy)

# Test PostgreSQL connection
docker exec overwatch_postgres psql -U overwatch -d overwatch_db -c "SELECT 1;"

# If you see "1" output, PostgreSQL is working!
```

**🎉 Checkpoint: Your development environment is ready!**

---

## 🏗️ PHASE 1: FOUNDATION - DATABASE & MODELS (Days 3-4)

### Step 1.1: Create Database Models

**Create `src/overwatch_core/persistence/models.py`**:

This file will define your database schema. Let me create it properly:

```python
"""
Database models for Overwatch.
Uses SQLAlchemy ORM for PostgreSQL.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Boolean, JSON, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class ScanStatus(str, Enum):
    """Scan job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Target(Base):
    """Target systems to be tested."""
    __tablename__ = "targets"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    
    # Scope definition
    scope_rules: Mapped[dict] = mapped_column(JSON, default=dict)
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)
    allowed_ports: Mapped[list] = mapped_column(JSON, default=list)
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan_jobs: Mapped[list["ScanJob"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class ScanJob(Base):
    """Individual scan jobs."""
    __tablename__ = "scan_jobs"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    
    # Job details
    scan_type: Mapped[str] = mapped_column(String(100))  # nmap, nuclei, sqli, etc.
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    
    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Results
    raw_output_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    
    # Relationships
    target: Mapped["Target"] = relationship(back_populates="scan_jobs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")
    ai_decisions: Mapped[list["AIDecision"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")


class Finding(Base):
    """Security vulnerabilities discovered."""
    __tablename__ = "findings"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    
    # Vulnerability details
    vulnerability_type: Mapped[str] = mapped_column(String(255))  # SQL Injection, XSS, etc.
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    
    # Location
    url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Severity & Confidence
    severity: Mapped[SeverityLevel] = mapped_column(SQLEnum(SeverityLevel))
    confidence: Mapped[float] = mapped_column(default=0.0)  # 0.0 to 1.0
    
    # Validation
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Evidence
    proof_of_concept: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    screenshot_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    
    # Remediation
    remediation_advice: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)
    
    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(back_populates="findings")


class AIDecision(Base):
    """Log of all AI agent decisions."""
    __tablename__ = "ai_decisions"
    
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"))
    
    # Decision details
    decision_type: Mapped[str] = mapped_column(String(100))  # scan, exploit, validate, etc.
    action: Mapped[str] = mapped_column(String(255))
    reasoning: Mapped[str] = mapped_column(Text)
    
    # Parameters & Results
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    outcome: Mapped[dict] = mapped_column(JSON, default=dict)
    success: Mapped[bool] = mapped_column(Boolean)
    
    # Confidence & Risk
    confidence: Mapped[float] = mapped_column(default=0.0)
    risk_level: Mapped[str] = mapped_column(String(50), nullable=True)
    
    # Approval tracking
    required_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Metadata
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    agent_model: Mapped[str] = mapped_column(String(100), default="claude-sonnet-4")
    
    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(back_populates="ai_decisions")
```

### Step 1.2: Set Up Database Connection

**Create `src/overwatch_core/persistence/database.py`**:

```python
"""
Database connection and session management.
"""
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from .models import Base


# Get database URL from environment
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://overwatch:overwatch_pass@localhost:5432/overwatch_db")

# Convert to async URL if needed
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=True,  # Log SQL queries (disable in production)
    poolclass=NullPool,  # Simple pool for development
)

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_db():
    """Drop all database tables (use with caution!)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session.
    
    Usage:
        async with get_session() as session:
            result = await session.execute(query)
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
```

### Step 1.3: Install Required Database Dependencies

```bash
# Install async PostgreSQL driver
poetry add asyncpg

# Install Alembic for migrations
poetry add alembic

# Install dependencies
poetry install
```

### Step 1.4: Initialize Alembic for Migrations

```bash
# Initialize Alembic
poetry run alembic init alembic

# This creates:
# - alembic/ directory
# - alembic.ini configuration file
```

**Edit `alembic.ini`** - Update the database URL:

```bash
# Find this line:
# sqlalchemy.url = driver://user:pass@localhost/dbname

# Replace with:
# sqlalchemy.url = postgresql+asyncpg://overwatch:overwatch_pass@localhost:5432/overwatch_db
```

**Edit `alembic/env.py`** - Configure async migrations:

```python
# Add this at the top after imports
from src.overwatch_core.persistence.models import Base
target_metadata = Base.metadata

# Replace run_migrations_offline() and run_migrations_online() with async versions
# (Full code provided in next step)
```

### Step 1.5: Create Initial Migration

```bash
# Generate initial migration
poetry run alembic revision --autogenerate -m "Initial schema"

# Review the generated migration in alembic/versions/

# Apply migration
poetry run alembic upgrade head

# Verify tables were created
docker exec overwatch_postgres psql -U overwatch -d overwatch_db -c "\dt"

# You should see tables: targets, scan_jobs, findings, ai_decisions
```

**🎉 Checkpoint: Database layer is complete and working!**

---

## 🔧 PHASE 2: REFACTOR CORE SCANNERS (Days 5-7)

### Step 2.1: Create Base Scanner Interface

**Create `src/overwatch_core/scanners/base.py`**:

```python
"""
Base scanner interface that all scanners must implement.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class ScannerType(str, Enum):
    """Types of scanners."""
    NETWORK = "network"
    WEB = "web"
    API = "api"
    ACTIVE_DIRECTORY = "active_directory"
    CLOUD = "cloud"
    IOT = "iot"


@dataclass
class ScanResult:
    """Standardized scan result format."""
    scanner_type: ScannerType
    scanner_name: str
    target: str
    findings: List[Dict[str, Any]]
    raw_output: str
    success: bool
    error: str = ""
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class AbstractScanner(ABC):
    """
    Base class for all scanners.
    
    All scanners must:
    1. Implement async scan() method
    2. Return standardized ScanResult
    3. Handle errors gracefully
    4. Log all actions
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.scanner_type = ScannerType.NETWORK  # Override in subclass
        self.scanner_name = self.__class__.__name__
    
    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute the scan.
        
        Args:
            target: Target to scan (IP, URL, etc.)
            options: Scanner-specific options
            
        Returns:
            ScanResult with findings
        """
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate target is in correct format.
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid, False otherwise
        """
        pass
    
    def get_capabilities(self) -> List[str]:
        """
        Return list of what this scanner can detect.
        
        Returns:
            List of capability strings
        """
        return []
```

### Step 2.2: Refactor Nmap Scanner

**Replace `src/overwatch_core/scanners/nmap_runner.py`** with proper async implementation:

```python
"""
Nmap scanner implementation.
Properly handles async execution, error handling, and logging.
"""
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
from .base import AbstractScanner, ScanResult, ScannerType

logger = logging.getLogger(__name__)


class NmapScanner(AbstractScanner):
    """
    Nmap network scanner implementation.
    
    Capabilities:
    - Port scanning
    - Service detection
    - Version detection
    - OS fingerprinting (with -O flag)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.scanner_type = ScannerType.NETWORK
        self.scanner_name = "nmap"
        
        # Scan profiles
        self.profiles = {
            "safe": "-sV -T2",
            "balanced": "-sV -sC -T3",
            "aggressive": "-A -T4",
            "quick": "-sV -T4 -F",  # Fast scan, common ports only
        }
    
    def validate_target(self, target: str) -> bool:
        """
        Validate target is valid IP or hostname.
        
        Args:
            target: IP address or hostname
            
        Returns:
            True if valid
        """
        # Basic validation (can be enhanced)
        if not target or len(target) == 0:
            return False
        
        # Check for command injection attempts
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">"]
        if any(char in target for char in dangerous_chars):
            logger.warning(f"Potential command injection in target: {target}")
            return False
        
        return True
    
    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Execute nmap scan.
        
        Args:
            target: Target IP or hostname
            options: {
                "profile": "safe" | "balanced" | "aggressive" | "quick",
                "ports": "80,443" or "1-1000" (optional),
                "output_dir": Path to save results (optional)
            }
            
        Returns:
            ScanResult with ports and services found
        """
        options = options or {}
        profile = options.get("profile", "balanced")
        ports = options.get("ports")
        output_dir = options.get("output_dir", "/tmp/overwatch/scans")
        
        # Validate target
        if not self.validate_target(target):
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Invalid target format"
            )
        
        # Build nmap command
        flags = self.profiles.get(profile, self.profiles["balanced"])
        
        # Add port specification if provided
        if ports:
            flags += f" -p {ports}"
        
        # Create output directory
        output_path = Path(output_dir) / target.replace("/", "_")
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_file = output_path / f"{timestamp}_nmap.xml"
        
        # Build command (using list to prevent shell injection)
        cmd = [
            "nmap",
            *flags.split(),
            "-oX", str(xml_file),
            target
        ]
        
        logger.info(f"Running nmap scan: {' '.join(cmd)}")
        
        try:
            # Execute nmap asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600  # 10 minutes max
            )
            
            # Check return code
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                logger.error(f"Nmap scan failed: {error_msg}")
                return ScanResult(
                    scanner_type=self.scanner_type,
                    scanner_name=self.scanner_name,
                    target=target,
                    findings=[],
                    raw_output=error_msg,
                    success=False,
                    error=f"Nmap exited with code {process.returncode}"
                )
            
            # Parse results
            from .nmap_parser import parse_nmap_xml
            scan_data = parse_nmap_xml(str(xml_file))
            
            logger.info(f"Nmap scan completed. Found {len(scan_data.get('ports', []))} ports")
            
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=scan_data.get("ports", []),
                raw_output=stdout.decode('utf-8', errors='ignore'),
                success=True,
                metadata={
                    "xml_path": str(xml_file),
                    "profile": profile,
                    "scan_duration_seconds": (datetime.now() - datetime.fromtimestamp(xml_file.stat().st_mtime)).seconds
                }
            )
            
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timed out after 600 seconds")
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error="Scan timed out after 10 minutes"
            )
        except Exception as e:
            logger.exception(f"Nmap scan failed with exception: {e}")
            return ScanResult(
                scanner_type=self.scanner_type,
                scanner_name=self.scanner_name,
                target=target,
                findings=[],
                raw_output="",
                success=False,
                error=str(e)
            )
    
    def get_capabilities(self) -> List[str]:
        """Return scanner capabilities."""
        return [
            "port_scanning",
            "service_detection",
            "version_detection",
            "os_fingerprinting",
            "script_scanning"
        ]
```

### Step 2.3: Create Tests for Scanner

**Create `tests/unit/test_scanners/test_nmap_scanner.py`**:

```python
"""
Tests for Nmap scanner.
"""
import pytest
from src.overwatch_core.scanners.nmap_runner import NmapScanner


@pytest.mark.asyncio
async def test_nmap_scanner_validates_target():
    """Test target validation."""
    scanner = NmapScanner()
    
    # Valid targets
    assert scanner.validate_target("192.168.1.1")
    assert scanner.validate_target("example.com")
    assert scanner.validate_target("10.0.0.0/24")
    
    # Invalid targets (command injection attempts)
    assert not scanner.validate_target("192.168.1.1; rm -rf /")
    assert not scanner.validate_target("example.com && cat /etc/passwd")
    assert not scanner.validate_target("")


@pytest.mark.asyncio
async def test_nmap_scanner_basic_scan():
    """Test basic nmap scan."""
    scanner = NmapScanner()
    
    # Scan localhost (should always work)
    result = await scanner.scan("127.0.0.1", {"profile": "quick"})
    
    assert result.success
    assert result.scanner_name == "nmap"
    assert len(result.findings) >= 0  # May or may not have open ports


@pytest.mark.asyncio
async def test_nmap_scanner_handles_invalid_target():
    """Test scanner handles invalid target gracefully."""
    scanner = NmapScanner()
    
    result = await scanner.scan("999.999.999.999")
    
    # Should fail gracefully, not crash
    assert not result.success
    assert "error" in result.error.lower() or "invalid" in result.error.lower()
```

### Step 2.4: Run Tests

```bash
# Create tests directory structure
mkdir -p tests/unit/test_scanners
touch tests/__init__.py
touch tests/unit/__init__.py
touch tests/unit/test_scanners/__init__.py

# Create pytest configuration
cat > pytest.ini << 'EOF'
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
EOF

# Run tests
poetry run pytest tests/unit/test_scanners/test_nmap_scanner.py -v

# Run tests with coverage
poetry run pytest tests/ --cov=src/overwatch_core --cov-report=html

# View coverage report
# open htmlcov/index.html
```

**🎉 Checkpoint: Core scanner refactored with tests!**

---

## 🤖 PHASE 3: CLAUDE AI BRAIN INTEGRATION (Days 8-10)

### Step 3.1: Create Claude Client

**Create `src/overwatch_core/agents/claude_client.py`**:

```python
"""
Claude AI client for autonomous pentesting decisions.
"""
import os
import json
import logging
from typing import Dict, Any, List
from anthropic import AsyncAnthropic

logger = logging.getLogger(__name__)


class ClaudeAgent:
    """
    Claude-powered pentesting agent.
    
    Responsibilities:
    - Analyze scan results
    - Decide next actions
    - Generate exploit POCs
    - Provide remediation advice
    """
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in environment")
        
        self.client = AsyncAnthropic(api_key=self.api_key)
        self.model = "claude-sonnet-4-20250514"
        self.max_tokens = 4000
    
    async def analyze_scan_results(
        self,
        target_info: Dict[str, Any],
        scan_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze scan results and suggest next actions.
        
        Args:
            target_info: Information about the target
            scan_results: List of scan findings
            
        Returns:
            {
                "analysis": "Summary of findings",
                "next_actions": [
                    {"action": "tool_name", "params": {...}, "reasoning": "..."},
                    ...
                ],
                "risk_assessment": "Overall risk level"
            }
        """
        prompt = f"""You are Overwatch, an autonomous penetration testing AI.

TARGET INFORMATION:
{json.dumps(target_info, indent=2)}

SCAN RESULTS:
{json.dumps(scan_results, indent=2)}

Your task: Analyze these scan results and recommend the next 3 most important actions.

Respond in this JSON format:
{{
  "analysis": "Brief summary of what you found (2-3 sentences)",
  "next_actions": [
    {{
      "priority": 1,
      "action": "tool_name",
      "params": {{"param": "value"}},
      "reasoning": "Why this is important"
    }}
  ],
  "risk_assessment": "Low|Medium|High|Critical"
}}
"""
        
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Extract JSON from response
            content = response.content[0].text
            
            # Parse JSON (handle markdown code blocks)
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            result = json.loads(content)
            return result
            
        except Exception as e:
            logger.exception(f"Failed to analyze scan results: {e}")
            return {
                "analysis": "Error analyzing results",
                "next_actions": [],
                "risk_assessment": "Unknown",
                "error": str(e)
            }
    
    async def generate_exploit_poc(
        self,
        vulnerability: Dict[str, Any]
    ) -> str:
        """
        Generate proof-of-concept exploit code.
        
        Args:
            vulnerability: Vulnerability details
            
        Returns:
            POC code/command
        """
        prompt = f"""Generate a proof-of-concept exploit for this vulnerability:

VULNERABILITY:
{json.dumps(vulnerability, indent=2)}

Provide:
1. A curl command or Python script to exploit this
2. Explanation of what it does
3. Expected output if successful

Keep it ethical - this is for authorized testing only.
"""
        
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return response.content[0].text
            
        except Exception as e:
            logger.exception(f"Failed to generate POC: {e}")
            return f"Error generating POC: {str(e)}"
```

### Step 3.2: Test Claude Integration

**Create `tests/unit/test_agents/test_claude_client.py`**:

```python
"""
Tests for Claude AI client.
"""
import pytest
import os
from src.overwatch_core.agents.claude_client import ClaudeAgent


@pytest.mark.asyncio
@pytest.mark.skipif(not os.getenv("ANTHROPIC_API_KEY"), reason="No API key")
async def test_claude_analyzes_nmap_results():
    """Test Claude can analyze nmap results."""
    agent = ClaudeAgent()
    
    target_info = {
        "url": "http://192.168.1.50/dvwa",
        "name": "DVWA Test Target"
    }
    
    scan_results = [
        {"port": 80, "service": "http", "version": "Apache 2.4.41"},
        {"port": 3306, "service": "mysql", "version": "MySQL 5.7.33"},
        {"port": 22, "service": "ssh", "version": "OpenSSH 7.9"}
    ]
    
    result = await agent.analyze_scan_results(target_info, scan_results)
    
    # Verify response structure
    assert "analysis" in result
    assert "next_actions" in result
    assert "risk_assessment" in result
    assert len(result["next_actions"]) > 0
    
    # Verify next actions have required fields
    action = result["next_actions"][0]
    assert "action" in action
    assert "reasoning" in action
```

**🎉 Checkpoint: Claude AI brain is integrated!**

---

## CONTINUED IN NEXT RESPONSE...

This is getting long. Should I continue with:
- Phase 4: API Layer (FastAPI)
- Phase 5: Orchestrator & Job Queue
- Phase 6: Testing & Documentation
- Phase 7: Deployment Guide

Let me know if you want me to continue, or if you have questions about Phases 0-3 first!
