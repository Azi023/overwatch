# OVERWATCH QUICK-START CHECKLIST

## ✅ Phase 0: Environment Setup (START HERE!)

**Day 1: Prerequisites**
- [ ] Python 3.11+ installed (`python3 --version`)
- [ ] Docker Desktop installed and running (`docker ps`)
- [ ] Git configured (`git config --list`)
- [ ] VS Code or preferred IDE installed
- [ ] Repository cloned locally (`cd ~/workspace && git clone ...`)

**Day 2: Python Environment**
- [ ] Virtual environment created (`python3 -m venv venv`)
- [ ] Virtual environment activated (`source venv/bin/activate`)
- [ ] Poetry installed (`pip install poetry`)
- [ ] Dependencies initialized (`poetry install`)
- [ ] `.env` file created with secrets
- [ ] `.env` added to `.gitignore`

**Day 2: Docker Infrastructure**
- [ ] `docker-compose.yml` created in root
- [ ] Services started (`docker-compose up -d`)
- [ ] PostgreSQL healthy (`docker-compose ps`)
- [ ] Redis healthy
- [ ] MinIO healthy
- [ ] Can connect to PostgreSQL (`docker exec overwatch_postgres psql -U overwatch -d overwatch_db -c "SELECT 1;"`)

**🎯 Success Criteria**: Running `docker-compose ps` shows 3 healthy services

---

## ✅ Phase 1: Database Foundation

**Day 3: Models & Schema**
- [ ] `src/overwatch_core/persistence/models.py` created with:
  - [ ] `Base` declarative base
  - [ ] `Target` model
  - [ ] `ScanJob` model
  - [ ] `Finding` model
  - [ ] `AIDecision` model
- [ ] `src/overwatch_core/persistence/database.py` created
- [ ] `asyncpg` installed (`poetry add asyncpg`)
- [ ] Can import models without errors

**Day 4: Migrations**
- [ ] Alembic initialized (`poetry run alembic init alembic`)
- [ ] `alembic.ini` configured with correct DATABASE_URL
- [ ] `alembic/env.py` configured for async
- [ ] Initial migration created (`poetry run alembic revision --autogenerate -m "Initial schema"`)
- [ ] Migration applied (`poetry run alembic upgrade head`)
- [ ] Tables exist in database (`docker exec overwatch_postgres psql -U overwatch -d overwatch_db -c "\dt"`)

**🎯 Success Criteria**: Database has tables: targets, scan_jobs, findings, ai_decisions

---

## ✅ Phase 2: Core Scanner Refactoring

**Day 5: Base Scanner**
- [ ] `src/overwatch_core/scanners/base.py` created
- [ ] `AbstractScanner` class defined
- [ ] `ScanResult` dataclass defined
- [ ] `ScannerType` enum defined

**Day 6-7: Nmap Scanner**
- [ ] `src/overwatch_core/scanners/nmap_runner.py` refactored
- [ ] `NmapScanner(AbstractScanner)` implements all methods
- [ ] Uses `asyncio.create_subprocess_exec` (not `subprocess.run`)
- [ ] Command injection protection in `validate_target()`
- [ ] Proper error handling with try/except
- [ ] Structured logging added
- [ ] Tests created in `tests/unit/test_scanners/test_nmap_scanner.py`
- [ ] Tests pass (`poetry run pytest tests/unit/test_scanners/ -v`)

**🎯 Success Criteria**: `poetry run pytest tests/` shows all tests passing

---

## ✅ Phase 3: Claude AI Brain

**Day 8-9: Claude Client**
- [ ] `ANTHROPIC_API_KEY` set in `.env`
- [ ] `anthropic` package installed (`poetry add anthropic`)
- [ ] `src/overwatch_core/agents/claude_client.py` created
- [ ] `ClaudeAgent` class implemented
- [ ] `analyze_scan_results()` method works
- [ ] `generate_exploit_poc()` method works

**Day 10: AI Integration Tests**
- [ ] Test file created: `tests/unit/test_agents/test_claude_client.py`
- [ ] Test: Claude can analyze nmap results
- [ ] Test: Claude suggests reasonable next actions
- [ ] Tests pass (requires API key)

**🎯 Success Criteria**: Claude successfully analyzes sample scan data and suggests next steps

---

## ⚠️ Common Mistakes to Avoid

### Environment Issues
❌ **MISTAKE**: Running commands without activating venv
✅ **FIX**: Always see `(venv)` in your prompt before running commands

❌ **MISTAKE**: Docker not running
✅ **FIX**: Start Docker Desktop, verify with `docker ps`

❌ **MISTAKE**: Committing `.env` to Git
✅ **FIX**: Add `.env` to `.gitignore` immediately

### Database Issues
❌ **MISTAKE**: PostgreSQL connection refused
✅ **FIX**: Wait 30 seconds after `docker-compose up` for services to be healthy

❌ **MISTAKE**: Alembic can't find models
✅ **FIX**: Check `alembic/env.py` imports: `from src.overwatch_core.persistence.models import Base`

❌ **MISTAKE**: "Table already exists" error
✅ **FIX**: Drop and recreate: `poetry run alembic downgrade base && poetry run alembic upgrade head`

### Code Issues
❌ **MISTAKE**: Using sync code in async functions
✅ **FIX**: Use `await` for all I/O operations, use `asyncio.create_subprocess_exec` not `subprocess.run`

❌ **MISTAKE**: No error handling
✅ **FIX**: Wrap all I/O in try/except blocks

❌ **MISTAKE**: Command injection vulnerability
✅ **FIX**: Always validate and sanitize user input, use list-based commands

---

## 📝 Daily Workflow

**Every morning:**
```bash
cd ~/workspace/overwatch
source venv/bin/activate
docker-compose ps  # Verify services are running
git pull  # Get latest changes
poetry install  # Update dependencies
```

**Before coding:**
```bash
git checkout -b feature/your-feature-name
```

**After coding:**
```bash
# Format code
poetry run black src/ tests/
poetry run isort src/ tests/

# Run linters
poetry run pylint src/overwatch_core/
poetry run mypy src/overwatch_core/

# Run tests
poetry run pytest tests/ -v

# Commit if all pass
git add .
git commit -m "feat: your descriptive message"
git push origin feature/your-feature-name
```

**End of day:**
```bash
docker-compose down  # Stop services (optional)
deactivate  # Exit venv (optional)
```

---

## 🆘 Troubleshooting Commands

**Reset everything:**
```bash
# Stop and remove all containers
docker-compose down -v

# Remove Python cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null

# Recreate venv
rm -rf venv/
python3 -m venv venv
source venv/bin/activate
pip install poetry
poetry install

# Restart services
docker-compose up -d
```

**Check service logs:**
```bash
docker-compose logs postgres
docker-compose logs redis
docker-compose logs minio
```

**Access PostgreSQL directly:**
```bash
docker exec -it overwatch_postgres psql -U overwatch -d overwatch_db
```

**Test database connection from Python:**
```bash
poetry run python -c "
from src.overwatch_core.persistence.database import engine
import asyncio
async def test():
    async with engine.begin() as conn:
        result = await conn.execute('SELECT 1')
        print('Connection successful!')
asyncio.run(test())
"
```

---

## 📊 Progress Tracking

**Mark your progress:**
- [ ] Phase 0 Complete (Environment Setup)
- [ ] Phase 1 Complete (Database Foundation)
- [ ] Phase 2 Complete (Core Scanner Refactoring)
- [ ] Phase 3 Complete (Claude AI Brain)
- [ ] Phase 4 Complete (API Layer) - NOT YET STARTED
- [ ] Phase 5 Complete (Orchestrator) - NOT YET STARTED
- [ ] Phase 6 Complete (Testing & Documentation) - NOT YET STARTED
- [ ] Phase 7 Complete (Deployment) - NOT YET STARTED

**Current Status**: _____________________________________

**Blockers**: _____________________________________

**Next Steps**: _____________________________________

---

## 🎓 Learning Resources

**SQLAlchemy Async**:
- https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html

**FastAPI**:
- https://fastapi.tiangolo.com/tutorial/

**Anthropic API**:
- https://docs.anthropic.com/en/api/getting-started

**Async Python**:
- https://realpython.com/async-io-python/

**Docker Compose**:
- https://docs.docker.com/compose/

---

## 💡 Pro Tips

1. **Always test locally first** - Don't push broken code
2. **Commit frequently** - Small commits are easier to review and debug
3. **Write tests as you code** - Don't leave testing for later
4. **Use meaningful commit messages** - "fix bug" is not helpful, "fix: prevent SQL injection in target validation" is
5. **Keep docker-compose running** - It's your development database
6. **Read error messages carefully** - They usually tell you exactly what's wrong
7. **Use logging liberally** - `logger.info()` is your friend for debugging
8. **Don't copy-paste without understanding** - Make sure you know what each line does

**Remember**: You're building something that will compete with XBow ($2M+ in funding). Take your time, do it right, and don't skip the tests!
