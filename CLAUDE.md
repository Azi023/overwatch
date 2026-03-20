# Overwatch — AI-Powered Penetration Testing Platform

## What This Project Is
Overwatch is an open-source, self-hosted AI pentesting platform that learns from every engagement. It uses Claude API as the primary reasoning engine, open-source security tools (ProjectDiscovery ecosystem + others) as the execution backbone, and a multi-agent architecture inspired by XBOW, Neo, and Horizon3.ai.

## Read These Files First
1. `ARCHITECTURE.md` — Full system design with 9 layers, competitor analysis, and priority classification
2. `CODEBASE_ANALYSIS.md` — Current state analysis of existing code
3. `Brother-Eye-Project-Summary.md` — Reasoning engine context (being merged into this project)
4. `OVERWATCH_IMPLEMENTATION_GUIDE.md` — Original implementation guide (partially outdated but useful for context)

## Current State (as of last commit)
- MVP at ~90% with FastAPI, PostgreSQL (async SQLAlchemy), Celery, Redis, Docker
- 11/13 tests passing, 46% coverage
- Observation store + feature extraction + feedback loop implemented
- Nmap scanner integrated with command injection protection
- Alembic migration conflict on feedback table (needs `alembic stamp` or migration fix)
- FakeLLMClient placeholder exists — needs replacement with real Claude API integration
- No agent system yet — this is the major addition
- No attack graph, no memory system, no validation engine, no reporting engine

## Architecture Direction (Key Principles)
1. **Short-lived focused agents** (XBOW model) — spawned with single objective, retired after completion to prevent context drift
2. **Coordinator is deterministic** — not LLM-based. It's a planning/dispatch engine that uses LLM outputs but doesn't hallucinate strategy
3. **LLM reasoning + runtime validation** (Neo model) — Claude analyzes, agents test hypotheses against live targets, only validated findings are reported
4. **Every finding needs reproducible PoC** — "No exploit, no report" (Shannon principle)
5. **Five-layer memory system** — working (per-agent ephemeral), engagement (shared per-test), long-term (cross-engagement vector DB), knowledge base (YAML patterns), credential store (encrypted, scoped)
6. **Attack graph with chaining** — directed graph tracking hosts, services, credentials, pivot paths. Auto-spawn new agents when new attack surface discovered
7. **Cost optimization** — pattern matching before LLM invocation, tiered model usage (Haiku for simple, Sonnet for analysis, Opus for complex chains), prompt caching
8. **Agent training arena** — practice against known vulnerable targets to measure proficiency before real engagements
9. **Safety first** — scope enforcement on every action, human approval gates, emergency kill switch, non-destructive validation, immutable audit trail

## Tech Stack
- **Language:** Python 3.11+
- **API Framework:** FastAPI with async
- **Database:** PostgreSQL 15 + pgvector extension (for vector embeddings)
- **ORM:** SQLAlchemy 2.0 (async) + Alembic migrations
- **Task Queue:** Celery + Redis
- **AI:** Anthropic Claude API (claude-haiku-4-5, claude-sonnet-4-6, claude-opus-4-6)
- **Security Tools:** Nmap (existing), Nuclei, httpx, Katana, Naabu, Subfinder, Interactsh, SQLMap, Playwright
- **Containers:** Docker for infrastructure + agent sandboxing
- **Artifact Storage:** MinIO/S3-compatible
- **Vector Search:** pgvector (PostgreSQL extension) — prefer this over separate Qdrant to minimize infrastructure
- **Observability:** Langfuse (self-hosted) or structured logging with OpenTelemetry
- **Secrets:** python-dotenv for dev, HashiCorp Vault for production

## Code Standards
- **Async throughout** — async def, async SQLAlchemy sessions, asyncio.gather for parallel operations
- **Type hints** on all function signatures
- **Pydantic models** for all data validation and API schemas
- **Security-first** — no shell=True, input validation, parameterized queries, scope checks
- **Tests for every module** — pytest + pytest-asyncio, minimum 70% coverage target
- **Incremental commits** — commit after each working component with descriptive message
- **Error handling** — proper try/except with logging, never silent failures
- **Structured logging** — JSON format with correlation IDs per engagement

## Directory Structure Target
```
overwatch/
├── CLAUDE.md                          # This file
├── ARCHITECTURE.md                    # Full architecture document
├── Brother-Eye-Project-Summary.md     # Brother Eye context
├── pyproject.toml
├── docker-compose.yml
├── alembic/                           # Database migrations
├── config/                            # Configuration files
├── knowledge_base/                    # YAML vulnerability patterns, tool guides
│   ├── vulnerability_patterns/
│   ├── tool_profiles/                 # How each tool should be used
│   └── attack_playbooks/             # Common attack chains
├── src/
│   └── overwatch/
│       ├── __init__.py
│       ├── api/                       # FastAPI routes + WebSocket
│       │   ├── main.py
│       │   ├── routes/
│       │   └── schemas/
│       ├── coordinator/               # Layer 1: Deterministic orchestration
│       │   ├── coordinator.py         # Main coordinator engine
│       │   ├── target_map.py          # Dynamic target/attack surface map
│       │   ├── attack_graph.py        # Directed graph for attack chaining
│       │   ├── strategy_planner.py    # Deterministic strategy planning
│       │   ├── scope_enforcer.py      # Scope validation on every action
│       │   ├── safety_controller.py   # Kill switch, approval gates
│       │   ├── budget_manager.py      # Token/time/cost limits
│       │   └── hvt_engine.py          # High-value target prioritizer
│       ├── memory/                    # Layer 2: Five-layer memory system
│       │   ├── working_memory.py      # Per-agent ephemeral memory
│       │   ├── engagement_memory.py   # Shared per-engagement memory
│       │   ├── long_term_memory.py    # Cross-engagement vector memory
│       │   ├── knowledge_base.py      # YAML pattern loader + queries
│       │   ├── credential_store.py    # Encrypted credential management
│       │   └── advisory_layer.py      # Bayesian priors from past engagements
│       ├── agents/                    # Layer 3: Agent factory + agent types
│       │   ├── factory.py             # Agent spawning and lifecycle
│       │   ├── base_agent.py          # Base agent with reasoning loop
│       │   ├── reasoning_loop.py      # KNOW→THINK→TEST→VALIDATE cycle
│       │   ├── meta_prompting.py      # Agent self-guidance rewriting
│       │   ├── proficiency.py         # Tool proficiency tracking
│       │   └── types/                 # Specialized agent implementations
│       │       ├── recon_agent.py
│       │       ├── webapp_agent.py
│       │       ├── network_agent.py
│       │       ├── api_agent.py
│       │       ├── auth_agent.py
│       │       ├── business_logic_agent.py
│       │       ├── pivot_agent.py
│       │       ├── triage_agent.py
│       │       └── report_agent.py
│       ├── sandbox/                   # Layer 4: Execution isolation
│       │   ├── sandbox_manager.py     # Docker sandbox lifecycle
│       │   ├── network_controls.py    # Network namespace + scope filtering
│       │   └── artifact_capture.py    # Screenshot, HTTP, log capture
│       ├── tools/                     # Layer 4: Tool integrations
│       │   ├── base_tool.py           # Abstract tool interface
│       │   ├── tool_registry.py       # Tool discovery and management
│       │   ├── discovery/
│       │   │   ├── nmap_tool.py       # Existing, needs refactoring
│       │   │   ├── nuclei_tool.py
│       │   │   ├── httpx_tool.py
│       │   │   ├── katana_tool.py
│       │   │   ├── naabu_tool.py
│       │   │   └── subfinder_tool.py
│       │   ├── detection/
│       │   │   ├── sqlmap_tool.py
│       │   │   └── interactsh_tool.py
│       │   ├── exploitation/
│       │   │   ├── http_client.py     # Custom HTTP for business logic testing
│       │   │   ├── browser_tool.py    # Playwright headless browser
│       │   │   └── payload_crafter.py # LLM-generated payloads
│       │   └── parsers/               # Existing parsers, move here
│       │       └── nmap_parser.py
│       ├── validation/                # Layer 5: Exploit verification
│       │   ├── validator.py           # Deterministic PoC verification
│       │   ├── poc_generator.py       # Reproducible exploit scripts
│       │   ├── false_positive.py      # FP elimination pipeline
│       │   └── impact_assessor.py     # What can attacker do with this?
│       ├── reasoning/                 # Claude API integration
│       │   ├── claude_client.py       # Anthropic API wrapper with tiered models
│       │   ├── prompt_templates.py    # System prompts per agent type
│       │   ├── cost_tracker.py        # Token usage and cost monitoring
│       │   └── prompt_cache.py        # Prompt caching for cost reduction
│       ├── observability/             # Layer 6: Tracing + learning
│       │   ├── tracer.py              # OpenTelemetry / Langfuse integration
│       │   ├── observation_store.py   # Existing, keep and extend
│       │   ├── evaluation.py          # Ragas-style quality metrics
│       │   ├── feedback.py            # Human feedback → ground truth
│       │   └── training_export.py     # JSONL export for fine-tuning
│       ├── reporting/                 # Layer 7: Report generation
│       │   ├── report_engine.py       # Main report orchestrator
│       │   ├── templates/             # Jinja2 report templates
│       │   ├── evidence_packager.py   # ZIP evidence packages
│       │   ├── cvss_scorer.py         # CVSS v4.0 calculation
│       │   ├── mitre_mapper.py        # ATT&CK technique mapping
│       │   └── mentorship.py          # Explains WHY (teaching mode)
│       ├── training/                  # Layer 8: Agent training arena
│       │   ├── arena.py               # Training environment manager
│       │   ├── scenarios.py           # Known vulnerable target configs
│       │   └── proficiency_scorer.py  # Measure agent performance
│       ├── persistence/               # Database models + migrations
│       │   ├── models.py              # Existing, extend with new tables
│       │   ├── database.py            # Async session management
│       │   └── repositories/          # Data access layer
│       └── orchestrator/              # Existing Celery integration
│           ├── celery_app.py
│           └── tasks.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── scripts/
│   ├── start_worker.sh
│   ├── start_flower.sh
│   └── setup_tools.sh                # Install ProjectDiscovery tools
├── docker/
│   ├── Dockerfile
│   ├── Dockerfile.sandbox             # Agent sandbox image
│   └── docker-compose.tools.yml       # PD tools container
└── docs/
    ├── QUICKSTART.md
    └── API.md
```

## Important Notes for Claude Code
- Always check existing code before creating new files — reuse and refactor where possible
- The existing `src/overwatch_core/` package should be migrated to `src/overwatch/` (cleaner)
- Preserve all existing tests and ensure they still pass after refactoring
- Use `alembic stamp head` to fix the migration conflict before creating new migrations
- Docker Compose already exists — extend it, don't replace it
- The `.env` file has database credentials and should have ANTHROPIC_API_KEY added
- Commit after each major component with a descriptive message
- If a component is too complex for one pass, create the interface/skeleton first and mark TODOs
