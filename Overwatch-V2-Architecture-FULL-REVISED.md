# Overwatch V2 — Complete Architecture Blueprint (Revised)

> **Created:** March 19, 2026 — V2 (Expanded with pentester critique)  
> **Purpose:** Comprehensive competitor analysis + full-complexity architecture  
> **Approach:** Analyzed from offensive security researcher, red teamer, and attacker perspective  
> **Competitors Analyzed:** XBOW, Pentera, ProjectDiscovery Neo, Horizon3.ai NodeZero, Terra Security, Shannon (Keygraph), PentestGPT, CAI, Strix, BugTrace-AI, Cyber-AutoAgent, PentAGI, HexStrike, Zen-AI-Pentest, LuaN1ao

---

## Part 1: Expanded Competitor Analysis

### 1.1 XBOW — $1B Unicorn (Web-focused)

- **Raised:** $120M Series C (March 18, 2026). Total: ~$120M+. Valuation: $1B+
- **Focus:** Web application pentesting only. API + mobile coming 2026.
- **Architecture:** Coordinator + thousands of short-lived parallel agents + deterministic validators
- **Key principle:** "Creative AI discovers. Deterministic logic decides what's real."
- **Agents are retired after each mission** to prevent context drift/accumulated bias
- **Shared Attack Machine** with headless browser + offensive tooling
- **#1 on HackerOne leaderboard** — outperformed human hackers
- **XBOW benchmark:** 104 challenges, used by community to measure agent quality

**Architectural lessons for us:**
- Short-lived agents > long-running agents
- Separate exploration from verification (two distinct systems)
- Every finding needs a reproducible PoC exploit
- Parallel agents at scale beats sequential depth

**Gaps we can exploit:**
- Web-only (no network, AD, cloud, IoT)
- Cloud-only, no self-hosted
- Black box — no reasoning transparency
- No mentorship/teaching angle
- Expensive ($2K+ per test)

---

### 1.2 Pentera — Enterprise Incumbent ($190M raised)

- **Focus:** Internal network + infrastructure security validation
- **Architecture:** Rule-based attack emulation + distributed attack nodes
- **Agentless** — operates from attack nodes, no endpoint agents
- **1,200+ enterprise customers**, including Fortune 500
- **Products:** Core (internal), Surface (external), Cloud (AWS/Azure/GCP), Credentials Exposure
- **MITRE ATT&CK mapping** with kill-chain visualization
- **AI additions (Sept 2025):** AI-driven attack path identification + AI reporting
- **Pentera Labs** research division discovers zero-days (Fortinet, VMware, Azure)
- **NSA/CAPT program** — NodeZero (Horizon3) comparison shows Pentera competes for government contracts
- **Safety by Design** — controlled payloads, automatic cleanup, non-destructive

**Architectural lessons for us:**
- Multi-domain coverage is a differentiator (network + cloud + AD in one platform)
- Distributed attack orchestration across multiple sites
- AI remediation workflows (auto-ticketing, SLA tracking, revalidation)
- Rule-based core is proven reliable even if not "smart"
- Enterprise needs compliance alignment (CTEM, FedRAMP)

**Gaps we can exploit:**
- NOT AI-native — core is rule-based, AI is being bolted on
- No business logic testing capability
- No source code analysis
- Closed architecture, no extensibility
- Expensive enterprise-only pricing

---

### 1.3 ProjectDiscovery Neo — Open-Source-Powered AI

- **Focus:** Full security lifecycle — code review, pentesting, threat modeling, remediation
- **Architecture:** Claude Opus 4.5 + specialized agents + memory layer + sandboxed execution
- **Uses their own open-source tools:** Nuclei (9K+ templates), httpx, Subfinder, Naabu, Katana, dnsx, Interactsh, cvemap, Uncover, Cloudlist
- **Benchmark results:** 66/74 valid findings (89% recall), 93% precision, 100% of Critical+High
- **Memory layer** that persists across engagements — learns your architecture, naming conventions, business context
- **Two types of workflows:** Interactive (human-directed) + Background (auto-triggered by events/deployments)
- **Agent assembly at runtime** — tuned to tech stack and business context
- **First credited CVE discovery (SSRF in Faraday)** — proved it can find real zero-days

**Architectural lessons for us (most important competitor to study):**
- LLM reasoning + runtime validation = 93% precision (vs 63% for code-only review)
- Memory that persists across engagements is a competitive moat
- Open-source tool ecosystem as the execution backbone
- Agent self-update during execution
- Business logic detection through understanding app behavior, not just patterns
- Multi-step, multi-role attack chain testing is the killer capability

**Gaps we can exploit:**
- Enterprise-only pricing (not accessible to freelancers like you)
- Cloud-hosted only
- Struggled with large targets (200+ servers) per independent testing
- Occasionally gets stuck during execution
- No offline/air-gapped mode
- Limited to ProjectDiscovery's ecosystem
- No Active Directory deep testing
- No network infrastructure testing depth

---

### 1.4 Horizon3.ai NodeZero — The Infrastructure King

- **Focus:** Internal network, AD, cloud, and hybrid pentesting. Web app testing in Early Access.
- **Architecture:** Agentless Docker host + ephemeral one-time-use cloud resources + graph-driven orchestration
- **Solved GOAD (Game of Active Directory) in 14 minutes** — first AI to do so
- **NSA CAPT program:** Expanded from 200 to 1,000 defense contractors. 50,000+ vulns found, 70% remediated. Domain compromise in 77 seconds.
- **High-Value Targeting (HVT):** Two-phase architecture — fast pattern matching first, then LLM analysis via AWS Bedrock. Identifies domain controllers, privileged accounts, critical infrastructure.
- **Prompt caching** reduces costs by up to 90% and latency by 85%
- **NodeZero Tripwires:** Auto-drops decoy honeytokens at discovered critical exposures for threat detection
- **1-click verify:** Targeted retest to confirm remediation worked
- **Attack chaining without CVEs** — uses credential abuse, misconfigurations, trust relationships
- **Hybrid cloud pentesting:** Pivots from on-prem through Azure/AWS organically

**Architectural lessons for us (critical for network/AD/cloud testing):**
- Graph-driven orchestration for attack path chaining
- Ephemeral one-time-use infrastructure per test
- Two-phase cost optimization (fast pattern matching BEFORE invoking LLM)
- Attack chaining that doesn't require CVEs (credential abuse, misconfiguration chains)
- Tripwires/honeytokens as a defensive byproduct of offensive testing
- 1-click revalidation of fixes
- FedRAMP High authorization for government work

**Gaps we can exploit:**
- Web app testing still in Early Access
- No source code analysis
- No business logic testing
- Enterprise pricing
- Cloud-hosted (Docker host is just the agent, orchestration is cloud)
- No open-source components

---

### 1.5 Terra Security — Human-in-the-Loop Agentic

- **Raised:** $38M total ($30M Series A, Sept 2025). Backed by Felicis, Dell Technologies Capital.
- **Focus:** Continuous web app + API pentesting with mandatory human oversight
- **Architecture:** Two-layer agent system:
  - **Ambient AI agents** — Autonomous: recon, code review, test case generation, reachability analysis, exploitability validation, documentation, remediation
  - **Copilot AI agents** — Human-directed: approved exploitation, controlled testing, reporting
- **Terra Portal** — Desktop app where human pentesters direct and oversee AI testing
- **Change-based continuous testing** — Every code/config change triggers evaluation
- **Context accumulation** — Onboarding context persists, doesn't restart every quarter
- **Compliance-ready** — Defensible reports for audits, SOC 2, regulated environments
- **MSSP model** — Enables service providers to scale pentesting without linear headcount

**Architectural lessons for us:**
- Two-tier agent model (autonomous ambient + human-directed copilot) is smart for safety
- Change-based triggers (CI/CD integration for continuous testing)
- Context accumulation across engagements (similar to Neo's memory)
- MSSP/service provider model as a business opportunity
- Compliance-ready output is a must for enterprise customers
- "The future of pentesting isn't autonomous versus human — it's giving humans leverage"

**Gaps we can exploit:**
- Enterprise/MSSP focused, not individual-accessible
- No network or AD testing
- No self-hosted option
- Relatively new (founded 2024)
- Small team (25 people)

---

### 1.6 Shannon (Keygraph) — White-Box Source Code + Exploitation

- **Focus:** White-box web app pentesting (requires source code access)
- **Architecture:** Reads source code first → maps attack surface → executes real exploits via browser automation
- **Uses Claude Agent SDK** for reasoning, Nmap for recon, Playwright for browser automation
- **96.15% on XBOW benchmark** (100/104) — highest known score
- **"No Exploit, No Report" policy** — zero false positives in final output
- **Dual licensing:** Lite (AGPL-3.0 open source) + Pro (enterprise with LLM data flow analysis)
- **$50/run cost**, 1-1.5 hours per assessment
- **10,000+ GitHub stars** already
- **Weakness:** Tunnel vision on OWASP hits (SQLi, XSS, SSRF, auth bypass). Ignores business logic flaws and config issues.

**Architectural lessons for us:**
- White-box (source code + running app) beats black-box every time
- "No Exploit, No Report" = zero false positive philosophy
- 96.15% XBOW score proves source-aware exploitation is king
- CI/CD integration for daily testing (not annual)
- Claude Agent SDK as the reasoning framework

**Gaps we can exploit:**
- White-box only (useless without source code access)
- Web apps only
- Ignores business logic flaws
- No network, AD, cloud, API-specific testing
- No persistent memory across engagements
- No multi-step attack chaining across roles

---

### 1.7 PentestGPT — The Academic Foundation

- **Published at USENIX Security 2024** (academic paper)
- **86.5% on XBOW benchmark** (90/104). Average cost: $1.11 per challenge.
- **Three modules:** Reasoning (planning), Generation (command execution), Parsing (output analysis)
- **Evolved into fully autonomous pipeline** from interactive assistant
- **Authors moved on to build CAI** — PentestGPT is now legacy
- **Langfuse integration** for observability and telemetry
- **Docker-based with pre-configured security tools**

---

### 1.8 Other Notable Tools

**CAI (Cybersecurity AI Framework):**
- Evolved from PentestGPT by the same authors
- Multi-agent orchestration with extensive tooling
- Supports local models (Ollama), Burp Suite integration
- Can handle network attacks (Pass the Hash)
- Most flexible but hardest to configure

**Strix:**
- Open-source AI hackers with PoC validation
- Uses LiteLLM, Caido, Nuclei, Playwright
- DevSecOps/CI/CD integration focus
- Auto-fix suggestions

**BugTrace-AI:**
- AI-driven discovery assistant (not exploitation)
- Analyzes URLs, JS files, headers for patterns
- Good at initial recon, not at exploitation

**HexStrike:**
- MCP-based framework with 150+ security tools, 12+ autonomous agents
- Runs on Kali Linux, uses proven pentesting tools
- Fast and reproducible results

**PentAGI:**
- Multi-agent system: research, coding, infrastructure roles
- Docker-isolated execution
- Browser + search for real-time intelligence gathering

**LuaN1ao (鸾鸟):**
- Chinese AI pentest tool based on state awareness and causal reasoning
- Sophisticated multi-host intrusion capabilities

---

## Part 2: Critical Analysis — What's Missing (Pentester's Perspective)

### The Debate: What I Got Wrong in V1

The V1 architecture was designed like a software engineer would think about it — clean layers, tool integration, data flow. But a pentester thinks about this differently. Here's what the V1 missed:

---

### 2.1 AGENT CAPABILITY & TRAINING (You asked: "Do agents need practice?")

**YES. This is the single biggest gap in V1.**

An agent that has Nmap as a tool but doesn't know WHEN to use `-sV -sC` vs `-A -T4` vs `--script vuln` is useless. The tool is only as good as the agent's ability to wield it intelligently. This needs:

**A) Tool Proficiency System (CRITICAL)**
- Each agent type needs proficiency profiles for every tool it can access
- Proficiency isn't just "can call the tool" — it's "knows the right flags, interprets output correctly, chains output to next action"
- Example: Nmap agent needs to know that finding port 88 (Kerberos) means "this is likely a Domain Controller → pivot to AD attack chain"
- Proficiency is TRAINED through practice runs against known vulnerable targets

**B) Training Arena / Simulation Environment (CRITICAL)**
- Agents should practice against deliberately vulnerable environments BEFORE real engagements
- Built-in targets: DVWA, Juice Shop, WebGoat, GOAD, Vulnhub machines
- After practice, measure: Did the agent find the known vulns? Did it chain them correctly? How many false positives?
- This creates a proficiency score per agent type per vulnerability class
- NodeZero proved this — they solved GOAD in 14 minutes because their agents KNOW AD attack patterns intimately

**C) Agent Self-Evaluation (NICE TO HAVE)**
- After each engagement, agents compare their findings against ground truth (if available)
- Agents that consistently miss certain vuln types get retrained with additional context
- Cyber-AutoAgent's Ragas metrics are a starting point

---

### 2.2 MEMORY SYSTEM (You asked: "Where's mem?")

The V1 architecture mentions memory in passing. It needs to be a first-class system with multiple layers:

**A) Working Memory (per-agent, ephemeral) (CRITICAL)**
- Current observations, hypotheses, and plans for this specific agent mission
- Dies when agent is retired
- Implemented as: structured JSON in agent context

**B) Engagement Memory (per-engagement, persistent) (CRITICAL)**
- Target map, discovered services, credentials found, attack paths tried
- Shared across all agents in the same engagement
- Implemented as: PostgreSQL + vector embeddings (pgvector)
- This is what the coordinator uses to avoid duplicate work

**C) Long-Term Memory (cross-engagement, persistent) (CRITICAL)**
- "Last time we tested a Django app with this stack, we found IDOR on 73% of endpoints"
- "Company X's previous pentest found weak JWT implementation — check if it's fixed"
- Attack pattern success rates by technology stack
- Implemented as: Vector database (Qdrant or pgvector) + embedding model

**D) Knowledge Base (static + evolving) (CRITICAL)**
- Vulnerability patterns (YAML), exploit techniques, tool usage guides
- MITRE ATT&CK framework data
- CWE/CVE databases
- Updated from: community contributions + automated CVE monitoring + engagement learnings

**E) Credential Store (per-engagement, encrypted) (CRITICAL)**
- Found credentials, session tokens, API keys during engagement
- Securely stored, scoped per engagement, auto-destroyed after
- Agents can query: "Do we have any valid creds for this service?"
- This is how attack chaining works — one agent finds creds, another uses them

---

### 2.3 ATTACK GRAPH & CHAINING ENGINE (CRITICAL — Completely Missing in V1)

This is what separates a scanner from a pentester. Real attackers don't find individual vulns — they chain them:

**A) Attack Graph**
- Directed graph of all discovered nodes (hosts, services, accounts, data)
- Edges represent: "can reach," "has credential for," "can exploit," "can pivot to"
- Updated in real-time as agents discover new paths
- This is how NodeZero chains from initial access → lateral movement → domain compromise
- Horizon3.ai's HVT uses this to prioritize which paths to test first

**B) Kill Chain Tracking**
- Map every finding to the cyber kill chain / MITRE ATT&CK stages
- Track: Initial Access → Execution → Persistence → Privilege Escalation → Lateral Movement → Collection → Exfiltration
- Show the complete attack narrative, not just isolated findings

**C) Pivot Engine**
- When an agent compromises a host/account, the coordinator should automatically:
  1. Add new attack surface to the graph
  2. Spawn new agents for the newly accessible targets
  3. Test whether compromised credentials work elsewhere
  4. Check for lateral movement opportunities
- This is the "organic pivoting" that NodeZero does when it moves from on-prem to Azure

---

### 2.4 REPORTING ENGINE (Severely Under-specified in V1)

As a pentester, the report IS the deliverable. V1 treated it as an afterthought.

**A) Professional VAPT Report Generation (CRITICAL)**
- Executive summary (non-technical, for C-suite)
- Technical findings with CVSS v4.0 scoring
- Reproducible PoC for every finding (curl commands, screenshots, HTTP requests)
- Remediation guidance per finding (developer-ready)
- Risk heat map / attack surface visualization
- MITRE ATT&CK mapping
- Compliance mapping (OWASP Top 10, CIS, NIST, PCI-DSS, ISO 27001)
- Output formats: PDF, HTML, Markdown, DOCX, JSON (machine-readable)

**B) Evidence Capture System (CRITICAL)**
- Every agent action must produce auditable evidence
- Screenshots of exploited states
- Full HTTP request/response pairs
- Terminal output logs
- Network packet captures (for network tests)
- Timestamps for every action
- This is non-negotiable for compliance and client delivery

**C) Engagement Timeline (NICE TO HAVE)**
- Chronological view of everything that happened during the engagement
- "At 14:32, Agent-07 discovered port 443 on 10.10.1.5 running Apache Tomcat 9.0.31"
- "At 14:35, Agent-12 identified CVE-2020-1938 (Ghostcat) applicable"
- "At 14:37, Agent-12 confirmed exploitation with PoC — data exfiltration possible"

**D) Differential Reports (NICE TO HAVE)**
- Compare current engagement vs previous engagement
- "3 findings from last test are now fixed, 2 new findings discovered"
- This is what continuous testing customers need

---

### 2.5 SCOPE & SAFETY SYSTEM (Under-specified in V1)

Real pentesting requires ironclad scope enforcement. One rogue request outside scope = legal trouble.

**A) Scope Definition Engine (CRITICAL)**
- Define allowed targets: IPs, CIDR ranges, domains, URLs
- Define exclusions: specific hosts, time windows, action types
- Define rules of engagement: max request rate, allowed exploit types, no data modification
- Every agent checks scope before EVERY action (not just at initialization)

**B) Safety Controls (CRITICAL)**
- Action classification: passive (recon) → active (scanning) → invasive (exploitation) → destructive (never)
- Human approval gates at escalation boundaries
- Rate limiting per target (avoid DoS)
- Automatic rollback for any modifications (if testing in production)
- Emergency kill switch — immediately halt all agents
- Pentera's "Safety by Design" principle — controlled payloads, auto-cleanup

**C) Audit Trail (CRITICAL)**
- Every agent action logged with: timestamp, agent ID, target, action, result, scope check
- Immutable audit log (append-only, cannot be modified)
- Exportable for compliance/legal review
- This protects both you AND your client

---

### 2.6 INFRASTRUCTURE COMPLEXITY (You're Right — Way Too Simple)

**A) Vector Database for Memory (CRITICAL)**
- pgvector (PostgreSQL extension) or Qdrant for embedding-based similarity search
- Stores: engagement memories, vulnerability patterns, tool usage patterns, attack success rates
- Enables: "Find engagements similar to this target" and "What worked against Django apps before?"

**B) Artifact Storage (CRITICAL)**
- MinIO/S3 for storing: screenshots, pcap files, downloaded files, evidence packages, reports
- Organized per engagement, per finding
- Signed URLs for secure sharing with clients

**C) Sandbox Orchestration (CRITICAL)**
- Docker/Podman per agent for isolation
- Network namespace controls (agent can only reach in-scope targets)
- Resource limits (CPU, memory, time per agent)
- Gvisor/Firecracker for stronger isolation if needed
- Auto-cleanup: sandbox destroyed after agent completes

**D) Message Queue Architecture (CRITICAL)**
- Redis Streams or RabbitMQ for: agent-to-coordinator communication, event-driven triggers, real-time UI updates
- Celery for long-running background tasks
- WebSocket for real-time dashboard updates

**E) Observability Stack (CRITICAL)**
- Langfuse or OpenTelemetry for: agent reasoning traces, tool execution timing, token consumption, cost tracking
- Prometheus + Grafana for: system metrics, agent health, queue depth
- Structured logging (JSON) with correlation IDs per engagement

**F) Cost Tracking & Optimization (CRITICAL for your budget)**
- Track LLM token usage per agent, per engagement
- Horizon3.ai's two-phase approach: fast pattern matching BEFORE invoking LLM
- Use Haiku for simple tasks, Sonnet for analysis, Opus only for complex chains
- Prompt caching (reduces costs up to 90% per NodeZero's data)
- Budget caps per engagement with graceful degradation

---

### 2.7 CI/CD & CONTINUOUS TESTING INTEGRATION (Missing in V1)

Every serious competitor now offers this. It's table stakes.

**A) CI/CD Pipeline Integration (NICE TO HAVE → becoming CRITICAL)**
- GitHub Actions, GitLab CI, Jenkins integration
- Trigger security testing on: PR merge, deployment, scheduled cadence
- Block deployments if critical findings detected
- Shannon and Strix both have this — it's becoming standard

**B) Change-Based Testing (NICE TO HAVE)**
- Terra's approach: detect meaningful changes → test only affected surface
- Don't re-test the entire app when only one endpoint changed
- Requires: baseline scan + diff detection + targeted re-scan

**C) API-First Design (CRITICAL)**
- Everything accessible via REST API
- Enables integration with: SIEM, ticketing (Jira), Slack notifications, custom workflows
- Horizon3.ai has an MCP server for AI ecosystem integration
- ProjectDiscovery tools have MCP server already

---

### 2.8 WHITE-BOX + BLACK-BOX DUAL MODE (Missing in V1)

Shannon proved that white-box (source code + running app) achieves 96% vs ~85% for black-box.

**A) Source Code Analysis Module (NICE TO HAVE → HIGH VALUE)**
- Ingest source code repos (Git integration)
- Static analysis: identify sinks, sources, data flows
- Map code patterns to potential vulnerabilities
- Feed source-aware context to exploitation agents
- "This endpoint at /api/disputes doesn't validate refund_amount against transaction.amount — test this"

**B) Black-Box Mode (CRITICAL — default mode)**
- No source code needed
- Pure external testing based on discovery + exploitation
- This is what most clients provide

**C) Gray-Box Mode (NICE TO HAVE)**
- Credentials provided but no source code
- Most common real-world pentest scenario
- Test as authenticated user across different roles

---

### 2.9 POST-EXPLOITATION & PERSISTENCE TESTING (Completely Missing in V1)

Real pentesters don't stop at "I found a vuln." They ask "What can I DO with it?"

**A) Impact Demonstration (CRITICAL)**
- After exploitation: What data can be accessed? Can we pivot? Can we escalate?
- "I got SQLi → dumped the users table → found admin credentials → logged in as admin → accessed all customer PII"
- This is the attack narrative that makes reports impactful

**B) Data Sensitivity Classification (NICE TO HAVE)**
- When data is accessed during exploitation, classify it: PII, financial, health, credentials, internal docs
- Automatic sensitivity tagging helps with impact assessment
- Relevant for: GDPR, HIPAA, PCI-DSS compliance

**C) Persistence Testing (for internal/AD tests) (NICE TO HAVE)**
- Can we maintain access? Create backdoor accounts? Scheduled tasks?
- NodeZero tests this as part of their AD assessment
- Important for demonstrating real attacker impact

---

### 2.10 THREAT INTELLIGENCE INTEGRATION (Missing in V1)

**A) CVE/Exploit Feed (CRITICAL)**
- Automatic updates when new CVEs are published
- Map discovered services to known CVEs (cvemap integration)
- Priority testing of actively exploited vulns (CISA KEV list)
- NodeZero's "Rapid Response" feature — test for new zero-days within minutes

**B) Dark Web Credential Monitoring (NICE TO HAVE)**
- Check if client credentials appear in breach databases
- Pentera has this as a product (Credentials Exposure)
- Feed compromised creds into testing (test if they still work)

**C) Threat Actor TTP Mapping (NICE TO HAVE)**
- "APT29 typically targets organizations like yours using technique X"
- Tailor testing to threat actors relevant to the client's industry
- MITRE ATT&CK navigator integration

---

## Part 3: Revised Architecture (Full Complexity)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OVERWATCH V2 — FULL SYSTEM                        │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                     COMMAND CENTER (Layer 0)                          │  │
│  │  FastAPI REST + WebSocket + React Dashboard (future)                 │  │
│  │  Natural language task input · Real-time agent stream                │  │
│  │  Engagement management · Scope definition · Budget controls          │  │
│  │  CI/CD webhooks · Slack/Jira integration · API-first                │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │                     COORDINATOR (Layer 1)                             │  │
│  │                                                                       │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌─────────────┐ ┌──────────────┐  │  │
│  │  │ Target Map  │ │ Attack Graph │ │ Kill Chain  │ │ Budget Mgr   │  │  │
│  │  │ (dynamic)   │ │ (directed    │ │ Tracker     │ │ (token/time  │  │  │
│  │  │             │ │  graph with  │ │ (ATT&CK     │ │  limits per  │  │  │
│  │  │             │ │  pivot edges)│ │  stages)    │ │  agent)      │  │  │
│  │  └─────────────┘ └──────────────┘ └─────────────┘ └──────────────┘  │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌─────────────┐ ┌──────────────┐  │  │
│  │  │ Strategy    │ │ Scope        │ │ Safety      │ │ HVT Engine   │  │  │
│  │  │ Planner     │ │ Enforcer     │ │ Controller  │ │ (high-value  │  │  │
│  │  │ (deterministic│ │ (every      │ │ (kill switch│ │  target      │  │  │
│  │  │  not LLM)   │ │  action)     │ │  approval   │ │  prioritizer)│  │  │
│  │  │             │ │              │ │  gates)     │ │              │  │  │
│  │  └─────────────┘ └──────────────┘ └─────────────┘ └──────────────┘  │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │                     MEMORY SYSTEM (Layer 2)                           │  │
│  │                                                                       │  │
│  │  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────┐  │  │
│  │  │ Working Memory  │  │ Engagement Memory │  │ Long-Term Memory    │  │  │
│  │  │ (per-agent,     │  │ (shared across    │  │ (cross-engagement,  │  │  │
│  │  │  ephemeral)     │  │  agents, per-     │  │  vector embeddings, │  │  │
│  │  │                 │  │  engagement)      │  │  pattern success    │  │  │
│  │  │                 │  │                   │  │  rates by stack)    │  │  │
│  │  └─────────────────┘  └──────────────────┘  └─────────────────────┘  │  │
│  │  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────┐  │  │
│  │  │ Knowledge Base  │  │ Credential Store │  │ Advisory Layer      │  │  │
│  │  │ (vuln patterns, │  │ (found creds,    │  │ (Bayesian priors    │  │  │
│  │  │  ATT&CK, CWE,  │  │  tokens, keys —  │  │  from past engage-  │  │  │
│  │  │  tool guides,   │  │  encrypted,      │  │  ments, technology  │  │  │
│  │  │  YAML configs)  │  │  scoped, auto-   │  │  stack success      │  │  │
│  │  │                 │  │  destroyed)      │  │  rates)             │  │  │
│  │  └─────────────────┘  └──────────────────┘  └─────────────────────┘  │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │                     AGENT FACTORY (Layer 3)                           │  │
│  │                                                                       │  │
│  │  Spawns short-lived focused agents with:                              │  │
│  │  • Single hypothesis to test (scoped objective)                       │  │
│  │  • Fresh context (no accumulated bias)                                │  │
│  │  • Confidence-driven reasoning loop (KNOW→THINK→TEST→VALIDATE)       │  │
│  │  • Tool proficiency profile (knows HOW to use each tool)             │  │
│  │  • Meta-prompting (can rewrite own guidance at checkpoints)          │  │
│  │  • Budget limit + scope check on every action                        │  │
│  │  • Retired after mission completion                                   │  │
│  │                                                                       │  │
│  │  Agent Types:                                                         │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │  Recon   │ │ Web App  │ │ Network  │ │   API    │ │Auth/RBAC │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ Business │ │  Cloud   │ │   AD     │ │  Pivot   │ │  Triage  │  │  │
│  │  │  Logic   │ │ Security │ │  Attack  │ │  & Post  │ │  & FP    │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐                            │  │
│  │  │ Source   │ │ Payload  │ │  Report  │                            │  │
│  │  │  Code    │ │ Crafter  │ │  Writer  │                            │  │
│  │  └──────────┘ └──────────┘ └──────────┘                            │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │                     SANDBOX + TOOL LAYER (Layer 4)                    │  │
│  │                                                                       │  │
│  │  Per-agent Docker sandbox with network namespace controls             │  │
│  │                                                                       │  │
│  │  Discovery:                                                           │  │
│  │  Subfinder · Naabu · httpx · Katana · dnsx · Nmap · Uncover          │  │
│  │  Cloudlist · Amass · Masscan                                          │  │
│  │                                                                       │  │
│  │  Detection + Scanning:                                                │  │
│  │  Nuclei (9K+ templates) · SQLMap · Nikto · Wapiti · Dirb/Gobuster   │  │
│  │  ffuf · Interactsh (OOB) · cvemap · Semgrep (SAST)                  │  │
│  │                                                                       │  │
│  │  Exploitation + Browser:                                              │  │
│  │  Playwright/Puppeteer (headless browser) · Custom HTTP client         │  │
│  │  LLM-crafted payloads · CyberChef (encoding/decoding)               │  │
│  │  JWT toolkit · Hashcat/John (credential cracking)                    │  │
│  │                                                                       │  │
│  │  Infrastructure + AD:                                                 │  │
│  │  BloodHound · Impacket · CrackMapExec · Responder · Mimikatz        │  │
│  │  Rubeus · Certipy · Evil-WinRM · Chisel (tunneling)                  │  │
│  │                                                                       │  │
│  │  Cloud:                                                               │  │
│  │  ScoutSuite · Prowler · CloudSploit · Pacu (AWS exploitation)        │  │
│  │  AzureHound · enumerate-iam                                           │  │
│  │                                                                       │  │
│  │  Utilities:                                                           │  │
│  │  LinPEAS/WinPEAS (privesc) · pspy (process monitoring)              │  │
│  │  tcpdump/tshark · curl/httpie · jq · Python (scripting)             │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │                     VALIDATION ENGINE (Layer 5)                       │  │
│  │                                                                       │  │
│  │  • Deterministic exploit verification (XBOW principle)               │  │
│  │  • Multi-step PoC execution with evidence capture                     │  │
│  │  • False positive elimination via runtime testing                     │  │
│  │  • Confidence scoring with evidence chain                             │  │
│  │  • Human approval gate for high-risk validations                      │  │
│  │  • Non-destructive validation (safe exploitation)                     │  │
│  │  • Impact demonstration (what can attacker do with this access?)     │  │
│  │  • 1-click revalidation after fix (Horizon3 feature)                 │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │                     OBSERVABILITY + LEARNING (Layer 6)                │  │
│  │                                                                       │  │
│  │  ┌──────────────┐ ┌───────────────┐ ┌─────────────┐ ┌────────────┐  │  │
│  │  │ Trace System │ │ Observation   │ │ Evaluation  │ │ Training   │  │  │
│  │  │ (Langfuse /  │ │ Store         │ │ Metrics     │ │ Data       │  │  │
│  │  │ OpenTelemetry│ │ (every action │ │ (Ragas-     │ │ Export     │  │  │
│  │  │ every agent  │ │  result,      │ │  style: tool│ │ (JSONL for │  │  │
│  │  │ decision)    │ │  decision,    │ │  selection, │ │  fine-     │  │  │
│  │  │              │ │  outcome)     │ │  evidence   │ │  tuning)   │  │  │
│  │  │              │ │               │ │  quality)   │ │            │  │  │
│  │  └──────────────┘ └───────────────┘ └─────────────┘ └────────────┘  │  │
│  │  ┌──────────────┐ ┌───────────────┐ ┌─────────────────────────────┐  │  │
│  │  │ Human        │ │ Cost          │ │ Agent Proficiency Tracker   │  │  │
│  │  │ Feedback     │ │ Tracking      │ │ (success rate per agent    │  │  │
│  │  │ → Ground     │ │ (tokens, $,   │ │  type per vuln class.     │  │  │
│  │  │   Truth      │ │  per agent)   │ │  Retrain underperformers) │  │  │
│  │  └──────────────┘ └───────────────┘ └─────────────────────────────┘  │  │
│  └──────────────────────────────┬────────────────────────────────────────┘  │
│                                 │                                           │
│  ┌──────────────────────────────▼────────────────────────────────────────┐  │
│  │                     REPORTING ENGINE (Layer 7)                        │  │
│  │                                                                       │  │
│  │  • Professional VAPT reports (PDF/HTML/DOCX/Markdown/JSON)           │  │
│  │  • Executive summary (non-technical, for C-suite)                     │  │
│  │  • Technical findings with CVSS v4.0 scoring                         │  │
│  │  • Reproducible PoC for EVERY finding (curl, screenshots, HTTP)      │  │
│  │  • Developer-ready remediation per finding                            │  │
│  │  • MITRE ATT&CK mapping + kill chain visualization                   │  │
│  │  • Compliance mapping (OWASP, CIS, NIST, PCI-DSS, ISO 27001)       │  │
│  │  • Attack narrative (full story of how we got from A to Z)           │  │
│  │  • Risk heat map + attack surface visualization                       │  │
│  │  • Differential reports (current vs previous engagement)             │  │
│  │  • Evidence package (all screenshots, logs, pcaps in ZIP)            │  │
│  │  • Engagement timeline (chronological audit trail)                    │  │
│  │  • Mentorship mode (explains WHY, teaches the defender)              │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                     TRAINING ARENA (Layer 8 — Unique to Overwatch)     ││
│  │                                                                         ││
│  │  Built-in deliberately vulnerable targets for agent training:           ││
│  │  DVWA · Juice Shop · WebGoat · GOAD · VulnHub machines                ││
│  │  crAPI · Damn Vulnerable GraphQL · CloudGoat                           ││
│  │                                                                         ││
│  │  Agents practice here before real engagements.                          ││
│  │  Proficiency scores tracked. Underperformers retrained.                 ││
│  │  New tool integrations validated here first.                            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                     INFRASTRUCTURE (Layer 9)                            ││
│  │                                                                         ││
│  │  PostgreSQL + pgvector · Redis Streams · Celery · Docker/Podman        ││
│  │  MinIO (artifact storage) · Qdrant (optional vector DB)                ││
│  │  Langfuse (traces) · Prometheus + Grafana (metrics)                    ││
│  │  Vault (secrets management) · Nginx (reverse proxy)                    ││
│  │  WebSocket server (real-time UI) · Webhook receiver (CI/CD triggers)   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 4: Competitive Edge — What Makes Overwatch Unique

| Capability | XBOW | Neo | Horizon3 | Terra | Shannon | Overwatch V2 |
|---|---|---|---|---|---|---|
| Web app testing | Strong | Strong | Early Access | Strong | Strong (white-box) | Yes |
| Network pentest | No | Limited | Strong | No | No | Yes |
| AD attacks | No | No | Strong (GOAD in 14min) | No | No | Yes (planned) |
| Cloud security | No | Limited | Strong | No | No | Yes (planned) |
| Business logic | Yes | Yes | Limited | Yes | No | Yes |
| Source code analysis | No | Yes | No | Yes | Yes (required) | Optional (dual mode) |
| Self-hosted | No | No | Docker host only | No | Yes (Lite) | Yes |
| Persistent memory | Unknown | Yes | Limited | Yes | No | Yes |
| Agent training arena | Unknown | No | No | No | No | Yes (unique) |
| Mentorship/teaching | No | No | No | No | No | Yes (unique) |
| Open-source tools | No | Yes (own ecosystem) | No | No | Some | Yes (PD + others) |
| Attack graph/chaining | Yes | Yes | Yes (strongest) | Limited | No | Yes |
| Cost for freelancer | $2K+ | Enterprise | Enterprise | Enterprise | ~$50/run | Free (self-hosted) |
| False positive rate | Very low | 7% (93% precision) | Very low | Low | 0% (no exploit=no report) | Target: <5% |
| XBOW benchmark score | ~85% (baseline) | N/A | N/A | N/A | 96.15% | Target: 85%+ |

**The unique value proposition no one else offers:**

1. Multi-domain coverage (web + network + AD + cloud) — like Pentera but AI-native
2. Self-hosted and affordable — like open-source tools but with enterprise capabilities  
3. Agent training arena — no one else trains their agents against known targets before real work
4. Persistent learning memory — like Neo but accessible to individuals
5. Mentorship mode — like having a senior pentester explain everything
6. Bayesian advisory context — historical intelligence from past engagements
7. Open-source tool ecosystem — leverage Nuclei's 9K+ templates + all PD tools
8. Dual-mode (white-box + black-box) — maximize coverage when source is available
9. Attack graph with organic pivoting — like Horizon3 but with LLM reasoning
10. Professional reporting with evidence packages — deliverable-quality output

---

## Part 5: Priority Classification

### CRITICAL (Must have for MVP)
1. Coordinator with scope enforcement and safety controls
2. Agent factory with confidence-driven reasoning loop
3. Memory system (working + engagement + long-term + knowledge base + credential store)
4. Tool layer (Nuclei, httpx, Nmap, Katana, Naabu, Subfinder, custom HTTP, Playwright)
5. Validation engine with PoC generation
6. Evidence capture system
7. Reporting engine (PDF/HTML with CVSS, PoC, remediation)
8. Audit trail (immutable logging)
9. Cost tracking and optimization
10. Attack graph with chaining

### HIGH VALUE (Phase 2)
11. Training arena with proficiency scoring
12. Meta-prompting (agents rewrite own guidance)
13. Plans as external memory
14. Observability stack (Langfuse traces + Ragas evaluation)
15. White-box/source code analysis mode
16. CI/CD integration
17. 1-click revalidation
18. MITRE ATT&CK mapping
19. Differential reports
20. Human feedback → ground truth pipeline

### NICE TO HAVE (Phase 3+)
21. Threat intelligence feed (CVE monitoring, CISA KEV)
22. Dark web credential monitoring
23. MCP server for AI ecosystem integration
24. MSSP/multi-tenant mode
25. AD attack module (BloodHound, Impacket)
26. Cloud security module (ScoutSuite, Prowler)
27. Compliance mapping (PCI-DSS, ISO 27001, HIPAA)
28. Tripwires/honeytokens (defensive byproduct)
29. Threat actor TTP-based testing
30. Data sensitivity classification

---

## Appendix: All Competitor Resources

| Tool | Type | URL | XBOW Score |
|---|---|---|---|
| XBOW | Commercial | https://xbow.com | Baseline (~85%) |
| Neo | Commercial | https://projectdiscovery.io | N/A |
| NodeZero | Commercial | https://horizon3.ai | N/A (solved GOAD in 14min) |
| Terra | Commercial | https://terra.security | N/A |
| Shannon Lite | Open Source | https://github.com/KeygraphHQ/shannon | 96.15% (100/104) |
| PentestGPT | Open Source | https://github.com/GreyDGL/PentestGPT | 86.5% (90/104) |
| Cyber-AutoAgent | Open Source | https://github.com/westonbrown/Cyber-AutoAgent | 84.62% (88/104) |
| CAI | Open Source | https://github.com/GreyDGL/CAI | N/A |
| Strix | Open Source | https://github.com/usestrix/strix | N/A |
| PentAGI | Open Source | https://github.com/vxcontrol/pentagi | N/A |
| HexStrike | Open Source | 150+ tools, MCP-based | N/A |
| Zen-AI-Pentest | Open Source | Nmap + Metasploit orchestration | N/A |
| BugTrace-AI | Open Source | Discovery/recon assistant | N/A |
| LuaN1ao | Open Source | State-aware causal reasoning | N/A |
