# AI-Powered Cyber Range — CVE-2014-6271 (Shellshock)

A self-contained cyber range that pairs a **deliberately vulnerable web
application** with an **AI security agent** built on LangChain. The agent
autonomously discovers, exploits, and reports vulnerabilities — demonstrating
key AI-agent engineering skills.

---

## Skills Demonstrated

| Skill Area | Where It Shows Up |
|---|---|
| **AI agent construction (LangChain)** | `agent/security_agent.py` — ReAct agent with `AgentExecutor` |
| **Agent design: reasoning** | Chain-of-thought via ReAct loop; explicit `Thought → Action → Observation` cycle |
| **Agent design: memory** | `ConversationBufferMemory` retains context across reasoning steps |
| **Agent design: tool orchestration** | 4 custom tools (`http_get`, `http_get_custom_header`, `lookup_cve`, `generate_report`) composed dynamically |
| **Structured outputs** | Pydantic models (`VulnerabilityReport`, `Vulnerability`) in `agent/models.py` |
| **Prompt engineering** | System prompt with role, methodology, rules in `agent/prompts.py` |
| **RAG** | FAISS vector store over CVE knowledge base (`agent/rag.py`) |
| **Chain-of-thought** | Built into the ReAct prompt template — agent must reason before each action |
| **Few-shot learning** | Worked examples of Shellshock and SQLi discovery in the prompt |
| **Agent evaluation** | `evaluate.py` — automated scoring against expected findings |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AI Security Agent                     │
│  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐ │
│  │ ReAct    │  │ Memory   │  │ RAG /  │  │ Structured│ │
│  │ Reasoning│──│ (Buffer) │──│ FAISS  │──│ Outputs   │ │
│  └────┬─────┘  └──────────┘  └────────┘  └───────────┘ │
│       │  Tool Orchestration                              │
│  ┌────┴──────────────────────────────────────────┐      │
│  │ http_get │ http_get_custom_header │ lookup_cve │      │
│  │                generate_report                 │      │
│  └────────────────────┬──────────────────────────┘      │
└───────────────────────┼─────────────────────────────────┘
                        │ HTTP
┌───────────────────────┼─────────────────────────────────┐
│   Vulnerable App      ▼            (Docker)              │
│  ┌──────────────────────────────────────────────┐       │
│  │ /cgi-bin/status  — Shellshock (CVE-2014-6271)│       │
│  │ /api/ping        — OS command injection       │       │
│  │ /api/users       — SQL injection              │       │
│  │ /robots.txt      — Information disclosure     │       │
│  └──────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- An OpenAI API key

### 1. Clone and configure

```bash
git clone <repo-url> && cd cyber-range
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

### 2. Start the vulnerable target

```bash
docker compose up -d --build
# Verify it's running:
curl http://localhost:8080/
```

### 3. Install agent dependencies

```bash
pip install -r agent/requirements.txt
```

### 4. Run the AI security agent

```bash
python -m agent.main
```

The agent will:
1. Perform **reconnaissance** — fetch the landing page, robots.txt, inspect headers
2. **Research** — query the RAG knowledge base for relevant CVEs
3. **Test** — send Shellshock payloads, command-injection strings, SQLi probes
4. **Exploit** — prove impact by reading files and extracting database flags
5. **Report** — produce a structured vulnerability report

### 5. Evaluate the agent (optional)

```bash
python evaluate.py
```

Scores the agent's performance against expected findings.

### 6. Tear down

```bash
docker compose down
```

---

## Project Structure

```
cyber-range/
├── docker-compose.yml            # Container orchestration
├── .env.example                  # Environment template
├── evaluate.py                   # Agent evaluation harness
├── vulnerable-app/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py                    # Intentionally vulnerable Flask app
└── agent/
    ├── requirements.txt          # Python dependencies
    ├── main.py                   # CLI entry point
    ├── security_agent.py         # LangChain ReAct agent
    ├── tools.py                  # Custom agent tools
    ├── rag.py                    # RAG / FAISS vector store
    ├── models.py                 # Pydantic structured output models
    ├── prompts.py                # Prompt engineering (system, few-shot, CoT)
    └── knowledge/
        └── cve_database.json     # CVE knowledge base for RAG
```

---

## Vulnerability Details

### CVE-2014-6271 — Shellshock (simulated)

The `/cgi-bin/status` endpoint passes the `User-Agent` header directly into
a `bash -c` call, mirroring how Apache mod_cgi + vulnerable Bash enabled
Shellshock.

**Exploit manually:**
```bash
curl -H "User-Agent: \$(cat /etc/passwd)" http://localhost:8080/cgi-bin/status
```

### OS Command Injection — /api/ping

The `host` query parameter is concatenated into a `ping` shell command.

```bash
curl "http://localhost:8080/api/ping?host=127.0.0.1;id"
```

### SQL Injection — /api/users

The `username` parameter is interpolated into a SQL query.

```bash
curl "http://localhost:8080/api/users?username=' UNION SELECT 1,flag,3 FROM secrets--"
```

---

## How the Agent Works (for reviewers)

### Prompt Engineering (`agent/prompts.py`)

The system prompt defines the agent's role, a 5-step methodology, severity
classification rubric, and strict behavioural rules. Few-shot examples show
complete worked-through Shellshock and SQLi discovery sequences so the model
has concrete patterns to follow.

### RAG (`agent/rag.py`)

CVE entries are loaded from `knowledge/cve_database.json`, embedded with
OpenAI's `text-embedding-3-small`, and stored in a FAISS vector index.
The agent's `lookup_cve` tool performs semantic similarity search to retrieve
relevant vulnerability information during assessment.

### Tool Orchestration (`agent/tools.py`)

Four tools with Pydantic input schemas:

| Tool | Purpose |
|------|---------|
| `http_get` | Recon, endpoint testing, query-param injection |
| `http_get_custom_header` | Header injection (Shellshock payloads) |
| `lookup_cve` | RAG-powered vulnerability research |
| `generate_report` | Structured report generation |

### Structured Outputs (`agent/models.py`)

Pydantic v2 models enforce schema validation on the final report:
`VulnerabilityReport` → `Vulnerability` → `Severity` enum.

### Memory (`agent/security_agent.py`)

`ConversationBufferMemory` stores the full interaction history, allowing the
agent to reference earlier findings when making later decisions.

### Evaluation (`evaluate.py`)

Checks agent output against 4 expected findings with keyword matching and
weighted scoring. Produces a percentage grade.

---

## Disclaimer

This application is **intentionally vulnerable** and must only be run in
isolated environments for educational purposes. Never expose it to the
public internet.
