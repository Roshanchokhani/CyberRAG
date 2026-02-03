# CyberRAG - Implementation Choices

## 1. Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐     ┌────────────┐
│ curl Client │────▶│  FastAPI    │────▶│  RAG Engine  │────▶│ PostgreSQL │
│             │◀────│  (Async)    │◀────│  (Ollama)    │◀────│  (Docker)  │
└─────────────┘     └─────────────┘     └──────────────┘     └────────────┘
```

---

## 2. Component-by-Component Explanation

### Component 1: PostgreSQL Database

**Choice:** PostgreSQL with Docker

**Rationale:**
- **PostgreSQL** was specified in the assignment ("Postgres time series database")
- **Docker** provides isolated, reproducible environment - easy to set up and tear down
- PostgreSQL handles complex aggregations (COUNT, GROUP BY, ORDER BY) efficiently
- Native support for TIMESTAMP WITH TIME ZONE for time-series data

**Schema Design:**
```sql
CREATE TABLE cyber_attacks (
    id SERIAL PRIMARY KEY,
    attack_id INTEGER,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_country VARCHAR(100),
    destination_country VARCHAR(100),
    protocol VARCHAR(20),
    source_port INTEGER,
    destination_port INTEGER,
    attack_type VARCHAR(100),
    payload_size INTEGER,
    detection_label VARCHAR(50),
    confidence_score DECIMAL(10, 9),
    ml_model VARCHAR(100),
    affected_system VARCHAR(100),
    port_type VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE
);
```

**Why these indexes?**
```sql
CREATE INDEX idx_attack_type ON cyber_attacks(attack_type);
CREATE INDEX idx_source_country ON cyber_attacks(source_country);
CREATE INDEX idx_destination_country ON cyber_attacks(destination_country);
CREATE INDEX idx_timestamp ON cyber_attacks(timestamp);
```
- Indexes on frequently queried columns (attack_type, countries, timestamp)
- Speeds up GROUP BY and WHERE clause operations

---

### Component 2: RAG Engine

**Choice:** Text-to-SQL approach using LLM (Ollama/llama3.2)

**Rationale:**
- **Why Text-to-SQL instead of Vector Embeddings?**
  - Data is structured (tabular), not unstructured text
  - SQL provides precise, deterministic results
  - No need for similarity search - users want exact answers

**How it works:**
```
User Query → LLM (with schema context) → SQL Query → Execute → JSON Response
```

**Key Implementation Details:**

#### 1. Schema Context Injection (`app/rag_engine.py`)
```python
def _build_system_prompt(self) -> str:
    return f"""You are a SQL query generator...
    {self.schema_description}  # Full schema injected here
    """
```
- LLM receives complete schema description
- Knows exactly what columns exist and their types
- Can determine if query is answerable

#### 2. "Not Available" Detection
```python
# LLM is instructed to return:
{"available": false, "reason": "explanation"}
# When data doesn't exist (e.g., user counts, financial loss)
```

#### 3. JSON Response Parsing
- Handles multiple response formats (raw JSON, markdown code blocks)
- Robust parsing with fallbacks

#### 4. SQL Safety (`app/database.py`)
```python
# Only SELECT queries allowed
if not query_upper.startswith("SELECT"):
    return {"error": "Only SELECT queries are allowed"}

# Block dangerous keywords
dangerous_keywords = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "TRUNCATE"]
```

---

### Component 3: FastAPI Async Service

**Choice:** FastAPI with async/await

**Rationale:**
- **Async requirement** was specified in assignment ("api requests should be handled in async approach")
- **FastAPI** is modern, fast, and has built-in async support
- Automatic OpenAPI documentation at `/docs`
- Pydantic models for request/response validation

**Key Implementation:**

```python
# Async endpoint (app/main.py)
@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    rag_engine = get_rag_engine()
    result = await rag_engine.process_query(request.query)  # Async call
    return QueryResponse(**result)
```

**Why async matters:**
- LLM calls take 2-10 seconds
- Async allows handling multiple requests concurrently
- Server doesn't block while waiting for LLM response

**Connection Pool:**
```python
_pool = await asyncpg.create_pool(
    settings.database_url,
    min_size=2,
    max_size=10  # Handles concurrent connections
)
```

---

### Component 4: Test Client

**Choice:** Both Python and Bash scripts

**Rationale:**
- **Python script** (`scripts/test_client.py`) for Windows compatibility and better output formatting
- **Bash script** (`scripts/test_client.sh`) for curl-based testing (as specified in assignment)
- Covers various query types including edge cases

---

## 3. Design Decisions & Trade-offs

| Decision | Alternative | Why This Choice |
|----------|-------------|-----------------|
| Ollama (local LLM) | OpenAI API | No API costs, works offline, data privacy |
| PostgreSQL | SQLite | Assignment specified PostgreSQL; better for production |
| Text-to-SQL | Vector RAG | Structured data → SQL is more precise |
| asyncpg | psycopg2 | Native async support for FastAPI |
| Docker for DB | Local install | Easier setup, reproducible environment |

---

## 4. Handling Edge Cases

### 1. Unanswerable queries
```json
{
  "success": false,
  "message": "not available",
  "reason": "This database does not contain information about..."
}
```

### 2. Invalid SQL generated
```json
{
  "success": false,
  "message": "query_error",
  "error": "SQL syntax error..."
}
```

### 3. NULL values in data
- Handled during import with `fillna()` for numeric columns
- Empty strings for text columns

### 4. Missing timestamps
- Generated random timestamps (2020-2025) as per assignment instructions

---

## 5. Project Structure

```
CyberRAG/
├── app/
│   ├── __init__.py
│   ├── config.py      # Centralized configuration (12-factor app)
│   ├── database.py    # Database abstraction layer
│   ├── rag_engine.py  # Core RAG logic (single responsibility)
│   └── main.py        # API routes (thin controller)
├── scripts/
│   ├── import_data.py # One-time data import
│   ├── test_client.py # Python test client
│   └── test_client.sh # Bash/curl test client
├── cyberattacks.csv   # Source data
├── requirements.txt   # Python dependencies
├── run_server.py      # Server launcher
├── start_demo.bat     # Windows startup script
├── .env               # Environment config (not in git)
└── .env.example       # Environment template
```

**Why this structure?**
- **Separation of concerns** - each file has one responsibility
- **Testability** - components can be tested independently
- **Configurability** - `.env` file for different environments

---

## 6. API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/query` | POST | Natural language query |
| `/schema` | GET | Database schema info |
| `/docs` | GET | Swagger documentation |

---

## 7. Interview Q&A

### "Why not use a vector database like Pinecone/Chroma?"
> The data is structured/tabular. Vector databases are for semantic similarity on unstructured text. SQL gives precise, deterministic results for aggregations and filtering.

### "How do you handle SQL injection?"
> Only SELECT queries allowed, dangerous keywords blocked, and the LLM generates queries based on schema context rather than user input directly.

### "Why async?"
> LLM calls are I/O bound (network latency). Async allows the server to handle other requests while waiting for LLM response, improving throughput.

### "How would you scale this?"
> - Add Redis for caching common queries
> - Use connection pooling (already implemented)
> - Deploy multiple FastAPI workers with Gunicorn
> - Consider read replicas for PostgreSQL
> - Use a faster/larger LLM model for better accuracy

### "What are the limitations?"
> - LLM may occasionally generate incorrect SQL
> - Response time depends on LLM speed (2-10 seconds)
> - Complex multi-table joins not supported (single table design)

---

## 8. Technologies Used

| Component | Technology | Version |
|-----------|------------|---------|
| Language | Python | 3.11 |
| Web Framework | FastAPI | 0.109.0 |
| Database | PostgreSQL | 16 |
| Async DB Driver | asyncpg | 0.29.0 |
| LLM | Ollama + llama3.2 | 0.15.4 |
| HTTP Client | httpx | 0.27.0 |
| Containerization | Docker | 28.0.4 |

---

## 9. Running the Project

### Prerequisites
- Python 3.11+
- Docker Desktop
- Ollama with llama3.2 model

### Quick Start
```bash
# 1. Start Docker Desktop

# 2. Start PostgreSQL
docker start cyberrag-postgres

# 3. Start Ollama (if not running)
ollama serve

# 4. Start API server
cd CyberRAG
python run_server.py

# 5. Test
curl http://localhost:8000/health
```

### Run Tests
```bash
python scripts/test_client.py
```

---

## 10. Sample Queries

```bash
# Top attack types
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the top 10 attack types?"}'

# Geographic distribution
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Show attacks by source country"}'

# Not available test
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Show financial losses from attacks"}'
```
