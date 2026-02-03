# CyberRAG Interview Demo Guide

## Pre-Demo Setup (Do this 10 mins before the call)

### Step 1: Start Docker Desktop
- Open Docker Desktop from Start Menu
- Wait until it shows "Running"

### Step 2: Start PostgreSQL
```bash
docker start cyberrag-postgres
```

### Step 3: Start Ollama
- Open Ollama from Start Menu (or run `ollama serve`)

### Step 4: Open Two Terminals

**Terminal 1 - API Server:**
```bash
cd C:\Users\roshanchokhani\Desktop\CyberRAG
python run_server.py
```

**Terminal 2 - Streamlit UI:**
```bash
cd C:\Users\roshanchokhani\Desktop\CyberRAG
streamlit run streamlit_app.py
```

### Step 5: Open Browser
- Go to: **http://localhost:8501**

---

## Demo Flow (During the Interview)

### 1. Introduction (1 min)
> "I've built CyberRAG - a RAG application that lets you query 90,000+ cyber attack records using natural language. It translates questions into SQL and returns results in JSON format."

### 2. Show the UI (1 min)
- Point out the **sidebar** showing available data types
- Show the **sample query buttons**
- Mention the **API status indicator** (green = connected)

### 3. Demo Query 1: Basic Query (2 min)
Click or type:
> **"What are the top 10 most common attack types?"**

**Explain:**
- "The query goes to FastAPI → Ollama LLM → generates SQL → executes on PostgreSQL → returns JSON"
- Show the **results table**
- Expand **"Generated SQL Query"** to show what was created

### 4. Demo Query 2: Geographic Distribution (2 min)
> **"Show geographic distribution of attacks by source country"**

**Explain:**
- "This demonstrates aggregation queries with GROUP BY"
- Point out the country-wise breakdown

### 5. Demo Query 3: Complex Query (2 min)
> **"How many attacks originated from China targeting USA?"**

**Explain:**
- "This shows filtering with multiple conditions (WHERE clause)"

### 6. Demo Query 4: "Not Available" Test (2 min) ⭐ Important!
> **"Get the top ten vulnerabilities that impacted the most number of users and resulted in highest loss"**

**Explain:**
- "This is the sample query from the assignment"
- "The system correctly identifies that user counts and financial loss data are NOT in our database"
- "It returns 'not available' with a clear reason instead of failing or giving wrong results"

### 7. Show Architecture (1 min)
> "Let me quickly show the code structure..."

Open these files briefly:
- `app/main.py` → "Async FastAPI endpoints"
- `app/rag_engine.py` → "LLM integration with Ollama"
- `app/database.py` → "PostgreSQL connection pool"

---

## Key Talking Points

| When Asked | Your Answer |
|------------|-------------|
| "Why not vector database?" | "Data is structured/tabular. SQL gives precise results for aggregations." |
| "Why async?" | "LLM calls take 2-10 seconds. Async handles concurrent requests without blocking." |
| "How do you prevent SQL injection?" | "Only SELECT allowed, dangerous keywords blocked, LLM generates from schema context." |
| "Why Ollama vs OpenAI?" | "Local LLM = no API costs, works offline, data privacy." |
| "How would you scale?" | "Redis caching, connection pooling (already done), multiple workers, read replicas." |

---

## Quick Recovery Commands

If something breaks during demo:

```bash
# Check all services
docker ps                                  # PostgreSQL running?
curl http://localhost:11434/api/version    # Ollama running?
curl http://localhost:8000/health          # API running?
curl http://localhost:8501                 # Streamlit running?

# Restart if needed
docker start cyberrag-postgres
python run_server.py
streamlit run streamlit_app.py
```

---

## Demo Checklist

- [ ] Docker Desktop running
- [ ] PostgreSQL container running (port 5433)
- [ ] Ollama running (port 11434)
- [ ] API server running (port 8000)
- [ ] Streamlit UI running (port 8501)
- [ ] Browser open at http://localhost:8501
- [ ] Tested one query before the call

---

## URLs

| Service | URL |
|---------|-----|
| Streamlit UI | http://localhost:8501 |
| API Health | http://localhost:8000/health |
| Swagger Docs | http://localhost:8000/docs |
| GitHub Repo | https://github.com/Roshanchokhani/CyberRAG |

---

Good luck! 🚀
