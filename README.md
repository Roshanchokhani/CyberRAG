# CyberRAG

A RAG (Retrieval-Augmented Generation) application for querying cyber threat intelligence data using natural language.

## Overview

CyberRAG translates natural language questions into SQL queries, executes them against a PostgreSQL database containing cyber attack records, and returns results in JSON format. If a query cannot be answered with the available data, it returns a "not available" message.

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐     ┌────────────┐
│ curl Client │────▶│  FastAPI    │────▶│  RAG Engine  │────▶│ PostgreSQL │
│             │◀────│  (Async)    │◀────│  (Ollama)    │◀────│  (Docker)  │
└─────────────┘     └─────────────┘     └──────────────┘     └────────────┘
```

## Features

- Natural language to SQL query translation
- Async API handling for concurrent requests
- Automatic detection of unanswerable queries
- JSON response format
- Swagger API documentation

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11, FastAPI |
| Database | PostgreSQL 16 (Docker) |
| LLM | Ollama + llama3.2 |
| Async DB | asyncpg |

## Project Structure

```
CyberRAG/
├── app/
│   ├── config.py          # Configuration management
│   ├── database.py        # PostgreSQL connection & queries
│   ├── main.py            # FastAPI async endpoints
│   └── rag_engine.py      # RAG + LLM logic
├── scripts/
│   ├── import_data.py     # CSV to PostgreSQL import
│   ├── test_client.py     # Python test client
│   └── test_client.sh     # Bash/curl test client
├── requirements.txt
├── run_server.py
└── start_demo.bat
```

## Prerequisites

- Python 3.11+
- Docker Desktop
- Ollama with llama3.2 model

## Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd CyberRAG
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set up environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Start PostgreSQL (Docker)
```bash
docker run -d \
  --name cyberrag-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=cyberrag \
  -p 5433:5432 \
  postgres:16
```

### 5. Import data
```bash
python scripts/import_data.py
```

### 6. Start Ollama
```bash
ollama serve
# In another terminal: ollama pull llama3.2
```

### 7. Start the API server
```bash
python run_server.py
```

## Usage

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/query` | POST | Natural language query |
| `/schema` | GET | Database schema info |
| `/docs` | GET | Swagger documentation |

### Example Queries

**Top attack types:**
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the top 10 most common attack types?"}'
```

**Geographic distribution:**
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Show attacks grouped by source country"}'
```

**Detection rate:**
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What percentage of attacks are detected?"}'
```

**Unavailable data (returns "not available"):**
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Show financial losses from attacks"}'
```

### Run Test Suite
```bash
python scripts/test_client.py
```

## Sample Response

**Success:**
```json
{
  "success": true,
  "message": "success",
  "sql": "SELECT attack_type, COUNT(*) FROM cyber_attacks GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 10",
  "data": [
    {"attack_type": "DNS Tunneling", "count": 4627},
    {"attack_type": "XSS Attack", "count": 4596}
  ],
  "row_count": 10
}
```

**Not Available:**
```json
{
  "success": false,
  "message": "not available",
  "reason": "This database does not contain information about financial losses."
}
```

## Database Schema

| Column | Type | Description |
|--------|------|-------------|
| attack_id | INTEGER | Unique attack identifier |
| source_ip | VARCHAR | Attack source IP |
| destination_ip | VARCHAR | Target IP |
| source_country | VARCHAR | Origin country |
| destination_country | VARCHAR | Target country |
| protocol | VARCHAR | Network protocol (TCP/UDP/ICMP) |
| attack_type | VARCHAR | Type of attack |
| payload_size | INTEGER | Payload size in bytes |
| detection_label | VARCHAR | Detected/Not Detected |
| confidence_score | DECIMAL | ML model confidence |
| ml_model | VARCHAR | Detection model used |
| affected_system | VARCHAR | Target system type |
| timestamp | TIMESTAMP | Attack timestamp |

## Configuration

Environment variables (`.env`):

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5433/cyberrag
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
HOST=0.0.0.0
PORT=8000
```

## Documentation

- [Implementation Choices](IMPLEMENTATION.md) - Detailed explanation of design decisions
- [Demo Guide](DEMO_GUIDE.txt) - Quick reference for demonstrations

## License

MIT
