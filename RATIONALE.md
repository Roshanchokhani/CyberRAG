# Implementation Choices - Rationale

A quick reference guide explaining the rationale behind each implementation choice.

---

## 1. Why PostgreSQL?
> "The assignment specified PostgreSQL. It handles complex aggregations efficiently and has native timestamp support for time-series data."

## 2. Why Docker for PostgreSQL?
> "Provides an isolated, reproducible environment. Easy to set up and tear down without affecting the host system."

## 3. Why Text-to-SQL instead of Vector RAG?
> "The data is structured and tabular. Vector databases are for semantic similarity on unstructured text. SQL gives precise, deterministic results for aggregations like COUNT, GROUP BY, and filtering."

## 4. Why Ollama (Local LLM)?
> "No API costs, works offline, and keeps data private. For production, we could swap to OpenAI or Claude API with minimal code changes."

## 5. Why FastAPI?
> "Modern, fast, built-in async support. The assignment required async request handling. FastAPI also auto-generates Swagger documentation."

## 6. Why Async?
> "LLM calls take 2-10 seconds. Async allows the server to handle multiple concurrent requests without blocking while waiting for LLM responses."

## 7. Why asyncpg instead of psycopg2?
> "Native async support. Works seamlessly with FastAPI's async endpoints. Connection pooling handles concurrent database connections."

## 8. How do you handle "Not Available" queries?
> "The LLM receives the complete database schema. It knows what data exists. If a query asks for unavailable data like user counts or financial loss, it returns 'not available' with a reason instead of generating invalid SQL."

## 9. How do you prevent SQL injection?
> "Three layers: Only SELECT queries allowed, dangerous keywords (DROP, DELETE, etc.) are blocked, and the LLM generates SQL from schema context rather than direct user input."

## 10. How would you scale this?
> - "Add Redis for caching frequent queries"
> - "Connection pooling is already implemented"
> - "Deploy multiple FastAPI workers with Gunicorn"
> - "Use PostgreSQL read replicas for heavy read loads"
> - "Use a faster LLM model for better accuracy"

---

## Architecture Decision Summary

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Database | PostgreSQL | Assignment requirement, good for aggregations |
| Containerization | Docker | Reproducible, isolated environment |
| RAG Approach | Text-to-SQL | Structured data needs SQL, not vector search |
| LLM | Ollama/llama3.2 | Free, local, private, swappable |
| API Framework | FastAPI | Async support, auto-docs, modern |
| DB Driver | asyncpg | Native async for concurrent requests |
| UI | Streamlit | Quick to build, interactive, good for demos |

---

## If Asked "What Would You Improve?"

> "Given more time, I would add:
> 1. **Caching** - Redis for frequent queries
> 2. **Query validation** - Verify SQL before execution
> 3. **Rate limiting** - Prevent API abuse
> 4. **Logging** - Better observability
> 5. **Tests** - Unit and integration tests
> 6. **Better LLM** - GPT-4 or Claude for more accurate SQL generation"

---

## Quick Answers Cheat Sheet

| Question | Short Answer |
|----------|--------------|
| Why not vector DB? | Structured data → SQL is precise |
| Why async? | LLM is slow, don't block other requests |
| SQL injection? | SELECT only + keyword blocking |
| Why local LLM? | Free, offline, private |
| How to scale? | Redis cache + more workers + read replicas |
