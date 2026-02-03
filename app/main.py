from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager
import asyncio

from app.config import get_settings
from app.database import init_pool, close_pool
from app.rag_engine import get_rag_engine


# Request/Response Models
class QueryRequest(BaseModel):
    """Request model for natural language queries."""
    query: str = Field(..., min_length=1, max_length=1000, description="Natural language query")

    class Config:
        json_schema_extra = {
            "example": {
                "query": "What are the top 10 most common attack types?"
            }
        }


class QueryResponse(BaseModel):
    """Response model for query results."""
    success: bool
    message: str
    data: Optional[List[Dict[str, Any]]] = None
    sql: Optional[str] = None
    explanation: Optional[str] = None
    row_count: Optional[int] = None
    reason: Optional[str] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    message: str


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    # Startup
    print("Starting CyberRAG API...")
    await init_pool()
    print("Database connection pool initialized")
    yield
    # Shutdown
    print("Shutting down CyberRAG API...")
    await close_pool()
    print("Database connection pool closed")


# Create FastAPI app
app = FastAPI(
    title="CyberRAG API",
    description="A RAG-based API for querying cyber threat intelligence data using natural language",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        message="CyberRAG API is running"
    )


@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """
    Process a natural language query about cyber threats.

    This endpoint receives a natural language question, translates it to SQL
    using an LLM, executes the query against the database, and returns
    the results in JSON format.

    If the question cannot be answered with the available data, it returns
    a "not available" message with an explanation.
    """
    try:
        rag_engine = get_rag_engine()

        # Process query asynchronously
        result = await rag_engine.process_query(request.query)

        return QueryResponse(**result)

    except Exception as e:
        return QueryResponse(
            success=False,
            message="error",
            error=str(e)
        )


@app.get("/schema")
async def get_schema_info():
    """
    Get information about the database schema.

    Returns details about available columns and data types
    to help users formulate their queries.
    """
    from app.database import get_schema_description
    return {
        "schema_description": get_schema_description(),
        "available_query_types": [
            "Attack type statistics (e.g., 'What are the most common attack types?')",
            "Geographic distribution (e.g., 'Which countries are the main sources of attacks?')",
            "Protocol analysis (e.g., 'What protocols are most commonly used in attacks?')",
            "Detection analysis (e.g., 'What percentage of attacks are detected?')",
            "Time-based analysis (e.g., 'Show attack trends over time')",
            "System impact (e.g., 'Which systems are most commonly targeted?')",
            "ML model performance (e.g., 'Which ML models have the highest confidence scores?')"
        ],
        "note": "This database does NOT contain: user counts, financial loss, CVE IDs, company names"
    }


# Run with uvicorn
if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=True
    )
