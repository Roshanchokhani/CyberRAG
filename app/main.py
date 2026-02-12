import logging
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import get_settings

logger = logging.getLogger("cyberrag")

settings = get_settings()


# --- Rate Limiter ---
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])


# --- API Key Authentication ---
async def verify_api_key(request: Request):
    """Verify API key if configured."""
    if not settings.api_key:
        return  # No API key configured, skip auth
    api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# --- Request/Response Models ---
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
    note: Optional[str] = None


class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    message: str


# --- Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    from app.database import init_pool, close_pool
    print("Starting CyberRAG API...")
    await init_pool()
    print("Database connection pool initialized")
    yield
    print("Shutting down CyberRAG API...")
    await close_pool()
    print("Database connection pool closed")


# --- Create FastAPI App ---
is_production = settings.environment == "production"

app = FastAPI(
    title="CyberRAG API",
    description="A RAG-based API for querying cyber threat intelligence data using natural language",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
)

# Register rate limiter
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded errors."""
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "message": "rate_limited",
            "error": "Too many requests. Please try again later."
        }
    )


# --- Endpoints ---

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint (no auth required)."""
    return HealthResponse(
        status="healthy",
        message="CyberRAG API is running"
    )


@app.post("/query", response_model=QueryResponse, dependencies=[Depends(verify_api_key)])
@limiter.limit(settings.rate_limit)
async def process_query(request: Request, body: QueryRequest):
    """
    Process a natural language query about cyber threats.

    Requires X-API-Key header if API_KEY is configured.
    """
    try:
        from app.rag_engine import get_rag_engine
        rag_engine = get_rag_engine()

        result = await rag_engine.process_query(body.query)

        return QueryResponse(**result)

    except Exception as e:
        # Log the full error internally but return sanitized message
        logger.error(f"Query processing error: {type(e).__name__}: {str(e)}")
        return QueryResponse(
            success=False,
            message="error",
            error="An internal error occurred. Please try again later."
        )


@app.get("/schema", dependencies=[Depends(verify_api_key)])
@limiter.limit(settings.rate_limit)
async def get_schema_info(request: Request):
    """
    Get information about available query types.

    Requires X-API-Key header if API_KEY is configured.
    """
    return {
        "available_query_types": [
            "Attack type statistics (e.g., 'What are the most common attack types?')",
            "Geographic distribution (e.g., 'Which countries are the main sources of attacks?')",
            "Protocol analysis (e.g., 'What protocols are most commonly used in attacks?')",
            "Detection analysis (e.g., 'What percentage of attacks are detected?')",
            "Time-based analysis (e.g., 'Show attack trends over time')",
            "System impact (e.g., 'Which systems are most commonly targeted?')",
            "ML model performance (e.g., 'Which ML models have the highest confidence scores?')"
        ],
        "note": "Ask natural language questions about cyber attack data."
    }


# Run with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=(settings.environment != "production")
    )
