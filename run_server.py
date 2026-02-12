"""
Simple script to run the CyberRAG API server.
"""

import uvicorn
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    environment = os.getenv("ENVIRONMENT", "development")
    is_production = environment == "production"

    print("Starting CyberRAG API Server...")
    print(f"Environment: {environment}")
    print(f"Server will be available at: http://localhost:{port}")
    if not is_production:
        print(f"API Documentation: http://localhost:{port}/docs")
    print()

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=(not is_production),
        log_level="warning" if is_production else "info",
    )
