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

    print("Starting CyberRAG API Server...")
    print(f"Server will be available at: http://localhost:{port}")
    print(f"API Documentation: http://localhost:{port}/docs")
    print()

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=True
    )
