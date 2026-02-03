@echo off
echo ============================================
echo    CyberRAG Demo Startup Script
echo ============================================
echo.

echo [1/4] Checking Docker...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not running. Please start Docker Desktop first.
    pause
    exit /b 1
)
echo Docker is running.

echo.
echo [2/4] Starting PostgreSQL container...
docker start cyberrag-postgres 2>nul || echo Container already running
timeout /t 2 >nul

echo.
echo [3/4] Checking Ollama...
curl -s http://localhost:11434/api/version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Ollama is not running. Please start Ollama manually.
    echo Run: ollama serve
) else (
    echo Ollama is running.
)

echo.
echo [4/4] Starting CyberRAG API Server...
echo.
echo ============================================
echo    API will be available at:
echo    http://localhost:8000
echo
echo    Swagger Docs:
echo    http://localhost:8000/docs
echo ============================================
echo.

cd /d %~dp0
python run_server.py
