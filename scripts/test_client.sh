#!/bin/bash

# CyberRAG API Test Client
# This script tests the RAG API with various natural language queries

BASE_URL="http://localhost:8000"

echo "=========================================="
echo "CyberRAG API Test Client"
echo "=========================================="
echo ""

# Health check
echo "1. Health Check"
echo "-------------------------------------------"
curl -s "${BASE_URL}/health" | python -m json.tool
echo ""

# Test: Top attack types
echo "2. Query: Top 10 most common attack types"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the top 10 most common attack types?"}' | python -m json.tool
echo ""

# Test: Geographic distribution
echo "3. Query: Geographic distribution of attacks"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me the geographic distribution of attacks by source country"}' | python -m json.tool
echo ""

# Test: Detection rate
echo "4. Query: Detection rate"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "What percentage of attacks are detected vs not detected?"}' | python -m json.tool
echo ""

# Test: Protocols used
echo "5. Query: Most common protocols"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "Which network protocols are most commonly used in attacks?"}' | python -m json.tool
echo ""

# Test: Affected systems
echo "6. Query: Most targeted systems"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the most commonly affected system types?"}' | python -m json.tool
echo ""

# Test: ML model performance
echo "7. Query: ML model confidence scores"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "Which ML models have the highest average confidence scores?"}' | python -m json.tool
echo ""

# Test: Attack by country combination
echo "8. Query: Attacks between specific countries"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "How many attacks originated from China targeting USA?"}' | python -m json.tool
echo ""

# Test: Sample query from assignment (should return "not available")
echo "9. Query: Users and financial loss (should return not available)"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "Get the top ten vulnerabilities that impacted the most number of users and resulted in highest loss"}' | python -m json.tool
echo ""

# Test: Payload size analysis
echo "10. Query: Largest payload attacks"
echo "-------------------------------------------"
curl -s -X POST "${BASE_URL}/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the top 10 attacks with the largest payload sizes?"}' | python -m json.tool
echo ""

echo "=========================================="
echo "Test completed!"
echo "=========================================="
