"""
CyberRAG API Test Client (Python version)

This script tests the RAG API with various natural language queries.
Works on Windows, macOS, and Linux without requiring bash.
"""

import requests
import json
import sys

BASE_URL = "http://localhost:8000"


def print_separator(char="=", length=60):
    print(char * length)


def print_response(response_json):
    """Pretty print the JSON response."""
    print(json.dumps(response_json, indent=2, default=str))


def health_check():
    """Test the health endpoint."""
    print("\n1. Health Check")
    print("-" * 40)
    try:
        response = requests.get(f"{BASE_URL}/health")
        print_response(response.json())
        return True
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to API. Is the server running?")
        print(f"Make sure the server is running at {BASE_URL}")
        return False


def query(natural_language_query: str, test_number: int, description: str):
    """Send a query to the API."""
    print(f"\n{test_number}. Query: {description}")
    print("-" * 40)
    print(f"Question: {natural_language_query}")
    print()

    try:
        response = requests.post(
            f"{BASE_URL}/query",
            json={"query": natural_language_query},
            headers={"Content-Type": "application/json"}
        )
        result = response.json()
        print_response(result)
        return result
    except requests.exceptions.ConnectionError:
        print("ERROR: Connection failed")
        return None


def main():
    print_separator()
    print("CyberRAG API Test Client")
    print_separator()

    # Health check first
    if not health_check():
        sys.exit(1)

    # Test queries
    test_queries = [
        ("What are the top 10 most common attack types?", "Top attack types"),
        ("Show me the geographic distribution of attacks by source country", "Geographic distribution"),
        ("What percentage of attacks are detected vs not detected?", "Detection rate"),
        ("Which network protocols are most commonly used in attacks?", "Most common protocols"),
        ("What are the most commonly affected system types?", "Most targeted systems"),
        ("Which ML models have the highest average confidence scores?", "ML model performance"),
        ("How many attacks originated from China targeting USA?", "Attacks between countries"),
        ("Get the top ten vulnerabilities that impacted the most number of users and resulted in highest loss", "Users and loss (not available)"),
        ("What are the top 10 attacks with the largest payload sizes?", "Largest payloads"),
        ("Show me DDoS attacks grouped by source country", "DDoS by country"),
    ]

    for i, (q, desc) in enumerate(test_queries, start=2):
        query(q, i, desc)

    print()
    print_separator()
    print("Test completed!")
    print_separator()


if __name__ == "__main__":
    main()
