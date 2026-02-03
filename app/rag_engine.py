import json
import re
import httpx
from typing import Dict, Any, Optional

from app.config import get_settings
from app.database import get_schema_description, execute_query_safe


class RAGEngine:
    """RAG Engine for translating natural language to SQL queries."""

    def __init__(self):
        settings = get_settings()
        self.ollama_url = settings.ollama_url
        self.model = settings.ollama_model
        self.schema_description = get_schema_description()

    def _build_system_prompt(self) -> str:
        """Build the system prompt with schema context."""
        return f"""You are a SQL query generator for a cyber threat intelligence database. Your task is to convert natural language questions into PostgreSQL queries.

{self.schema_description}

RULES:
1. Generate ONLY valid PostgreSQL SELECT queries
2. If the question asks for information NOT available in the database (like number of users affected, financial loss, CVE IDs, specific malware names, company names), respond with: {{"available": false, "reason": "explanation of what data is missing"}}
3. If the question CAN be answered with available data, respond with: {{"available": true, "sql": "YOUR SQL QUERY HERE", "explanation": "brief explanation of what the query does"}}
4. Always use proper SQL syntax for PostgreSQL
5. Use appropriate aggregations (COUNT, SUM, AVG, MAX, MIN) when needed
6. Use GROUP BY for aggregated queries
7. Use ORDER BY and LIMIT for "top N" queries
8. For geographic distribution, group by source_country or destination_country
9. Always return results in a useful format
10. Limit results to 100 rows maximum unless specifically asked for more

RESPONSE FORMAT (JSON only):
For answerable questions:
{{"available": true, "sql": "SELECT ...", "explanation": "..."}}

For unanswerable questions:
{{"available": false, "reason": "This database does not contain information about..."}}
"""

    def _build_user_prompt(self, query: str) -> str:
        """Build the user prompt with the natural language query."""
        return f"""Convert this natural language question to a PostgreSQL query:

Question: {query}

Respond with JSON only."""

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call Ollama API."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.ollama_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.1
                    }
                }
            )
            response.raise_for_status()
            result = response.json()
            return result["message"]["content"]

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse the LLM response JSON."""
        # Try to extract JSON from the response
        try:
            # First, try direct JSON parse
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to find JSON in markdown code blocks
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to find JSON object pattern
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # If all parsing fails, return error
        return {
            "available": False,
            "reason": "Failed to parse LLM response"
        }

    async def process_query(self, natural_language_query: str) -> Dict[str, Any]:
        """
        Process a natural language query and return results.

        Args:
            natural_language_query: The user's question in natural language

        Returns:
            Dict containing:
            - success: bool
            - data: list of results (if successful)
            - sql: the generated SQL (if successful)
            - message: status message
            - error: error message (if failed)
        """
        try:
            # Step 1: Call LLM to generate SQL
            system_prompt = self._build_system_prompt()
            user_prompt = self._build_user_prompt(natural_language_query)

            llm_response = await self._call_llm(system_prompt, user_prompt)
            parsed_response = self._parse_llm_response(llm_response)

            # Step 2: Check if query is answerable
            if not parsed_response.get("available", False):
                return {
                    "success": False,
                    "message": "not available",
                    "reason": parsed_response.get("reason", "Query cannot be answered with available data"),
                    "data": None
                }

            # Step 3: Get the SQL query
            sql_query = parsed_response.get("sql")
            if not sql_query:
                return {
                    "success": False,
                    "message": "not available",
                    "reason": "No SQL query generated",
                    "data": None
                }

            # Step 4: Execute the query
            query_result = await execute_query_safe(sql_query)

            if not query_result["success"]:
                return {
                    "success": False,
                    "message": "query_error",
                    "error": query_result["error"],
                    "sql": sql_query,
                    "data": None
                }

            # Step 5: Return successful results
            return {
                "success": True,
                "message": "success",
                "sql": sql_query,
                "explanation": parsed_response.get("explanation", ""),
                "data": query_result["data"],
                "row_count": query_result["row_count"]
            }

        except Exception as e:
            return {
                "success": False,
                "message": "error",
                "error": str(e),
                "data": None
            }


# Singleton instance
_rag_engine: Optional[RAGEngine] = None


def get_rag_engine() -> RAGEngine:
    """Get the RAG engine singleton instance."""
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine
