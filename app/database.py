import asyncpg
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from app.config import get_settings

# Global connection pool
_pool: Optional[asyncpg.Pool] = None


# Database schema for cyber attacks
SCHEMA_SQL = """
-- Create the cyber_attacks table
CREATE TABLE IF NOT EXISTS cyber_attacks (
    id SERIAL PRIMARY KEY,
    attack_id INTEGER,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_country VARCHAR(100),
    destination_country VARCHAR(100),
    protocol VARCHAR(20),
    source_port INTEGER,
    destination_port INTEGER,
    attack_type VARCHAR(100),
    payload_size INTEGER,
    detection_label VARCHAR(50),
    confidence_score DECIMAL(10, 9),
    ml_model VARCHAR(100),
    affected_system VARCHAR(100),
    port_type VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE
);

-- Create indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_attack_type ON cyber_attacks(attack_type);
CREATE INDEX IF NOT EXISTS idx_source_country ON cyber_attacks(source_country);
CREATE INDEX IF NOT EXISTS idx_destination_country ON cyber_attacks(destination_country);
CREATE INDEX IF NOT EXISTS idx_detection_label ON cyber_attacks(detection_label);
CREATE INDEX IF NOT EXISTS idx_timestamp ON cyber_attacks(timestamp);
CREATE INDEX IF NOT EXISTS idx_affected_system ON cyber_attacks(affected_system);
"""

# Schema description for LLM context
SCHEMA_DESCRIPTION = """
Database: PostgreSQL
Table: cyber_attacks

Columns:
- id: SERIAL PRIMARY KEY - Auto-generated unique identifier
- attack_id: INTEGER - Original attack ID from dataset
- source_ip: VARCHAR(45) - IP address of attack source
- destination_ip: VARCHAR(45) - IP address of attack target
- source_country: VARCHAR(100) - Country where attack originated (e.g., 'USA', 'China', 'India', 'Germany', 'France', 'UK', 'Japan', 'Brazil', 'Russia', 'South Korea')
- destination_country: VARCHAR(100) - Country of attack target
- protocol: VARCHAR(20) - Network protocol used (TCP, UDP, ICMP)
- source_port: INTEGER - Source port number
- destination_port: INTEGER - Destination port number
- attack_type: VARCHAR(100) - Type of cyber attack. Values include:
  * 'Brute Force'
  * 'Advanced Persistent Threat (APT)'
  * 'Cross-Site Scripting (XSS) Attack'
  * 'Insider Threat'
  * 'Watering Hole Attack'
  * 'SQL Injection'
  * 'Credential Stuffing'
  * 'Drive-by Download'
  * 'Cryptojacking'
  * 'Zero-Day Exploit'
  * 'Malware'
  * 'Phishing'
  * 'Distributed Denial of Service (DDoS)'
  * 'Man-in-the-Middle (MITM)'
  * 'Remote Desktop Protocol (RDP) Attack'
  * 'Ransomware'
- payload_size: INTEGER - Size of attack payload in bytes
- detection_label: VARCHAR(50) - Whether attack was detected ('Detected', 'Not Detected')
- confidence_score: DECIMAL(10,9) - ML model confidence score (0.0 to 1.0)
- ml_model: VARCHAR(100) - ML model used for detection (e.g., 'Random Forest', 'Neural Network', 'K-Nearest Neighbors', 'Support Vector Machine', 'Logistic Regression')
- affected_system: VARCHAR(100) - Type of system affected (e.g., 'Cloud Storage', 'Network Router', 'Workstation', 'Web Server', 'Database Server', 'Email Server', 'Firewall', 'IoT Device', 'Application Server')
- port_type: VARCHAR(50) - Classification of port
- timestamp: TIMESTAMP WITH TIME ZONE - When the attack occurred

Total records: ~90,000 cyber attack incidents

IMPORTANT: This database does NOT contain:
- Number of users affected
- Financial loss amounts
- Vulnerability CVE identifiers
- Specific malware names
- Company/organization names
"""


async def init_pool() -> asyncpg.Pool:
    """Initialize the database connection pool."""
    global _pool
    if _pool is None:
        settings = get_settings()
        _pool = await asyncpg.create_pool(
            settings.database_url,
            min_size=2,
            max_size=10,
            command_timeout=60
        )
    return _pool


async def close_pool():
    """Close the database connection pool."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def get_pool() -> asyncpg.Pool:
    """Get the database connection pool."""
    if _pool is None:
        await init_pool()
    return _pool


@asynccontextmanager
async def get_connection():
    """Get a database connection from the pool."""
    pool = await get_pool()
    async with pool.acquire() as connection:
        yield connection


async def execute_query(query: str) -> List[Dict[str, Any]]:
    """Execute a SELECT query in a read-only transaction and return results as list of dicts."""
    async with get_connection() as conn:
        try:
            # Use a read-only transaction to prevent any writes
            async with conn.transaction(readonly=True):
                rows = await conn.fetch(query)
                return [dict(row) for row in rows]
        except Exception as e:
            raise Exception(f"Query execution failed: {str(e)}")


async def execute_query_safe(query: str) -> Dict[str, Any]:
    """
    Execute a query with safety checks.
    Returns dict with 'success', 'data' or 'error' keys.
    """
    import re

    query_clean = query.strip()
    query_upper = query_clean.upper()

    # Must start with SELECT
    if not query_upper.startswith("SELECT"):
        return {
            "success": False,
            "error": "Only SELECT queries are allowed"
        }

    # Strip string literals for structural analysis (handle escaped quotes too)
    query_no_strings = re.sub(r"'(?:[^']|'')*'", "", query_clean)

    # Block multiple statements
    if ";" in query_no_strings:
        return {
            "success": False,
            "error": "Multiple SQL statements are not allowed"
        }

    # Block dangerous keywords (word-boundary matching)
    dangerous_patterns = [
        r'\bDROP\b', r'\bDELETE\b', r'\bINSERT\b', r'\bUPDATE\b',
        r'\bALTER\b', r'\bTRUNCATE\b', r'\bEXEC\b', r'\bEXECUTE\b',
        r'\bCREATE\b', r'\bGRANT\b', r'\bREVOKE\b', r'\bCOPY\b',
        r'\bLOAD\b', r'\bIMPORT\b',
    ]
    query_no_strings_upper = query_no_strings.upper()
    for pattern in dangerous_patterns:
        if re.search(pattern, query_no_strings_upper):
            return {
                "success": False,
                "error": "Query contains a disallowed operation"
            }

    # Block SQL comment syntax
    if "--" in query_no_strings or "/*" in query_no_strings:
        return {
            "success": False,
            "error": "SQL comments are not allowed"
        }

    # Block time-based blind SQL injection patterns
    blind_sqli_patterns = [
        r'\bpg_sleep\b', r'\bsleep\b', r'\bbenchmark\b',
        r'\bwaitfor\b', r'\bdelay\b',
        r'\bdblink\b', r'\blo_import\b', r'\blo_export\b',
    ]
    for pattern in blind_sqli_patterns:
        if re.search(pattern, query_clean, re.IGNORECASE):
            return {
                "success": False,
                "error": "Query contains a disallowed function"
            }

    # Block system table access
    system_tables = [
        r'information_schema', r'pg_catalog', r'pg_tables', r'pg_proc',
        r'pg_shadow', r'pg_roles', r'pg_user', r'pg_stat', r'pg_settings',
        r'pg_database', r'pg_authid', r'pg_class', r'pg_namespace',
    ]
    for pattern in system_tables:
        if re.search(pattern, query_clean, re.IGNORECASE):
            return {
                "success": False,
                "error": "Access to system tables is not allowed"
            }

    # Block subqueries in FROM clause — FROM (SELECT ...)
    if re.search(r'\bFROM\s*\(', query_no_strings, re.IGNORECASE):
        return {
            "success": False,
            "error": "Subqueries in FROM clause are not allowed"
        }

    # Block UNION-based injection
    if re.search(r'\bUNION\b', query_no_strings_upper):
        return {
            "success": False,
            "error": "UNION queries are not allowed"
        }

    # Ensure query only references the cyber_attacks table
    from_tables = re.findall(r'\bFROM\s+(\w+)', query_no_strings, re.IGNORECASE)
    join_tables = re.findall(r'\bJOIN\s+(\w+)', query_no_strings, re.IGNORECASE)
    all_tables = from_tables + join_tables
    for table in all_tables:
        if table.lower() != "cyber_attacks":
            return {
                "success": False,
                "error": "Only the 'cyber_attacks' table can be queried"
            }

    try:
        results = await execute_query(query_clean)
        # Hard cap: never return more than 100 rows regardless of query
        MAX_ROWS = 100
        truncated = len(results) > MAX_ROWS
        results = results[:MAX_ROWS]
        return {
            "success": True,
            "data": results,
            "row_count": len(results),
            "truncated": truncated
        }
    except Exception as e:
        return {
            "success": False,
            "error": "Query execution failed"
        }


def get_schema_description() -> str:
    """Get the schema description for LLM context."""
    return SCHEMA_DESCRIPTION
