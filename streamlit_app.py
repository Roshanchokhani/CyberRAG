"""
CyberRAG - Streamlit UI
A simple web interface for querying cyber threat intelligence data.
"""

import os
import streamlit as st
import requests
import pandas as pd
import json
from dotenv import load_dotenv

load_dotenv()

# Configuration
API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("API_KEY", "")


def get_headers():
    """Build request headers with API key if configured."""
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers

# Page config
st.set_page_config(
    page_title="CyberRAG",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E88E5;
        margin-bottom: 0;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #666;
        margin-top: 0;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #E8F5E9;
        border-left: 4px solid #4CAF50;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #FFEBEE;
        border-left: 4px solid #F44336;
    }
    .sql-box {
        background-color: #263238;
        color: #80CBC4;
        padding: 1rem;
        border-radius: 0.5rem;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<p class="main-header">🛡️ CyberRAG</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Query cyber threat intelligence data using natural language</p>', unsafe_allow_html=True)
st.divider()

# Sidebar
with st.sidebar:
    st.header("ℹ️ About")
    st.write("""
    CyberRAG translates natural language questions into SQL queries
    and returns results from a database of 90,000+ cyber attack records.
    """)

    st.header("📊 Available Data")
    st.write("""
    - Attack types (DDoS, XSS, Malware, etc.)
    - Geographic distribution (countries)
    - Network protocols (TCP, UDP, ICMP)
    - Affected systems
    - Detection status
    - ML model confidence scores
    """)

    st.header("❌ Not Available")
    st.write("""
    - User impact counts
    - Financial losses
    - CVE identifiers
    - Company names
    """)

    st.divider()

    # Health check
    try:
        health = requests.get(f"{API_URL}/health", timeout=5)
        if health.status_code == 200:
            st.success("✅ API Connected")
        else:
            st.error("❌ API Error")
    except requests.exceptions.RequestException:
        st.error("❌ API Offline - Start the server first")

# Sample queries
st.subheader("💡 Sample Queries")
sample_queries = [
    "What are the top 10 most common attack types?",
    "Show geographic distribution of attacks by source country",
    "What percentage of attacks are detected?",
    "How many attacks originated from China targeting USA?",
    "Which systems are most commonly affected?",
    "Show DDoS attacks grouped by country",
]

cols = st.columns(3)
for i, query in enumerate(sample_queries):
    with cols[i % 3]:
        if st.button(query[:40] + "..." if len(query) > 40 else query, key=f"sample_{i}"):
            st.session_state.query = query

# Query input
st.subheader("🔍 Enter Your Query")
query = st.text_area(
    "Natural language query:",
    value=st.session_state.get("query", ""),
    height=80,
    placeholder="e.g., What are the most common attack types?"
)

# Submit button
col1, col2 = st.columns([1, 5])
with col1:
    submit = st.button("🚀 Submit", type="primary", use_container_width=True)

# Process query
if submit and query:
    with st.spinner("Processing query..."):
        try:
            response = requests.post(
                f"{API_URL}/query",
                json={"query": query},
                headers=get_headers(),
                timeout=120
            )
            result = response.json()

            st.divider()

            if result.get("success"):
                # Success response
                st.subheader("✅ Results")

                # Show explanation
                if result.get("explanation"):
                    st.info(f"**Explanation:** {result['explanation']}")

                # Show data as table
                if result.get("data"):
                    df = pd.DataFrame(result["data"])
                    st.dataframe(df, use_container_width=True)

                    # Row count
                    st.caption(f"📊 {result.get('row_count', len(df))} rows returned")

                # Show SQL query
                with st.expander("🔧 Generated SQL Query"):
                    st.code(result.get("sql", "N/A"), language="sql")

            else:
                # Not available or error
                st.subheader("⚠️ Query Could Not Be Processed")

                if result.get("message") == "not available":
                    st.warning(f"**Reason:** {result.get('reason', 'Data not available')}")
                else:
                    st.error(f"**Error:** {result.get('error', 'Unknown error')}")

                    # Show SQL if generated
                    if result.get("sql"):
                        with st.expander("🔧 Generated SQL Query (Failed)"):
                            st.code(result.get("sql"), language="sql")

            # Raw JSON response
            with st.expander("📄 Raw JSON Response"):
                st.json(result)

        except requests.exceptions.ConnectionError:
            st.error("❌ Cannot connect to API. Make sure the server is running on http://localhost:8000")
        except requests.exceptions.Timeout:
            st.error("⏱️ Request timed out. The query may be too complex.")
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

elif submit and not query:
    st.warning("Please enter a query first.")

# Footer
st.divider()
st.caption("Built with FastAPI, PostgreSQL, Ollama, and Streamlit | CyberRAG © 2025")
