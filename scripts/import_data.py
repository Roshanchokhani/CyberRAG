"""
Data Import Script for CyberRAG

This script:
1. Creates the PostgreSQL database and table
2. Reads the CSV data
3. Generates random timestamps (since the CSV timestamps are empty)
4. Imports all data into the database
"""

import pandas as pd
import psycopg2
from psycopg2.extras import execute_values
import random
import re
from datetime import datetime, timedelta
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration (must be set via .env — no hardcoded default)
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable is not set.")
    print("Set it in .env file: DATABASE_URL=postgresql://user:password@host:port/database")
    sys.exit(1)

# Parse database URL
def parse_db_url(url: str) -> dict:
    """Parse PostgreSQL connection URL into components."""
    # postgresql://user:password@host:port/database
    url = url.replace("postgresql://", "")

    # Split user:password@host:port/database
    auth_host, database = url.rsplit("/", 1)
    auth, host_port = auth_host.rsplit("@", 1)
    user, password = auth.split(":", 1)
    host, port = host_port.split(":", 1)

    return {
        "user": user,
        "password": password,
        "host": host,
        "port": int(port),
        "database": database
    }


def generate_random_timestamp(year: int = None) -> datetime:
    """Generate a random timestamp within a year range."""
    if year is None:
        year = random.randint(2020, 2025)

    month = random.randint(1, 12)
    day = random.randint(1, 28)  # Safe for all months
    hour = random.randint(0, 23)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)

    return datetime(year, month, day, hour, minute, second)


def create_database_if_not_exists(db_config: dict):
    """Create the database if it doesn't exist."""
    # Connect to default postgres database
    conn = psycopg2.connect(
        host=db_config["host"],
        port=db_config["port"],
        user=db_config["user"],
        password=db_config["password"],
        database="postgres"
    )
    conn.autocommit = True
    cursor = conn.cursor()

    # Check if database exists
    cursor.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s",
        (db_config["database"],)
    )

    if not cursor.fetchone():
        db_name = db_config['database']
        # Validate database name to prevent SQL injection (alphanumeric and underscores only)
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', db_name):
            raise ValueError(f"Invalid database name: {db_name}")
        print(f"Creating database: {db_name}")
        cursor.execute(f"CREATE DATABASE {db_name}")
        print("Database created successfully")
    else:
        print(f"Database '{db_config['database']}' already exists")

    cursor.close()
    conn.close()


def create_table(conn):
    """Create the cyber_attacks table."""
    cursor = conn.cursor()

    # Drop existing table (for clean import)
    cursor.execute("DROP TABLE IF EXISTS cyber_attacks CASCADE")

    # Create table
    create_sql = """
    CREATE TABLE cyber_attacks (
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
    """
    cursor.execute(create_sql)

    # Create indexes
    indexes = [
        "CREATE INDEX idx_attack_type ON cyber_attacks(attack_type)",
        "CREATE INDEX idx_source_country ON cyber_attacks(source_country)",
        "CREATE INDEX idx_destination_country ON cyber_attacks(destination_country)",
        "CREATE INDEX idx_detection_label ON cyber_attacks(detection_label)",
        "CREATE INDEX idx_timestamp ON cyber_attacks(timestamp)",
        "CREATE INDEX idx_affected_system ON cyber_attacks(affected_system)",
        "CREATE INDEX idx_protocol ON cyber_attacks(protocol)",
    ]

    for idx_sql in indexes:
        cursor.execute(idx_sql)

    conn.commit()
    cursor.close()
    print("Table and indexes created successfully")


def import_csv_data(conn, csv_path: str):
    """Import CSV data into the database."""
    print(f"Reading CSV file: {csv_path}")

    # Read CSV
    df = pd.read_csv(csv_path)

    # Fix column names (handle the 'yeAttack ID' typo)
    df.columns = [
        'attack_id', 'source_ip', 'destination_ip', 'source_country',
        'destination_country', 'protocol', 'source_port', 'destination_port',
        'attack_type', 'payload_size', 'detection_label', 'confidence_score',
        'ml_model', 'affected_system', 'port_type', 'timestamp'
    ]

    print(f"Total records to import: {len(df)}")

    # Validate CSV structure
    expected_columns = 16
    if len(df.columns) != expected_columns:
        raise ValueError(f"CSV has {len(df.columns)} columns, expected {expected_columns}")

    # Validate and sanitize data
    print("Validating and cleaning data...")

    # Validate IP addresses (basic format check)
    import re
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    for col in ['source_ip', 'destination_ip']:
        invalid_ips = df[col].dropna().apply(lambda x: not bool(ip_pattern.match(str(x))))
        invalid_count = invalid_ips.sum()
        if invalid_count > 0:
            print(f"  Warning: {invalid_count} invalid IPs in {col} (will be set to empty)")
            df.loc[df[col].apply(lambda x: not bool(ip_pattern.match(str(x))) if pd.notna(x) else True), col] = ''

    # Validate numeric ranges
    df['source_port'] = df['source_port'].clip(0, 65535)
    df['destination_port'] = df['destination_port'].clip(0, 65535)
    df['payload_size'] = df['payload_size'].clip(0, None)

    # Truncate string fields to max column lengths to prevent overflow
    string_length_limits = {
        'source_ip': 45, 'destination_ip': 45, 'source_country': 100,
        'destination_country': 100, 'protocol': 20, 'attack_type': 100,
        'detection_label': 50, 'ml_model': 100, 'affected_system': 100,
        'port_type': 50,
    }
    for col, max_len in string_length_limits.items():
        if col in df.columns:
            df[col] = df[col].astype(str).str[:max_len]

    # Clean data - handle NaN values
    print("Cleaning data...")
    # Fill NaN in integer columns with 0 or appropriate defaults
    df['source_port'] = df['source_port'].fillna(0).astype(int)
    df['destination_port'] = df['destination_port'].fillna(0).astype(int)
    df['payload_size'] = df['payload_size'].fillna(0).astype(int)
    df['attack_id'] = df['attack_id'].fillna(0).astype(int)

    # Fill NaN in string columns with empty string
    string_cols = ['source_ip', 'destination_ip', 'source_country', 'destination_country',
                   'protocol', 'attack_type', 'detection_label', 'ml_model',
                   'affected_system', 'port_type']
    for col in string_cols:
        df[col] = df[col].fillna('')

    # Fill NaN in confidence_score with 0
    df['confidence_score'] = df['confidence_score'].fillna(0.0)

    # Generate random timestamps (since original timestamps are empty)
    print("Generating random timestamps...")
    df['timestamp'] = [generate_random_timestamp() for _ in range(len(df))]

    # Prepare data for insertion
    columns = [
        'attack_id', 'source_ip', 'destination_ip', 'source_country',
        'destination_country', 'protocol', 'source_port', 'destination_port',
        'attack_type', 'payload_size', 'detection_label', 'confidence_score',
        'ml_model', 'affected_system', 'port_type', 'timestamp'
    ]

    # Convert DataFrame to list of tuples
    data = df[columns].values.tolist()

    # Insert data in batches
    cursor = conn.cursor()
    batch_size = 5000
    total_batches = (len(data) + batch_size - 1) // batch_size

    insert_sql = f"""
        INSERT INTO cyber_attacks
        ({', '.join(columns)})
        VALUES %s
    """

    print(f"Importing data in {total_batches} batches...")

    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        execute_values(cursor, insert_sql, batch)
        conn.commit()
        batch_num = (i // batch_size) + 1
        print(f"  Batch {batch_num}/{total_batches} imported ({len(batch)} records)")

    cursor.close()
    print(f"\nSuccessfully imported {len(data)} records")


def verify_import(conn):
    """Verify the data import with some sample queries."""
    cursor = conn.cursor()

    print("\n--- Import Verification ---")

    # Total count
    cursor.execute("SELECT COUNT(*) FROM cyber_attacks")
    count = cursor.fetchone()[0]
    print(f"Total records: {count}")

    # Attack types
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count
        FROM cyber_attacks
        GROUP BY attack_type
        ORDER BY count DESC
        LIMIT 5
    """)
    print("\nTop 5 Attack Types:")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    # Countries
    cursor.execute("""
        SELECT source_country, COUNT(*) as count
        FROM cyber_attacks
        GROUP BY source_country
        ORDER BY count DESC
        LIMIT 5
    """)
    print("\nTop 5 Source Countries:")
    for row in cursor.fetchall():
        print(f"  {row[0]}: {row[1]}")

    # Timestamp range
    cursor.execute("""
        SELECT MIN(timestamp), MAX(timestamp)
        FROM cyber_attacks
    """)
    min_ts, max_ts = cursor.fetchone()
    print(f"\nTimestamp range: {min_ts} to {max_ts}")

    cursor.close()


def main():
    """Main function to run the import process."""
    print("=" * 60)
    print("CyberRAG Data Import Script")
    print("=" * 60)

    # Parse database URL
    db_config = parse_db_url(DATABASE_URL)
    print(f"\nDatabase: {db_config['database']} @ {db_config['host']}:{db_config['port']}")

    # CSV file path
    csv_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "cyberattacks.csv"
    )

    if not os.path.exists(csv_path):
        print(f"ERROR: CSV file not found at {csv_path}")
        sys.exit(1)

    try:
        # Step 1: Create database if not exists
        print("\n[Step 1] Checking database...")
        create_database_if_not_exists(db_config)

        # Step 2: Connect to the database
        print("\n[Step 2] Connecting to database...")
        conn = psycopg2.connect(
            host=db_config["host"],
            port=db_config["port"],
            user=db_config["user"],
            password=db_config["password"],
            database=db_config["database"]
        )
        print("Connected successfully")

        # Step 3: Create table
        print("\n[Step 3] Creating table and indexes...")
        create_table(conn)

        # Step 4: Import data
        print("\n[Step 4] Importing CSV data...")
        import_csv_data(conn, csv_path)

        # Step 5: Verify import
        print("\n[Step 5] Verifying import...")
        verify_import(conn)

        conn.close()

        print("\n" + "=" * 60)
        print("Data import completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\nERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
