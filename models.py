"""
models.py — SQLite Database Models

This file handles all database operations for the SkyPass Guard project.
It creates the SQLite database, defines tables, and manages saving/retrieving password checks.

Key functions:
- init_db(): Create database and tables
- save_password_check(): Save a new password check
- get_all_checks(): Retrieve all password checks
- export_to_csv(): Export history to CSV file
"""

import sqlite3
from datetime import datetime
import csv
import os

# Database file name
DATABASE_FILE = 'database.db'


def get_db_connection():
    """
    Create a database connection.
    
    Returns:
        sqlite3.Connection: Database connection object
    """
    # Connect to SQLite database
    conn = sqlite3.connect(DATABASE_FILE)
    
    # Enable row factory for easier access
    conn.row_factory = sqlite3.Row
    
    return conn


def init_db():
    """
    Initialize the database and create tables.
    
    This function creates the password_checks table if it doesn't exist.
    The table stores:
    - id: Unique identifier
    - password_hash: Encrypted password (never store plain passwords!)
    - score: Strength score (0-100)
    - label: Strength label (Very Weak, Weak, Medium, Strong, Very Strong)
    - issues: JSON list of detected issues
    - suggestions: JSON list of improvement suggestions
    - created_at: Timestamp when check was saved
    """
    
    # Create database connection
    conn = get_db_connection()
    
    # Create password_checks table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS password_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL,
            score INTEGER NOT NULL,
            label TEXT NOT NULL,
            issues TEXT NOT NULL,
            suggestions TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Save changes and close connection
    conn.commit()
    conn.close()
    
    print("✅ Database initialized successfully")


def save_password_check(password_hash, score, label, issues, suggestions):
    """
    Save a password check to the database.
    
    Args:
        password_hash (str): Encrypted password (do NOT store plain passwords!)
        score (int): Strength score (0-100)
        label (str): Strength label
        issues (list): List of detected issues
        suggestions (list): List of improvement suggestions
    
    Returns:
        int: ID of the newly created record
    """
    
    # Create database connection
    conn = get_db_connection()
    
    # Convert lists to JSON strings
    issues_json = str(issues)
    suggestions_json = str(suggestions)
    
    # Insert new record
    cursor = conn.execute('''
        INSERT INTO password_checks (password_hash, score, label, issues, suggestions)
        VALUES (?, ?, ?, ?, ?)
    ''', (password_hash, score, label, issues_json, suggestions_json))
    
    # Get the ID of the new record
    record_id = cursor.lastrowid
    
    # Save changes and close connection
    conn.commit()
    conn.close()
    
    print(f"💾 Saved password check ID: {record_id}")
    
    return record_id


def get_all_checks():
    """
    Retrieve all password checks from the database.
    
    Returns:
        list: All password checks with id, password_hash, score, label, issues, suggestions, created_at
    """
    
    # Create database connection
    conn = get_db_connection()
    
    # Query all records
    checks = conn.execute('''
        SELECT id, password_hash, score, label, issues, suggestions, created_at
        FROM password_checks
        ORDER BY created_at DESC
    ''').fetchall()
    
    # Close connection
    conn.close()
    
    # Convert to list of dictionaries
    result = []
    for check in checks:
        result.append({
            'id': check['id'],
            'password_hash': check['password_hash'],  # Encrypted (don't decrypt in API)
            'score': check['score'],
            'label': check['label'],
            'issues': check['issues'],
            'suggestions': check['suggestions'],
            'created_at': check['created_at']
        })
    
    return result


def export_to_csv():
    """
    Export all password checks to a CSV file.
    
    Creates a CSV file with all password check history including:
    - Timestamp
    - Score
    - Label
    - Issues
    - Suggestions
    
    Note:
        - Does NOT include password_hash (encrypted passwords stay encrypted)
        - Only exports metadata for security
    
    Returns:
        str: Path to the created CSV file
    """
    
    # Get all checks from database
    checks = get_all_checks()
    
    # CSV file name
    csv_filename = 'password_history.csv'
    
    # Write to CSV file
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        # Create CSV writer
        writer = csv.writer(csvfile)
        
        # Write header row
        writer.writerow(['ID', 'Timestamp', 'Score', 'Label', 'Issues', 'Suggestions'])
        
        # Write data rows
        for check in checks:
            writer.writerow([
                check['id'],
                check['created_at'],
                check['score'],
                check['label'],
                check['issues'],
                check['suggestions']
            ])
    
    print(f"📄 Exported {len(checks)} checks to {csv_filename}")
    
    return csv_filename
