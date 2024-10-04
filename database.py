import sqlite3
import logging
import os
import time
from datetime import datetime
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database connection
def get_db_connection(db_path):
    try:
        conn = sqlite3.connect(db_path)
        logging.info(f"Connected to database at {db_path}")
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection failed: {e}")
        raise

# Database initialization with backup
def initialize_database(conn):
    try:
        c = conn.cursor()

        # Check if the database is initialized (you can adjust the logic here if needed)
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='PhotoList';")
        if not c.fetchone():
            logging.info("Database not initialized. Initializing now.")
            c.execute("""
                CREATE TABLE IF NOT EXISTS PhotoList (
                    photo_id TEXT PRIMARY KEY,
                    filename TEXT,
                    creation_time TEXT,
                    mime_type TEXT,
                    width INTEGER,
                    height INTEGER,
                    albums TEXT
                );
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS FileList (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT,
                    md5_hash TEXT,
                    size INTEGER,
                    width INTEGER,
                    height INTEGER,
                    status TEXT,
                    albums TEXT,
                    photo_taken_time TEXT
                );
            """)
            # Add indexes for optimization
            c.execute("CREATE INDEX IF NOT EXISTS idx_filelist_md5 ON FileList(md5_hash);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_photolist_time ON PhotoList(creation_time);")
            c.execute("""
                CREATE TABLE IF NOT EXISTS ArchiveProcessing (
                    archive_name TEXT PRIMARY KEY,
                    status TEXT
                );
            """)
            logging.info("Database initialized successfully.")
        else:
            logging.info("Database already initialized.")

    except sqlite3.Error as e:
        logging.error(f"Error initializing database: {e}")
        raise

# Backup the database with timestamp
def backup_database(db_path):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{db_path}_{timestamp}.bak"
        shutil.copy(db_path, backup_filename)
        logging.info(f"Database backup created at {backup_filename}")
    except Exception as e:
        logging.error(f"Failed to backup database: {e}")
        raise

# Close the database connection
def close_db_connection(conn):
    try:
        if conn:
            conn.close()
            logging.info("Database connection closed.")
    except sqlite3.Error as e:
        logging.error(f"Error closing the database connection: {e}")
        raise
