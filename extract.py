import os
import hashlib
import sqlite3
import json
import shutil
import logging
import zipfile
import tarfile
import pyexiv2
from PIL import Image
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime

# Setup logging
logging.basicConfig(filename='photo_processing.log', level=logging.INFO, format='%(asctime)s - %(levellevelname)s - %(message)s')

# Define the database connection
DATABASE_PATH = 'photo_processing.db'
BACKUP_DATABASE_PATH = 'photo_processing_backup.db'

# Create or connect to the database
conn = sqlite3.connect(DATABASE_PATH)
c = conn.cursor()

# Setup Google Photos API
SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']
creds = Credentials.from_authorized_user_file('token.json', SCOPES)
service = build('photoslibrary', 'v1', credentials=creds)

# Check if database exists and create tables if necessary
def initialize_database():
    try:
        with conn:
            c.execute("""
                CREATE TABLE IF NOT EXISTS PhotoList (
                    photo_id TEXT PRIMARY KEY,
                    filename TEXT,
                    creation_time TEXT,
                    mime_type TEXT,
                    width INTEGER,
                    height INTEGER,
                    albums TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS FileList (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT,
                    md5_hash TEXT,
                    width INTEGER,
                    height INTEGER,
                    status TEXT,
                    albums TEXT,
                    photo_taken_time TEXT
                )
            """)
        logging.info("Database initialized and tables created if they did not exist.")
    except Exception as e:
        logging.error(f"Error initializing the database: {str(e)}")
        print("Error: Could not initialize the database. Check logs for details.")
        exit(1)

# Backup the database before processing
def backup_database():
    try:
        if os.path.exists(DATABASE_PATH):
            shutil.copyfile(DATABASE_PATH, BACKUP_DATABASE_PATH)
            logging.info(f"Database backup created at {BACKUP_DATABASE_PATH}")
    except Exception as e:
        logging.error(f"Error creating database backup: {str(e)}")
        print("Error: Could not backup the database. Check logs for details.")

# Step 1: Create a map/list of photos from Google Photos
def create_google_photos_map():
    logging.info('Fetching Google Photos metadata...')
    albums_map = fetch_albums()
    photos_map = fetch_google_photos_metadata(albums_map)
    save_to_db(photos_map, albums_map)
    logging.info('Google Photos metadata saved.')

# Fetch albums from Google Photos
def fetch_albums():
    logging.info('Fetching Google Photos albums...')
    albums_map = {}
    try:
        albums_response = service.albums().list(pageSize=50).execute()
        for album in albums_response.get('albums', []):
            albums_map[album['id']] = album['title']
        logging.info(f"Fetched {len(albums_map)} albums.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos albums: {str(e)}")
    return albums_map

# Fetch photos from Google Photos in batches
def fetch_google_photos_metadata(albums_map):
    photos_map = {}
    next_page_token = None
    total_photos = 0
    try:
        while True:
            results = service.mediaItems().list(pageSize=100, pageToken=next_page_token).execute()
            items = results.get('mediaItems', [])
            total_photos += len(items)

            for item in items:
                photo_data = {
                    'id': item['id'],
                    'filename': item['filename'],
                    'creation_time': item['mediaMetadata']['creationTime'],
                    'mime_type': item['mimeType'],
                    'width': item['mediaMetadata'].get('width'),
                    'height': item['mediaMetadata'].get('height'),
                    'albums': []  # Albums will be filled later
                }
                for album_id in item.get('albumIds', []):
                    if album_id in albums_map:
                        photo_data['albums'].append(albums_map[album_id])
                photos_map[item['id']] = photo_data

            logging.info(f"Fetched {total_photos} Google Photos items so far.")
            next_page_token = results.get('nextPageToken')
            if not next_page_token:
                break

    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {str(e)}")
        exit(1)

    return photos_map

# Save the photo and album data to the SQLite database
def save_to_db(photos_map, albums_map):
    with conn:
        for photo_id, photo_data in photos_map.items():
            c.execute("""
                INSERT OR REPLACE INTO PhotoList (photo_id, filename, creation_time, mime_type, width, height, albums)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                photo_id, 
                photo_data['filename'], 
                photo_data['creation_time'], 
                photo_data['mime_type'], 
                photo_data['width'], 
                photo_data['height'], 
                ', '.join(photo_data['albums'])  # Join album titles
            ))
    conn.commit()

# Create directory safely with permission handling
def create_directory(path):
    try:
        if not os.path.exists(path):
            os.makedirs(path)
    except OSError as e:
        logging.error(f"Permission denied: Unable to create directory at {path}: {str(e)}")
        print(f"Error: Permission denied. Unable to create directory at {path}. Check permissions.")
        exit(1)

# Step 2: Verify Takeout files using JSON files from the archive (Dry Run / Full Run)
def verify_takeout_files(source_dir, tmp_dir, dry_run=True, batch_size=100):
    create_directory(tmp_dir)
    archive_files = [f for f in os.listdir(source_dir) if f.endswith(('.zip', '.tgz'))]

    if dry_run:
        logging.info("Running in dry-run mode. Only JSON files will be extracted.")
        print("Dry-run mode: Only JSON files will be extracted.")
    else:
        logging.info("Running full extraction mode.")
        print("Full extraction mode: Photos and JSON files will be processed.")

    for archive_file in archive_files:
        archive_path = os.path.join(source_dir, archive_file)
        if dry_run:
            extract_json_files_only(archive_path, tmp_dir)
        else:
            extract_full_archive_in_batches(archive_path, tmp_dir, batch_size)

# Extract only JSON files from an archive
def extract_json_files_only(archive_path, tmp_dir):
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                total_files = len(zip_ref.infolist())
                for index, file_info in enumerate(zip_ref.infolist()):
                    if file_info.filename.endswith('.json'):
                        zip_ref.extract(file_info, tmp_dir)
                        logging.info(f"Extracted {file_info.filename} ({index+1}/{total_files})")
                        print(f"Extracting {file_info.filename} ({index+1}/{total_files})...")
        elif archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                total_files = len(tar_ref.getmembers())
                for index, tar_info in enumerate(tar_ref.getmembers()):
                    if tar_info.name.endswith('.json'):
                        tar_ref.extract(tar_info, tmp_dir)
                        logging.info(f"Extracted {tar_info.name} ({index+1}/{total_files})")
                        print(f"Extracting {tar_info.name} ({index+1}/{total_files})...")
    except Exception as e:
        logging.error(f"Error extracting JSON files from {archive_path}: {str(e)}")

# Extract full archive in batches to avoid memory overload
def extract_full_archive_in_batches(archive_path, tmp_dir, batch_size=100):
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                total_files = len(zip_ref.infolist())
                batch = []
                for index, file_info in enumerate(zip_ref.infolist()):
                    zip_ref.extract(file_info, tmp_dir)
                    batch.append(file_info.filename)

                    # Process the batch if the size is reached
                    if len(batch) >= batch_size or (index + 1) == total_files:
                        process_batch(batch, tmp_dir)
                        clean_up_batch(batch, tmp_dir)
                        batch = []  # Reset the batch
                        logging.info(f"Batch {index // batch_size + 1} processed and cleaned.")

        elif archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                total_files = len(tar_ref.getmembers())
                batch = []
                for index, tar_info in enumerate(tar_ref.getmembers()):
                    tar_ref.extract(tar_info, tmp_dir)
                    batch.append(tar_info.name)

                    # Process the batch if the size is reached
                    if len(batch) >= batch_size or (index + 1) == total_files:
                        process_batch(batch, tmp_dir)
                        clean_up_batch(batch, tmp_dir)
                        batch = []  # Reset the batch
                        logging.info(f"Batch {index // batch_size + 1} processed and cleaned.")

    except Exception as e:
        logging.error(f"Error extracting full archive from {archive_path}: {str(e)}")

# Process batch (placeholder for actual processing logic)
def process_batch(batch, tmp_dir):
    logging.info(f"Processing files in batch: {batch}")
    # Placeholder for actual processing logic (deduplication, EXIF repair, etc.)
    for file in batch:
        file_path = os.path.join(tmp_dir, file)
        # Process the file (deduplicate, EXIF repair, etc.)
        logging.info(f"Processing file: {file_path}")

# Clean up the batch after processing
def clean_up_batch(batch, tmp_dir):
    for file in batch:
        file_path = os.path.join(tmp_dir, file)
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"Deleted file: {file_path}")

# Main function
def main():
    logging.info('Script started...')
    
    source_dir = 'path_to_takeout_files'
    tmp_dir = 'path_to_tmp_directory'
    destination_dir = 'path_to_photos_directory'

    initialize_database()
    backup_database()
    create_google_photos_map()
    verify_takeout_files(source_dir, tmp_dir, dry_run=False, batch_size=100)
    conn.close()

    logging.info('Script completed.')

if __name__ == "__main__":
    main()
