import os
import zipfile
import tarfile
import json
import logging
import sqlite3
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Setup logging
logging.basicConfig(filename='photo_migration.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Google Photos API setup
SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']
creds = Credentials.from_authorized_user_file('token.json', SCOPES)

# SQLite database setup
conn = sqlite3.connect('photo_matches.db')
cursor = conn.cursor()

# Create table if not exists
cursor.execute('''
CREATE TABLE IF NOT EXISTS photo_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_photo_id TEXT UNIQUE,
    google_photo_filename TEXT,
    google_creation_time TEXT,
    google_mime_type TEXT,
    takeout_filename TEXT,
    takeout_creation_time TEXT,
    takeout_mime_type TEXT,
    takeout_dimensions TEXT,
    status TEXT
)
''')
conn.commit()

# Fetch photos from Google Photos API
def fetch_google_photos_metadata(service):
    try:
        results = service.mediaItems().list(pageSize=100).execute()
        items = results.get('mediaItems', [])
        photos_metadata = []
        for item in items:
            photo_data = {
                'id': item['id'],
                'creation_time': item['mediaMetadata']['creationTime'],
                'filename': item['filename'],  # This is Google-assigned
                'mime_type': item['mimeType'],
                'dimensions': (item['mediaMetadata'].get('width'), item['mediaMetadata'].get('height'))
            }
            photos_metadata.append(photo_data)
        logging.info(f"Fetched {len(photos_metadata)} Google Photos metadata")
        return photos_metadata
    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {e}")
        return []

# Extract metadata from ZIP or TGZ archive
def extract_takeout_metadata(file_path):
    takeout_metadata = []
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                for zip_info in zip_ref.infolist():
                    if zip_info.filename.endswith('.json'):
                        with zip_ref.open(zip_info.filename) as f:
                            json_data = json.load(f)
                            takeout_metadata.append({
                                'original_filename': json_data.get('originalFilename'),
                                'creation_time': json_data['creationTime']['formatted'],
                                'mime_type': json_data.get('mimeType'),
                                'dimensions': (json_data.get('width'), json_data.get('height'))
                            })
        elif file_path.endswith('.tgz'):
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                for tar_info in tar_ref.getmembers():
                    if tar_info.name.endswith('.json'):
                        file = tar_ref.extractfile(tar_info)
                        if file:
                            json_data = json.load(file)
                            takeout_metadata.append({
                                'original_filename': json_data.get('originalFilename'),
                                'creation_time': json_data['creationTime']['formatted'],
                                'mime_type': json_data.get('mimeType'),
                                'dimensions': (json_data.get('width'), json_data.get('height'))
                            })
        logging.info(f"Extracted {len(takeout_metadata)} items from {file_path}")
        return takeout_metadata
    except Exception as e:
        logging.error(f"Error extracting metadata from {file_path}: {e}")
        return []

# Save match result to SQLite database
def save_match_to_db(google_photo, takeout_photo):
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO photo_matches (
                google_photo_id, google_photo_filename, google_creation_time,
                google_mime_type, takeout_filename, takeout_creation_time, 
                takeout_mime_type, takeout_dimensions, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            google_photo['id'],
            google_photo['filename'],
            google_photo['creation_time'],
            google_photo['mime_type'],
            takeout_photo['original_filename'],
            takeout_photo['creation_time'],
            takeout_photo['mime_type'],
            f"{takeout_photo['dimensions'][0]}x{takeout_photo['dimensions'][1]}" if takeout_photo['dimensions'] else None,
            'matched'
        ))
        conn.commit()
        logging.info(f"Matched and saved photo {google_photo['id']} to database")
    except sqlite3.Error as e:
        logging.error(f"Database error while saving match: {e}")

# Check if photo is already processed
def is_photo_processed(google_photo_id):
    cursor.execute('SELECT 1 FROM photo_matches WHERE google_photo_id = ?', (google_photo_id,))
    return cursor.fetchone() is not None

# Match Google Photos metadata with Takeout metadata
def match_photos(google_photos_metadata, takeout_metadata):
    matches = 0
    for google_photo in google_photos_metadata:
        if is_photo_processed(google_photo['id']):
            logging.info(f"Photo {google_photo['id']} already processed, skipping")
            continue

        for takeout_photo in takeout_metadata:
            if (google_photo['creation_time'] == takeout_photo['creation_time'] and 
                google_photo['mime_type'] == takeout_photo['mime_type']):
                if google_photo['dimensions'] == takeout_photo['dimensions']:
                    save_match_to_db(google_photo, takeout_photo)
                    matches += 1
                    break
    logging.info(f"Total matched photos: {matches}")

# Process all Takeout files in a directory
def process_takeout_directory(directory_path):
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.zip') or file.endswith('.tgz'):
                file_path = os.path.join(root, file)
                logging.info(f"Processing file: {file_path}")
                takeout_metadata = extract_takeout_metadata(file_path)
                google_photos_metadata = fetch_google_photos_metadata(service)
                match_photos(google_photos_metadata, takeout_metadata)

# Main function to drive the process
def main(takeout_directory):
    try:
        # Initialize Google Photos API service
        global service
        service = build('photoslibrary', 'v1', credentials=creds)
        
        # Process all Takeout files in the given directory
        process_takeout_directory(takeout_directory)
    except Exception as e:
        logging.error(f"An error occurred during the process: {e}")

if __name__ == '__main__':
    # Provide the directory containing Google Takeout files
    takeout_directory = '/path/to/your/TakeoutDirectory'
    main(takeout_directory)
