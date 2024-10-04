import json
import re
import os
import hashlib
import shutil
import sqlite3
import logging
from PIL import Image
from PIL.ExifTags import TAGS
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime
import zipfile
import tarfile

# Setup logging
logging.basicConfig(filename='photo_processing.log', level=logging.INFO)

# Define the database connection
conn = sqlite3.connect('photo_processing.db')
c = conn.cursor()

# Setup Google Photos API
SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']
creds = Credentials.from_authorized_user_file('token.json', SCOPES)
service = build('photoslibrary', 'v1', credentials=creds)

def close_db():
    conn.close()

# Create required tables in the database
def create_tables():
    with conn:
        c.execute("""
            CREATE TABLE IF NOT EXISTS ZipProcessing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                zip_file TEXT,
                status TEXT,
                error_message TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS FileProcessing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT,
                status TEXT,
                error_message TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS FileList (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT,
                google_photo_id TEXT,
                google_creation_time TEXT,
                google_mime_type TEXT,
                status TEXT,
                size INTEGER,
                md5_hash TEXT,
                dimensions TEXT,
                album TEXT
            )
        """)

# Fetch metadata from Google Photos using the API
def fetch_google_photos_metadata():
    try:
        results = service.mediaItems().list(pageSize=100).execute()
        items = results.get('mediaItems', [])
        photos_metadata = []
        for item in items:
            photo_data = {
                'id': item['id'],
                'filename': item['filename'],
                'creation_time': item['mediaMetadata']['creationTime'],
                'mime_type': item['mimeType'],
                'width': item['mediaMetadata'].get('width'),
                'height': item['mediaMetadata'].get('height')
            }
            photos_metadata.append(photo_data)
        logging.info(f"Fetched {len(photos_metadata)} Google Photos metadata items")
        return photos_metadata
    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {str(e)}")
        return []

# Handle zip and tgz archives
def handle_archives(source_dir, tmp_dir):
    os.makedirs(tmp_dir, exist_ok=True)
    archive_files = [f for f in os.listdir(source_dir) if f.endswith(('.zip', '.tgz'))]

    for archive_file in archive_files:
        archive_path = os.path.join(source_dir, archive_file)
        if not is_archive_processed(archive_path):
            extract_archive(archive_path, tmp_dir)
        else:
            logging.info(f'Skipping {archive_path}, already processed.')

def is_archive_processed(archive_path):
    with conn:
        c.execute("SELECT status FROM ZipProcessing WHERE zip_file = ? AND status = 'Success'", (archive_path,))
        return c.fetchone() is not None

# Extract zip and tgz archives
def extract_archive(archive_path, extract_to):
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(extract_to)

        for file in os.listdir(extract_to):
            file_path = os.path.join(extract_to, file)
            size = os.path.getsize(file_path)
            md5_hash = generate_hash(file_path)
            with conn:
                c.execute("""
                    INSERT INTO FileList (file_name, status, size, md5_hash)
                    VALUES (?, ?, ?, ?)
                """, (file, 'extracted', size, md5_hash))
        status = 'Success'
        error_message = ''
    except Exception as e:
        status = 'Failed'
        error_message = str(e)
        logging.error(f'Failed to unpack {archive_path}: {error_message}')
    finally:
        with conn:
            c.execute("""
                INSERT INTO ZipProcessing (zip_file, status, error_message)
                VALUES (?, ?, ?)
            """, (archive_path, status, error_message))

# Generate MD5 hash for a file
def generate_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# Deduplication logic: Based on MD5, dimensions, and quality
def deduplicate_files(dest_dir):
    files_list = fetch_centralized_files()
    google_photos_metadata = fetch_google_photos_metadata()

    seen_hashes = {}
    for file in files_list:
        file_path = os.path.join(dest_dir, file)
        size = os.path.getsize(file_path)
        md5_hash = generate_hash(file_path)
        dimensions = get_image_dimensions(file_path)

        # Check against Google Photos metadata
        google_match = check_against_google_photos(md5_hash, dimensions, google_photos_metadata)

        if google_match:
            logging.info(f'Matched with Google Photos: {file_path} matches {google_match["id"]}')
            save_google_metadata_to_db(file, google_match)

        # Local deduplication logic based on MD5 and size/dimensions
        if md5_hash in seen_hashes:
            logging.info(f'Duplicate found: {file_path}')
            compare_quality(file_path, seen_hashes[md5_hash])  # Keep higher quality
        else:
            seen_hashes[md5_hash] = file_path

# Compare quality and keep the higher quality version
def compare_quality(file1, file2):
    size1 = os.path.getsize(file1)
    size2 = os.path.getsize(file2)
    dims1 = get_image_dimensions(file1)
    dims2 = get_image_dimensions(file2)

    if size1 >= size2 and dims1 >= dims2:
        os.remove(file2)
        update_file_status(file2, 'deleted')
    else:
        os.remove(file1)
        update_file_status(file1, 'deleted')

# Check against Google Photos metadata for matching photos
def check_against_google_photos(md5_hash, dimensions, google_photos_metadata):
    for photo in google_photos_metadata:
        if f"{photo['width']}x{photo['height']}" == dimensions:
            return photo
    return None

# Save Google Photos metadata to the local database
def save_google_metadata_to_db(file_name, google_photo):
    with conn:
        c.execute("""
            UPDATE FileList SET google_photo_id = ?, google_creation_time = ?, google_mime_type = ?
            WHERE file_name = ?
        """, (google_photo['id'], google_photo['creation_time'], google_photo['mime_type'], file_name))

# Centralize extracted files
def centralize_files(src_dir, dest_dir):
    status = 'Failed'
    try:
        files_list = os.listdir(src_dir)
        for file in files_list:
            shutil.move(os.path.join(src_dir, file), os.path.join(dest_dir, file))
            update_file_status(file, 'centralized')
        error_message = ''
    except Exception as e:
        status = 'Failed'
        error_message = str(e)
        logging.error(f'Failed to centralize files: {error_message}')

def fetch_centralized_files():
    with conn:
        c.execute("SELECT file_name FROM FileList WHERE status = 'centralized'")
        return [row[0] for row in c.fetchall()]

# Extract image dimensions from EXIF data
def get_image_dimensions(file_path):
    try:
        image = Image.open(file_path)
        return f"{image.width}x{image.height}"
    except Exception as e:
        logging.error(f"Error getting dimensions for {file_path}: {str(e)}")
        return None

# Reorganize photos by EXIF `DateTimeOriginal`
def sort_photos_by_date(dest_dir):
    for root, _, files in os.walk(dest_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                image = Image.open(file_path)
                exif_data = image._getexif()
                if exif_data and 36867 in exif_data:  # DateTimeOriginal tag
                    date_taken = exif_data[36867]
                    date_obj = datetime.strptime(date_taken, "%Y:%m:%d %H:%M:%S")
                    year_dir = os.path.join(dest_dir, str(date_obj.year))
                    month_dir = os.path.join(year_dir, str(date_obj.month).zfill(2))
                    os.makedirs(month_dir, exist_ok=True)
                    shutil.move(file_path, os.path.join(month_dir, file))
            except Exception as e:
                logging.error(f"Error sorting photo {file_path}: {str(e)}")

# Process JSON sidecar files for album information
def extract_album_info_from_json(json_file_path):
    try:
        with open(json_file_path, 'r') as f:
            json_data = json.load(f)
            if 'albums' in json_data:
                album_titles = ', '.join([album['title'] for album in json_data['albums']])
                file_name = json_data.get('originalFilename', '')
                if file_name:
                    save_album_info(file_name, album_titles)
    except Exception as e:
        logging.error(f"Error processing album information from {json_file_path}: {str(e)}")

# Save album information in the database
def save_album_info(file_name, album_info):
    with conn:
        c.execute("""
            UPDATE FileList SET album = ? WHERE file_name = ?
        """, (album_info, file_name))

# Update the status of files in the database
def update_file_status(file_name, status):
    with conn:
        c.execute("""
            UPDATE FileList SET status = ? WHERE file_name = ?
        """, (status, file_name))

# Main function to execute the script
def main():
    logging.info('Script started...')
    source_dir = 'path_to_source'
    destination_dir = 'path_to_destination'
    tmp_dir = os.path.join(destination_dir, 'tmp')

    create_tables()
    handle_archives(source_dir, tmp_dir)
    centralize_files(tmp_dir, destination_dir)
    deduplicate_files(destination_dir)
    sort_photos_by_date(destination_dir)

    close_db()
    logging.info('Script completed.')

if __name__ == "__main__":
    main()
