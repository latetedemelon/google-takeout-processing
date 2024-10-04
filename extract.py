import os
import hashlib
import sqlite3
import json
import shutil
import logging
import zipfile
import tarfile
from PIL import Image
from PIL.ExifTags import TAGS
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime

# Setup logging
logging.basicConfig(filename='photo_processing.log', level=logging.INFO)

# Define the database connection
conn = sqlite3.connect('photo_processing.db')
c = conn.cursor()

# Setup Google Photos API
SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']
creds = Credentials.from_authorized_user_file('token.json', SCOPES)
service = build('photoslibrary', 'v1', credentials=creds)

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

# Fetch photos from Google Photos
def fetch_google_photos_metadata(albums_map):
    photos_map = {}
    try:
        results = service.mediaItems().list(pageSize=100).execute()
        items = results.get('mediaItems', [])
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
            # Map the photo to its album
            for album_id in item.get('albumIds', []):
                if album_id in albums_map:
                    photo_data['albums'].append(albums_map[album_id])
            photos_map[item['id']] = photo_data
        logging.info(f"Fetched {len(photos_map)} Google Photos items.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {str(e)}")
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

# Step 2: Verify Takeout files using JSON files from the archive (Dry Run / Full Run)
def verify_takeout_files(source_dir, tmp_dir, dry_run=True):
    os.makedirs(tmp_dir, exist_ok=True)
    archive_files = [f for f in os.listdir(source_dir) if f.endswith(('.zip', '.tgz'))]

    for archive_file in archive_files:
        archive_path = os.path.join(source_dir, archive_file)
        if dry_run:
            extract_json_files_only(archive_path, tmp_dir)
        else:
            extract_full_archive(archive_path, tmp_dir)

# Extract only JSON files from an archive
def extract_json_files_only(archive_path, tmp_dir):
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    if file_info.filename.endswith('.json'):
                        zip_ref.extract(file_info, tmp_dir)
        elif archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                for tar_info in tar_ref.getmembers():
                    if tar_info.name.endswith('.json'):
                        tar_ref.extract(tar_info, tmp_dir)
        logging.info(f"Extracted JSON files from {archive_path}")
    except Exception as e:
        logging.error(f"Error extracting JSON files from {archive_path}: {str(e)}")

# Step 3: Build the database from the JSON files if necessary
def build_db_from_json(json_dir):
    json_files = [os.path.join(json_dir, f) for f in os.listdir(json_dir) if f.endswith('.json')]
    for json_file in json_files:
        with open(json_file, 'r') as f:
            json_data = json.load(f)
            process_json_data(json_data)

def process_json_data(json_data):
    try:
        original_filename = json_data['title']
        album_data = json_data.get('albums', [])
        albums = ', '.join(album['title'] for album in album_data)
        photo_taken_time = json_data['photoTakenTime']['timestamp']
        
        # Save to database
        c.execute("""
            INSERT OR REPLACE INTO FileList (file_name, albums, photo_taken_time)
            VALUES (?, ?, ?)
        """, (original_filename, albums, photo_taken_time))
        conn.commit()
    except KeyError as e:
        logging.error(f"KeyError processing JSON file: {str(e)}")

# Step 4: Deduplication - MD5 Hash and Check for Lower Resolution
def deduplicate_photos(photo_path):
    md5_hash = generate_hash(photo_path)
    if is_duplicate(md5_hash):
        logging.info(f"Duplicate photo found: {photo_path}")
        mark_as_duplicate(photo_path)
    else:
        check_for_lower_resolution(photo_path, md5_hash)

def generate_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def is_duplicate(md5_hash):
    c.execute("SELECT 1 FROM FileList WHERE md5_hash = ?", (md5_hash,))
    return c.fetchone() is not None

# Check for lower resolution duplicate
def check_for_lower_resolution(photo_path, md5_hash):
    dimensions = get_image_dimensions(photo_path)
    c.execute("SELECT file_name, width, height FROM FileList WHERE width >= ? AND height >= ?", dimensions)
    existing_photos = c.fetchall()
    if existing_photos:
        logging.info(f"Lower resolution duplicate found for {photo_path}")
        mark_as_duplicate(photo_path)
    else:
        logging.info(f"No lower resolution duplicate found, adding {photo_path} to database.")
        add_photo_to_db(photo_path, md5_hash, dimensions)

def get_image_dimensions(file_path):
    image = Image.open(file_path)
    return image.width, image.height

def mark_as_duplicate(photo_path):
    c.execute("UPDATE FileList SET status = 'duplicate' WHERE file_name = ?", (photo_path,))
    conn.commit()

def add_photo_to_db(photo_path, md5_hash, dimensions):
    width, height = dimensions
    c.execute("""
        INSERT INTO FileList (file_name, md5_hash, width, height, status)
        VALUES (?, ?, ?, ?, 'processed')
    """, (photo_path, md5_hash, width, height))
    conn.commit()

# Step 6: Move extracted files to designated year/month folders
def move_files_to_designated_location(photo_dir, destination_dir):
    for root, _, files in os.walk(photo_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                image = Image.open(file_path)
                exif_data = image._getexif()
                if exif_data and 36867 in exif_data:
                    date_taken = exif_data[36867]
                    date_obj = datetime.strptime(date_taken, "%Y:%m:%d %H:%M:%S")
                    year_dir = os.path.join(destination_dir, str(date_obj.year))
                    month_dir = os.path.join(year_dir, str(date_obj.month).zfill(2))
                    os.makedirs(month_dir, exist_ok=True)
                    shutil.move(file_path, os.path.join(month_dir, file))
            except Exception as e:
                logging.error(f"Error moving photo {file_path}: {str(e)}")

# Step 7: Repair EXIF data from JSON sidecar files
def repair_exif_data(photo_path, json_data):
    try:
        photo_taken_time = json_data['photoTakenTime']['timestamp']
        date_taken = datetime.utcfromtimestamp(int(photo_taken_time)).strftime('%Y:%m:%d %H:%M:%S')
        
        # Use pyexiv2 or other EXIF library to update EXIF data
        metadata = pyexiv2.ImageMetadata(photo_path)
        metadata.read()
        metadata['Exif.Photo.DateTimeOriginal'] = date_taken
        metadata.write()
        logging.info(f"EXIF data repaired for {photo_path}")
    except Exception as e:
        logging.error(f"Error repairing EXIF data for {photo_path}: {str(e)}")

# Main function
def main():
    logging.info('Script started...')
    
    source_dir = 'path_to_takeout_files'
    tmp_dir = 'path_to_tmp_directory'
    destination_dir = 'path_to_photos_directory'

    # Step 1: Create map/list of Google Photos
    create_google_photos_map()

    # Step 2: Verify Takeout files (Dry Run or Full Run)
    verify_takeout_files(source_dir, tmp_dir, dry_run=False)

    # Step 3: Build database from JSON files
    build_db_from_json(tmp_dir)

    # Step 4: Process and deduplicate photos
    move_files_to_designated_location(tmp_dir, destination_dir)

    close_db()
    logging.info('Script completed.')

if __name__ == "__main__":
    main()
