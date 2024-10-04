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
import concurrent.futures
import time
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError

# Setup logging
logging.basicConfig(filename='photo_processing.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

# Database initialization with indexes
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
                    size INTEGER,
                    width INTEGER,
                    height INTEGER,
                    status TEXT,
                    albums TEXT,
                    photo_taken_time TEXT
                )
            """)
            # Add indexes for performance optimization
            c.execute("CREATE INDEX IF NOT EXISTS idx_filelist_md5 ON FileList(md5_hash)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_photolist_photo_id ON PhotoList(photo_id)")
            c.execute("""
                CREATE TABLE IF NOT EXISTS ArchiveProcessing (
                    archive_name TEXT PRIMARY KEY,
                    status TEXT
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

# Retry mechanism for transient errors (e.g., API or DB operations)
def retry_operation(operation, retries=3, delay=2, *args, **kwargs):
    for attempt in range(retries):
        try:
            return operation(*args, **kwargs)
        except (HttpError, Exception) as e:
            if attempt < retries - 1:
                logging.warning(f"Retrying operation after error: {str(e)}")
                time.sleep(delay)
            else:
                logging.error(f"Operation failed after {retries} attempts: {str(e)}")
                return None

# Google Photos API error handler (rate-limiting, OAuth re-auth)
def handle_google_photos_api_errors(func):
    def wrapper(*args, **kwargs):
        retries = 3
        delay = 2
        for attempt in range(retries):
            try:
                return func(*args, **kwargs)
            except RefreshError:
                logging.error("OAuth token expired or invalid. Please refresh credentials.")
                print("Error: OAuth token expired or invalid. Reauthenticate using 'token.json'.")
                exit(1)
            except HttpError as e:
                if e.resp.status == 429:  # Too many requests (rate limiting)
                    logging.warning("Rate limit exceeded, retrying after delay...")
                    time.sleep(delay * (attempt + 1))
                else:
                    logging.error(f"Google Photos API error: {str(e)}")
                    if attempt < retries - 1:
                        time.sleep(delay)
                    else:
                        print(f"Error: Google Photos API error: {str(e)}")
                        exit(1)
    return wrapper

# Fetch Google Photos metadata
@handle_google_photos_api_errors
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
            for album_id in item.get('albumIds', []):
                if album_id in albums_map:
                    photo_data['albums'].append(albums_map[album_id])
            photos_map[item['id']] = photo_data
        logging.info(f"Fetched {len(photos_map)} Google Photos items.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {str(e)}")
    return photos_map

# Parallel extraction of archives
def extract_archives_in_parallel(archives, tmp_dir, batch_size=100):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(extract_full_archive_in_batches, archive, tmp_dir, batch_size) for archive in archives]
        for future in concurrent.futures.as_completed(futures):
            archive_name = future.result()
            if archive_name:
                logging.info(f"Archive {archive_name} processed.")
            else:
                logging.error(f"Error processing archive {archive_name}.")

# Deduplicate photos by MD5 hash and check for lower resolution
def deduplicate_photos(photo_path):
    md5_hash = generate_hash(photo_path)
    size = os.path.getsize(photo_path)
    if is_duplicate(md5_hash, size):
        logging.info(f"Duplicate photo skipped: {photo_path}")
        mark_as_duplicate(photo_path)
        return True
    else:
        check_for_lower_resolution(photo_path, md5_hash, size)
        return False

# Generate MD5 hash
def generate_hash(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error generating MD5 hash for {file_path}: {str(e)}")
        return None

def is_duplicate(md5_hash, size):
    return retry_operation(lambda: c.execute("SELECT 1 FROM FileList WHERE md5_hash = ? AND size = ?", (md5_hash, size)).fetchone()) is not None

# Add photo to database after processing
def add_photo_to_db(photo_path, md5_hash, dimensions, size):
    width, height = dimensions
    retry_operation(lambda: c.execute("""
        INSERT INTO FileList (file_name, md5_hash, size, width, height, status)
        VALUES (?, ?, ?, ?, ?, 'processed')
    """, (photo_path, md5_hash, size, width, height)))
    conn.commit()

# Repair EXIF data from the Google sidecar JSON
def repair_exif_data(photo_path, json_data):
    try:
        metadata = pyexiv2.ImageMetadata(photo_path)
        metadata.read()

        # Repair timestamp
        photo_taken_time = json_data.get('photoTakenTime', {}).get('timestamp')
        if photo_taken_time:
            date_taken = datetime.utcfromtimestamp(int(photo_taken_time)).strftime('%Y:%m:%d %H:%M:%S')
            metadata['Exif.Photo.DateTimeOriginal'] = date_taken
            logging.info(f"Timestamp repaired for {photo_path}: {date_taken}")

        # Repair GPS (location) data
        geo_data = json_data.get('geoData', {})
        geo_data_exif = json_data.get('geoDataExif', {})

        latitude = geo_data_exif.get('latitude') or geo_data.get('latitude')
        longitude = geo_data_exif.get('longitude') or geo_data.get('longitude')
        altitude = geo_data_exif.get('altitude') or geo_data.get('altitude', 0)

        if latitude and longitude:
            lat_deg = convert_to_degrees(abs(latitude))
            lon_deg = convert_to_degrees(abs(longitude))

            metadata['Exif.GPSInfo.GPSLatitude'] = lat_deg
            metadata['Exif.GPSInfo.GPSLatitudeRef'] = 'N' if latitude >= 0 else 'S'
            metadata['Exif.GPSInfo.GPSLongitude'] = lon_deg
            metadata['Exif.GPSInfo.GPSLongitudeRef'] = 'E' if longitude >= 0 else 'W'

            logging.info(f"Location repaired for {photo_path}: ({latitude}, {longitude})")

        if altitude:
            metadata['Exif.GPSInfo.GPSAltitude'] = convert_to_rational(altitude)
            metadata['Exif.GPSInfo.GPSAltitudeRef'] = '0'  # '0' indicates altitude above sea level

            logging.info(f"Altitude repaired for {photo_path}: {altitude} meters")

        # Repair description/caption if available
        description = json_data.get('description')
        if description:
            metadata['Exif.Image.ImageDescription'] = description
            logging.info(f"Description repaired for {photo_path}: {description}")

        metadata.write()

    except Exception as e:
        logging.error(f"Error repairing EXIF data for {photo_path}: {str(e)}")

# Step 6: Move files to designated folders based on EXIF data
def move_file_based_on_exif(photo_path, destination_dir):
    try:
        image = Image.open(photo_path)
        exif_data = image._getexif()
        if exif_data and 36867 in exif_data:
            date_taken = exif_data[36867]
            date_obj = datetime.strptime(date_taken, "%Y:%m:%d %H:%M:%S")
        else:
            date_obj = datetime.fromtimestamp(os.path.getmtime(photo_path))  # Fallback to modification time

        year_dir = os.path.join(destination_dir, str(date_obj.year))
        month_dir = os.path.join(year_dir, str(date_obj.month).zfill(2))

        create_directory(month_dir)
        shutil.move(photo_path, os.path.join(month_dir, os.path.basename(photo_path)))

    except Exception as e:
        logging.error(f"Error moving file {photo_path}: {str(e)}")

# Main function
def main():
    logging.info('Script started...')
    
    source_dir = 'path_to_takeout_files'
    tmp_dir = 'path_to_tmp_directory'
    global destination_dir
    destination_dir = 'path_to_photos_directory'

    initialize_database()
    backup_database()

    # Step 3: Process the takeout archives in parallel batches
    archives = [f for f in os.listdir(source_dir) if f.endswith(('.zip', '.tgz'))]
    extract_archives_in_parallel(archives, tmp_dir, batch_size=100)

    conn.close()
    logging.info('Script completed.')

if __name__ == "__main__":
    main()
