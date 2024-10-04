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

# Setup logging with more granular levels
logging.basicConfig(
    filename='photo_processing.log',
    level=logging.DEBUG,  # Changed to DEBUG for more granular logging
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define paths in environment variables or config
DATABASE_PATH = os.getenv('DATABASE_PATH', 'photo_processing.db')
BACKUP_DATABASE_PATH = os.getenv('BACKUP_DATABASE_PATH', 'photo_processing_backup.db')
TOKEN_PATH = os.getenv('TOKEN_PATH', 'token.json')

# Create or connect to the database
def get_db_connection(db_path):
    try:
        conn = sqlite3.connect(db_path)
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection failed: {e}")
        raise

conn = get_db_connection(DATABASE_PATH)
c = conn.cursor()

# Setup Google Photos API
SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']

def get_google_service(token_path):
    try:
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        service = build('photoslibrary', 'v1', credentials=creds)
        return service
    except RefreshError as e:
        logging.error("Failed to refresh Google API token. Please check token.json.")
        raise
    except Exception as e:
        logging.error(f"Error setting up Google Photos API service: {e}")
        raise

service = get_google_service(TOKEN_PATH)

# Retry mechanism for operations
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

# Handle Google API errors and rate-limiting
def handle_google_photos_api_errors(func):
    def wrapper(*args, **kwargs):
        retries = 3
        delay = 2
        for attempt in range(retries):
            try:
                return func(*args, **kwargs)
            except RefreshError:
                logging.error("OAuth token expired or invalid. Please refresh credentials.")
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
                        exit(1)
    return wrapper

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
            c.execute("CREATE INDEX IF NOT EXISTS idx_photolist_time ON PhotoList(creation_time)")
            c.execute("""
                CREATE TABLE IF NOT EXISTS ArchiveProcessing (
                    archive_name TEXT PRIMARY KEY,
                    status TEXT
                )
            """)
            logging.info("Database initialized and tables created.")
    except sqlite3.Error as e:
        logging.error(f"Error initializing database: {e}")
        raise

initialize_database()

# Function to back up the database
def backup_database():
    try:
        shutil.copy(DATABASE_PATH, BACKUP_DATABASE_PATH)
        logging.info("Database backup completed.")
    except Exception as e:
        logging.error(f"Error backing up the database: {e}")
        raise

# Handle Google API errors and rate-limiting
def handle_google_photos_api_errors(func):
    def wrapper(*args, **kwargs):
        retries = 3
        delay = 2
        for attempt in range(retries):
            try:
                return func(*args, **kwargs)
            except RefreshError:
                logging.error("OAuth token expired or invalid. Please refresh credentials.")
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
                        exit(1)
    return wrapper

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
            c.execute("CREATE INDEX IF NOT EXISTS idx_photolist_time ON PhotoList(creation_time)")
            c.execute("""
                CREATE TABLE IF NOT EXISTS ArchiveProcessing (
                    archive_name TEXT PRIMARY KEY,
                    status TEXT
                )
            """)
            logging.info("Database initialized and tables created.")
    except sqlite3.Error as e:
        logging.error(f"Error initializing database: {e}")
        raise

initialize_database()

# Function to back up the database
def backup_database():
    try:
        shutil.copy(DATABASE_PATH, BACKUP_DATABASE_PATH)
        logging.info("Database backup completed.")
    except Exception as e:
        logging.error(f"Error backing up the database: {e}")
        raise


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

# Process an individual archive
def extract_full_archive_in_batches(archive_path, tmp_dir, batch_size):
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    zip_ref.extract(file_info, tmp_dir)
                    process_file(os.path.join(tmp_dir, file_info.filename))
        elif archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                for tar_info in tar_ref.getmembers():
                    tar_ref.extract(tar_info, tmp_dir)
                    process_file(os.path.join(tmp_dir, tar_info.name))
        return archive_path
    except Exception as e:
        logging.error(f"Error extracting archive {archive_path}: {e}")
        return None

# Fetch Google Photos metadata
@handle_google_photos_api_errors
def fetch_google_photos_metadata():
    photos_map = {}
    albums_map = fetch_albums()  # Ensure we get album data first
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
                'albums': []
            }
            for album_id in item.get('albumIds', []):
                if album_id in albums_map:
                    photo_data['albums'].append(albums_map[album_id])
            photos_map[item['id']] = photo_data
        logging.info(f"Fetched {len(photos_map)} Google Photos items.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {e}")
    return photos_map

# Fetch Google Photos albums
@handle_google_photos_api_errors
def fetch_albums():
    albums_map = {}
    try:
        albums_response = service.albums().list(pageSize=50).execute()
        for album in albums_response.get('albums', []):
            albums_map[album['id']] = album['title']
        logging.info(f"Fetched {len(albums_map)} albums.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos albums: {e}")
    return albums_map

# Save metadata to DB
def save_to_db(photos_map):
    try:
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
        logging.info("Google Photos metadata saved to DB.")
    except Exception as e:
        logging.error(f"Error saving metadata to DB: {e}")


# Process extracted files
def process_file(file_path):
    if file_path.endswith('.json'):
        handle_json_file(file_path)
    elif file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
        handle_photo_file(file_path)

# Handle JSON file (EXIF repair)
def handle_json_file(json_file_path):
    try:
        with open(json_file_path, 'r') as f:
            json_data = json.load(f)
        photo_path = json_file_path.replace('.json', '')
        if os.path.exists(photo_path):
            repair_exif_data(photo_path, json_data)
    except Exception as e:
        logging.error(f"Error processing JSON file {json_file_path}: {e}")

# Repair EXIF data
def repair_exif_data(photo_path, json_data):
    try:
        metadata = pyexiv2.ImageMetadata(photo_path)
        metadata.read()
        # Example: Repair timestamp
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
        logging.error(f"Error repairing EXIF data for {photo_path}: {e}")

# Move files to designated folders based on EXIF data
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
        logging.error(f"Error moving file {photo_path}: {e}")

# Utility: Create directory safely
def create_directory(path):
    try:
        if not os.path.exists(path):
            os.makedirs(path)
    except OSError as e:
        logging.error(f"Permission denied: Unable to create directory at {path}: {e}")
        print(f"Error: Permission denied. Unable to create directory at {path}. Check permissions.")
        exit(1)

# Utility: Convert decimal degrees to EXIF format (degrees, minutes, seconds)
def convert_to_degrees(value):
    degrees = int(value)
    minutes = int((value - degrees) * 60)
    seconds = (value - degrees - minutes / 60) * 3600
    return (degrees, minutes, seconds)

# Utility: Convert decimal to rational (numerator/denominator) for EXIF format
def convert_to_rational(value):
    return (int(value * 100), 100)

# Utility: Generate MD5 hash
def generate_hash(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error generating MD5 hash for {file_path}: {e}")
        return None

# Utility: Get image dimensions
def get_image_dimensions(file_path):
    try:
        image = Image.open(file_path)
        return image.width, image.height
    except Exception as e:
        logging.error(f"Error getting dimensions for {file_path}: {e}")
        return None

# Main function
def main():
    logging.info('Script started...')
    
    source_dir = 'path_to_takeout_files'
    tmp_dir = 'path_to_tmp_directory'
    global destination_dir
    destination_dir = 'path_to_photos_directory'

    # Step 1: Initialize the database and create a backup
    initialize_database()
    backup_database()

    # Step 2: Fetch Google Photos metadata
    # We first get the metadata from Google Photos, including albums and photo info
    photos_map = fetch_google_photos_metadata()

    # Step 3: Save Google Photos metadata to the database
    # This metadata will be used later for comparison, deduplication, and album structure preservation
    save_to_db(photos_map)

    # Step 4: Verify and extract Takeout files
    # Dry-run or full-run (change 'dry_run=True' if just verifying JSON files)
    verify_takeout_files(source_dir, tmp_dir, dry_run=False)

    # Step 5: Process the JSON files from Takeout for EXIF repairs, deduplication, etc.
    # Build the database with file information extracted from JSON files (sidecar files)
    build_db_from_json(tmp_dir)

    # Step 6: Extract and process archives in parallel, handling photo extraction in batches
    # This step handles both the extraction and the processing of photos, deduplication, and repairs
    archives = [f for f in os.listdir(source_dir) if f.endswith(('.zip', '.tgz'))]
    extract_archives_in_parallel(archives, tmp_dir, batch_size=100)

    # Step 7: Move photos to the final destination (organized by year/month)
    # Once all files are processed, move them into their respective directories
    move_files_to_designated_location(tmp_dir, destination_dir)

    # Step 8: Clean up, close the database connection
    conn.close()
    logging.info('Script completed successfully.')

if __name__ == "__main__":
    main()
