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
from PIL import Image
import pillow_heif  # Ensures HEIC support in Pillow
import hachoir
from hachoir.metadata import extractMetadata
from hachoir.parser import createParser
from hachoir.editor import createEditor
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError

# Setup logging with more granular levels
logging.basicConfig(
    filename='photo_processing.log',
    level=logging.DEBUG,  # Changed to DEBUG for more granular logging
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define paths in environment variables or config file for flexibility
DATABASE_PATH = os.getenv('DATABASE_PATH', 'photo_processing.db')
BACKUP_DATABASE_PATH = os.getenv('BACKUP_DATABASE_PATH', 'photo_processing_backup.db')
TOKEN_PATH = os.getenv('TOKEN_PATH', 'token.json')
# Setup Google Photos API
SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']

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

# Error handling for file operations
def process_file(file_path):
    try:
        # Process the file (either JSON or photo)
        if file_path.endswith('.json'):
            handle_json_file(file_path)
        elif file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
            handle_photo_file(file_path)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except PermissionError:
        logging.error(f"Permission denied: {file_path}")
    except Exception as e:
        logging.error(f"Unexpected error processing file {file_path}: {e}")

def handle_video_file(file_path):
    try:
        parser = createParser(file_path)
        metadata = extractMetadata(parser)
        if metadata:
            # Modify the creation date (example)
            editor = createEditor(parser)
            editor.setValue('creation_date', '2024-10-01 10:00:00')
            editor.save(file_path)
        
        logging.info(f"Processed MOV file: {file_path}")
    except Exception as e:
        logging.error(f"Error processing MOV file {file_path}: {e}")


# Google Photos service setup
# service = get_google_service(TOKEN_PATH)
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

# Decorator for handling API errors and rate limiting
def handle_api_errors_and_rate_limit(func):
    def wrapper(*args, **kwargs):
        retries = 3
        delay = 2
        for attempt in range(retries):
            try:
                result = func(*args, **kwargs)
                if 'X-RateLimit-Remaining' in result and int(result['X-RateLimit-Remaining']) == 0:
                    sleep_time = int(result['X-RateLimit-Reset'])
                    logging.warning(f"Rate limit hit. Sleeping for {sleep_time} seconds.")
                    time.sleep(sleep_time)
                return result
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

# Fetch Google Photos albums
@handle_api_errors_and_rate_limit
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

# Fetch Google Photos metadata
@handle_api_errors_and_rate_limit
def fetch_google_photos_metadata():
    photos_map = {}
    albums_map = fetch_albums()  # Get album data first
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

# Save metadata to DB with flexibility (batch or transactional insert)
def save_photos_to_db(photos_map, batch_size=100, transactional=False):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        if transactional:
            conn.execute('BEGIN EXCLUSIVE TRANSACTION')

        batch = []
        for photo_id, photo_data in photos_map.items():
            batch.append((
                photo_id, 
                photo_data['filename'], 
                photo_data['creation_time'], 
                photo_data['mime_type'], 
                photo_data['width'], 
                photo_data['height'], 
                ', '.join(photo_data['albums'])  # Join album titles
            ))
            if len(batch) == batch_size:
                cursor.executemany("""
                    INSERT OR REPLACE INTO PhotoList 
                    (photo_id, filename, creation_time, mime_type, width, height, albums)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, batch)
                conn.commit()
                logging.info(f"Batch of {batch_size} photos saved to DB.")
                batch.clear()  # Clear batch after saving

        # Save the remaining batch
        if batch:
            cursor.executemany("""
                INSERT OR REPLACE INTO PhotoList 
                (photo_id, filename, creation_time, mime_type, width, height, albums)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, batch)
            conn.commit()
            logging.info(f"Final batch of {len(batch)} photos saved to DB.")

        if transactional:
            conn.commit()

    except sqlite3.Error as e:
        if transactional:
            conn.rollback()  # Rollback if transactional
        logging.error(f"Error saving photos to DB: {e}")
    finally:
        conn.close()

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

# Process extracted files
def process_file(file_path):
    file_extension = file_path.lower().split('.')[-1]

    # Handle JSON sidecar files
    if file_extension == 'json':
        handle_json_file(file_path)

    # Handle common image file formats, including Apple formats (HEIC, HEIF, ProRAW)
    elif file_extension in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'raw', 'heic', 'heif', 'dng']:
        handle_image_file(file_path)

    # Handle video files, including Apple's MOV format
    elif file_extension in ['mp4', 'mov', 'avi', 'mkv', 'flv', 'wmv']:
        handle_video_file(file_path)

    # Unsupported file types
    else:
        logging.warning(f"Unsupported file type: {file_path}")


def handle_image_file(file_path):
    try:
        # HEIC/HEIF image EXIF handling
        if file_path.endswith(('.heic', '.heif')):
            image = Image.open(file_path)
            exif_data = image.getexif()  # Extract EXIF data
            # Modify or add EXIF data
            exif_data[0x0132] = "2024:10:01 10:00:00"  # Example: Modify date taken
            image.save(file_path, exif=exif_data.tobytes())  # Save with modified EXIF
            
            logging.info(f"Processed HEIC/HEIF file: {file_path}")
        else:
            logging.info(f"Processed regular image file: {file_path}")
    except Exception as e:
        logging.error(f"Error processing image file {file_path}: {e}")


def handle_image_file(file_path):
    try:
        # DNG image EXIF handling
        if file_path.endswith('.dng'):
            image = Image.open(file_path)
            exif_data = image.getexif()  # Extract EXIF data
            # Modify EXIF data
            exif_data[0x9003] = "2024:10:01 12:00:00"  # Example: Modify DateTimeOriginal
            image.save(file_path, exif=exif_data.tobytes())  # Save with modified EXIF

            logging.info(f"Processed ProRAW/DNG file: {file_path}")
    except Exception as e:
        logging.error(f"Error processing DNG file {file_path}: {e}")

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

# Utility: User-friendly logging and error reporting
def log_and_report_error(message, error=None):
    if error:
        logging.error(f"{message}: {error}")
    else:
        logging.error(f"{message}")
    print(f"Error: {message}. Check logs for more details.")

# Utility: Retry mechanism with exponential backoff for operations
def retry_operation(operation, retries=3, delay=2, *args, **kwargs):
    for attempt in range(retries):
        try:
            return operation(*args, **kwargs)
        except (HttpError, Exception) as e:
            if attempt < retries - 1:
                time.sleep(delay * (2 ** attempt))  # Exponential backoff
                logging.warning(f"Retrying operation after error: {e}")
            else:
                logging.error(f"Operation failed after {retries} attempts: {e}")
                return None

# Main function
def main():
    logging.info('Script started...')

    source_dir = os.getenv('SOURCE_DIR', 'path_to_takeout_files')
    tmp_dir = os.getenv('TMP_DIR', 'path_to_tmp_directory')
    global destination_dir
    destination_dir = os.getenv('DESTINATION_DIR', 'path_to_photos_directory')

    try:
        # Step 1: Initialize the database and create a backup
        initialize_database()
        backup_database()

        # Step 2: Fetch Google Photos metadata
        photos_map = fetch_google_photos_metadata()

        # Step 3: Save Google Photos metadata to the database using batch processing
        save_photos_in_batches(photos_map)

        # Step 4: Verify and extract Takeout files (e.g., ZIPs, TGZs)
        archives = [f for f in os.listdir(source_dir) if f.endswith(('.zip', '.tgz'))]
        extract_archives_in_parallel(archives, tmp_dir)

        # Step 5: Process the JSON files for EXIF repairs, deduplication, etc.
        process_files_in_dir(tmp_dir)

        # Step 6: Move photos to the final destination (organized by year/month)
        move_files_to_designated_location(tmp_dir, destination_dir)

        # Step 7: Clean up, close the database connection
        close_db_connection()

        logging.info('Script completed successfully.')
        print("Processing completed successfully.")
    except Exception as e:
        log_and_report_error("An error occurred during processing", e)

if __name__ == "__main__":
    main()

