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

SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']  # Define your scopes

# Get Google Photos service setup
def get_google_service(token_path):
    try:
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        service = build('photoslibrary', 'v1', credentials=creds)
        logging.info("Google Photos API service successfully initialized.")
        return service
    except RefreshError as e:
        logging.error("Failed to refresh Google API token. Please check token.json.")
        raise
    except Exception as e:
        logging.error(f"Error setting up Google Photos API service: {e}")
        raise

# Fetch Google Photos albums
@handle_api_errors_and_rate_limit
def fetch_albums(service):
    albums_map = {}
    try:
        next_page_token = None
        while True:
            albums_response = service.albums().list(pageSize=50, pageToken=next_page_token).execute()
            for album in albums_response.get('albums', []):
                albums_map[album['id']] = album['title']
            next_page_token = albums_response.get('nextPageToken')
            if not next_page_token:
                break
        logging.info(f"Fetched {len(albums_map)} albums.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos albums: {e}")
    return albums_map

# Fetch Google Photos metadata
@handle_api_errors_and_rate_limit
def fetch_google_photos_metadata(service):
    photos_map = {}
    albums_map = fetch_albums(service)  # Get album data first
    try:
        next_page_token = None
        while True:
            results = service.mediaItems().list(pageSize=100, pageToken=next_page_token).execute()
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

            next_page_token = results.get('nextPageToken')
            if not next_page_token:
                break

        logging.info(f"Fetched {len(photos_map)} Google Photos items.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {e}")
    return photos_map

# Save photo metadata in the database
def save_photos_in_batches(conn, photos_map):
    try:
        c = conn.cursor()
        for photo in photos_map.values():
            c.execute("""
                INSERT OR REPLACE INTO PhotoList (photo_id, filename, creation_time, mime_type, width, height, albums)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (photo["id"], photo["filename"], photo["creation_time"], photo["mime_type"], 
                  photo["width"], photo["height"], ','.join(photo["albums"])))
        
        conn.commit()
        logging.info(f"Successfully saved {len(photos_map)} photos to the database.")
    except sqlite3.Error as e:
        logging.error(f"Error saving photo metadata to database: {e}")
        raise


# Decorator for handling API errors and rate limiting
def handle_api_errors_and_rate_limit(func):
    def wrapper(*args, **kwargs):
        retries = 3
        delay = 2
        for attempt in range(retries):
            try:
                result = func(*args, **kwargs)
                return result
            except HttpError as e:
                if e.resp.status == 429:  # Too many requests (rate limiting)
                    logging.warning(f"Rate limit exceeded. Retrying in {delay * (attempt + 1)} seconds...")
                    time.sleep(delay * (attempt + 1))
                else:
                    logging.error(f"Google Photos API error: {str(e)}")
                    if attempt < retries - 1:
                        time.sleep(delay)
                    else:
                        raise
            except Exception as e:
                logging.error(f"An error occurred: {e}")
                if attempt < retries - 1:
                    time.sleep(delay)
                else:
                    raise
    return wrapper

# Function to generate MD5 hash for a file
def generate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logging.error(f"Error generating MD5 for {file_path}: {e}")
        raise

# Function to extract ZIP files
def extract_zip(archive_path, extract_dir):
    try:
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
            logging.info(f"Successfully extracted ZIP archive: {archive_path}")
    except Exception as e:
        logging.error(f"Error extracting ZIP file {archive_path}: {e}")
        raise

# Function to extract TGZ files
def extract_tgz(archive_path, extract_dir):
    try:
        with tarfile.open(archive_path, 'r:gz') as tar_ref:
            tar_ref.extractall(extract_dir)
            logging.info(f"Successfully extracted TGZ archive: {archive_path}")
    except Exception as e:
        logging.error(f"Error extracting TGZ file {archive_path}: {e}")
        raise

# Function to extract archives in parallel (ZIP and TGZ)
def extract_archives_in_parallel(archives, extract_dir, conn):
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_archive = {executor.submit(extract_and_process_archive, archive, extract_dir, conn): archive for archive in archives}
            for future in concurrent.futures.as_completed(future_to_archive):
                archive = future_to_archive[future]
                try:
                    future.result()  # Raises exceptions if any occurred during the processing
                    logging.info(f"Successfully processed {archive}")
                except Exception as exc:
                    logging.error(f"Error processing {archive}: {exc}")
    except Exception as e:
        logging.error(f"Error during parallel archive extraction: {e}")
        raise

# Function to extract a single archive and process files for MD5 hash generation
def extract_and_process_archive(archive, extract_dir, conn):
    archive_path = os.path.join(extract_dir, archive)
    
    if archive.endswith('.zip'):
        extract_zip(archive_path, extract_dir)
    elif archive.endswith('.tgz'):
        extract_tgz(archive_path, extract_dir)
    else:
        logging.warning(f"Unsupported archive format: {archive}")
        return
    
    # After extraction, process the extracted files
    process_extracted_files(conn, extract_dir)

# Function to process extracted files, generate MD5, and update the database
def process_extracted_files(conn, extract_dir):
    try:
        c = conn.cursor()
        for root, dirs, files in os.walk(extract_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                md5_hash = generate_md5(file_path)
                
                # Insert the file details into the database
                c.execute("""
                    INSERT OR REPLACE INTO FileList (file_name, md5_hash, status)
                    VALUES (?, ?, ?);
                """, (file_name, md5_hash, "extracted"))

        conn.commit()
        logging.info(f"Processed files and updated the database for {extract_dir}")
    except sqlite3.Error as e:
        logging.error(f"Database error during file processing: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing extracted files: {e}")
        raise

# Function to extract EXIF data from a file
def extract_exif(file_path):
    exif_data = {}
    try:
        with Image.open(file_path) as img:
            exif_raw = img._getexif()
            if exif_raw:
                exif_data = {TAGS.get(tag, tag): value for tag, value in exif_raw.items()}
        logging.info(f"Extracted EXIF data for {file_path}")
    except Exception as e:
        logging.warning(f"Failed to extract EXIF data from {file_path}: {e}")
    return exif_data

# Use file creation time as EXIF creation time if no EXIF and no sidecar data is available
def get_file_creation_time(file_path):
    try:
        creation_time = os.path.getmtime(file_path)
        return time.strftime('%Y:%m:%d %H:%M:%S', time.gmtime(creation_time))
    except Exception as e:
        logging.error(f"Error getting creation time for {file_path}: {e}")
        return None

# Function to repair EXIF data using all available sidecar JSON fields
def repair_exif_with_sidecar(file_path, sidecar_path, exif_data):
    try:
        if not os.path.exists(sidecar_path):
            logging.warning(f"Sidecar file not found for {file_path}")
            return exif_data

        with open(sidecar_path, 'r') as f:
            sidecar_data = json.load(f)

        # Add all available EXIF-related fields from the sidecar JSON
        if 'photoTakenTime' in sidecar_data:
            exif_data['DateTime'] = sidecar_data['photoTakenTime']['timestamp']
            logging.info(f"Repaired DateTime EXIF for {file_path} using sidecar JSON")

        if 'geoData' in sidecar_data:
            exif_data['GPSInfo'] = {
                'GPSLatitude': sidecar_data['geoData'].get('latitude'),
                'GPSLongitude': sidecar_data['geoData'].get('longitude')
            }
            logging.info(f"Repaired GPS EXIF for {file_path} using sidecar JSON")

        if 'geoDataExif' in sidecar_data:
            exif_data['GPSInfoExif'] = {
                'GPSLatitude': sidecar_data['geoDataExif'].get('latitude'),
                'GPSLongitude': sidecar_data['geoDataExif'].get('longitude')
            }
            logging.info(f"Repaired GPS EXIF with EXIF data for {file_path} using sidecar JSON")

        if 'cameraMake' in sidecar_data:
            exif_data['Make'] = sidecar_data['cameraMake']
            logging.info(f"Repaired Camera Make for {file_path}")

        if 'cameraModel' in sidecar_data:
            exif_data['Model'] = sidecar_data['cameraModel']
            logging.info(f"Repaired Camera Model for {file_path}")

        if 'focalLength' in sidecar_data:
            exif_data['FocalLength'] = sidecar_data['focalLength']
            logging.info(f"Repaired Focal Length for {file_path}")

        if 'apertureFNumber' in sidecar_data:
            exif_data['Aperture'] = sidecar_data['apertureFNumber']
            logging.info(f"Repaired Aperture FNumber for {file_path}")

        if 'isoEquivalent' in sidecar_data:
            exif_data['ISO'] = sidecar_data['isoEquivalent']
            logging.info(f"Repaired ISO Equivalent for {file_path}")

        if 'exposureTime' in sidecar_data:
            exif_data['ExposureTime'] = sidecar_data['exposureTime']
            logging.info(f"Repaired Exposure Time for {file_path}")

        if 'creationTime' in sidecar_data:
            exif_data['FileCreationTime'] = sidecar_data['creationTime']['timestamp']
            logging.info(f"Repaired File Creation Time for {file_path}")

        if 'modificationTime' in sidecar_data:
            exif_data['FileModificationTime'] = sidecar_data['modificationTime']['timestamp']
            logging.info(f"Repaired File Modification Time for {file_path}")

        return exif_data
    except Exception as e:
        logging.warning(f"Failed to repair EXIF data for {file_path} using sidecar JSON: {e}")
        return exif_data

# Function to process EXIF for files including Apple formats
def process_exif_for_files(conn, extract_dir):
    try:
        c = conn.cursor()

        for root, dirs, files in os.walk(extract_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                sidecar_path = file_path + ".json"  # Assuming the sidecar file is named the same as the media file
                
                # Extract EXIF data based on media type (images and videos)
                exif_data = extract_exif(file_path) if file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.heic', '.heif')) else {}

                # Repair EXIF data with sidecar JSON if necessary
                if not exif_data or 'DateTime' not in exif_data or 'GPSInfo' not in exif_data:
                    exif_data = repair_exif_with_sidecar(file_path, sidecar_path, exif_data)
                
                # If still no EXIF data, fall back to the file's creation time
                if 'DateTime' not in exif_data:
                    file_creation_time = get_file_creation_time(file_path)
                    if file_creation_time:
                        exif_data['DateTime'] = file_creation_time
                        logging.info(f"Using file creation time as EXIF DateTime for {file_name}")

                # Update the database with EXIF data
                c.execute("""
                    UPDATE FileList SET exif_data = ?, status = ?
                    WHERE file_name = ?;
                """, (json.dumps(exif_data), "exif_processed", file_name))

        conn.commit()
        logging.info(f"Successfully processed EXIF data for files in {extract_dir}")
    except sqlite3.Error as e:
        logging.error(f"Database error while processing EXIF data: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing EXIF data: {e}")
        raise

# Function to match files with Google Photos API metadata and move them to the final location
def match_and_move_files(conn, tmp_dir, destination_dir, photos_map):
    try:
        c = conn.cursor()

        # Query the temporary table to get all the processed files
        c.execute("SELECT file_name, exif_data FROM FileList WHERE status = 'exif_processed'")
        processed_files = c.fetchall()

        for file_record in processed_files:
            file_name, exif_data = file_record
            file_path = os.path.join(tmp_dir, file_name)

            # Find a match in the Google Photos API map using filename and creation time
            matched_photo_id = None
            for photo_id, photo_data in photos_map.items():
                if file_name == photo_data['filename']:
                    exif_json = json.loads(exif_data)
                    file_creation_time = exif_json.get('DateTime', None)

                    # Match using creation time if available
                    if file_creation_time and photo_data['creation_time'].startswith(file_creation_time[:10]):
                        matched_photo_id = photo_id
                        break
                    elif not file_creation_time:
                        matched_photo_id = photo_id  # Fallback to filename match only

            if matched_photo_id:
                # Move the file to its final destination
                matched_photo = photos_map[matched_photo_id]
                new_location = move_file_to_final_location(file_path, destination_dir, matched_photo, exif_data)
                
                # Generate MD5 hash for the moved file
                md5_hash = generate_md5(new_location)
                
                # Update the database with the new location and status
                c.execute("""
                    UPDATE FileList SET status = ?, new_location = ?, md5_hash = ?
                    WHERE file_name = ?;
                """, ("moved", new_location, md5_hash, file_name))

                logging.info(f"File {file_name} matched with Google Photos metadata and moved to {new_location}")
            else:
                logging.warning(f"No match found for {file_name} in Google Photos API map.")

        conn.commit()
        logging.info(f"All matched files have been moved and the database updated.")
    except sqlite3.Error as e:
        logging.error(f"Database error during file matching and moving: {e}")
        raise
    except Exception as e:
        logging.error(f"Error during file matching and moving: {e}")
        raise

# Move the file to the final destination directory, organized by year/month from EXIF or Google Photos API data
def move_file_to_final_location(file_path, destination_dir, photo_data, exif_data):
    try:
        # Extract year and month from EXIF data first, then fall back on Google Photos metadata if needed
        creation_time = None
        exif_json = json.loads(exif_data)
        if 'DateTime' in exif_json:
            creation_time = exif_json['DateTime']
        else:
            creation_time = photo_data.get('creation_time')

        if creation_time:
            year = creation_time[:4]
            month = creation_time[5:7]
        else:
            year = 'unknown_year'
            month = 'unknown_month'

        # Create destination path based on year/month structure
        final_dir = os.path.join(destination_dir, year, month)
        if not os.path.exists(final_dir):
            os.makedirs(final_dir)

        # Move the file to the final directory
        new_path = os.path.join(final_dir, photo_data['filename'])
        shutil.move(file_path, new_path)

        return new_path
    except Exception as e:
        logging.error(f"Error moving file {file_path} to final location: {e}")
        raise

# Function to compare file quality (e.g., resolution, file size)
def compare_file_quality(file1, file2):
    resolution1 = file1['width'] * file1['height'] if file1['width'] and file1['height'] else 0
    resolution2 = file2['width'] * file2['height'] if file2['width'] and file2['height'] else 0
    
    # Compare resolutions first
    if resolution1 > resolution2:
        return file1
    elif resolution2 > resolution1:
        return file2
    else:
        # If resolution is the same, use file size as a secondary check
        if file1['size'] and file2['size']:
            return file1 if file1['size'] > file2['size'] else file2
        else:
            # If no size or resolution difference, keep file1 by default
            return file1

# Move the lower-quality duplicate to the 'duplicates' directory
def move_to_duplicates_directory(file_info, duplicates_dir):
    try:
        creation_time = os.path.getmtime(file_info['location'])
        year = time.strftime('%Y', time.gmtime(creation_time))
        month = time.strftime('%m', time.gmtime(creation_time))

        final_duplicates_dir = os.path.join(duplicates_dir, year, month)
        if not os.path.exists(final_duplicates_dir):
            os.makedirs(final_duplicates_dir)

        new_path = os.path.join(final_duplicates_dir, os.path.basename(file_info['location']))
        shutil.move(file_info['location'], new_path)

        logging.info(f"Moved file {file_info['location']} to duplicates directory {new_path}")
        return new_path
    except Exception as e:
        logging.error(f"Error moving file {file_info['location']} to duplicates directory: {e}")
        raise

# Function to handle duplicates based on MD5, filename, and creation time
def handle_duplicates(conn, tmp_dir, duplicates_dir):
    try:
        c = conn.cursor()

        # Query the temporary table for MD5 hashes
        c.execute("SELECT file_name, md5_hash, exif_data FROM FileList WHERE status = 'extracted'")
        temp_files = c.fetchall()

        # Check the map and the temporary table for MD5 matches
        for temp_file in temp_files:
            temp_file_name, temp_md5, temp_exif = temp_file
            exif_json_temp = json.loads(temp_exif)

            # Search in both the processed map and the temporary table for MD5 hash matches
            c.execute("""
                SELECT file_name, md5_hash, exif_data, new_location FROM FileList 
                WHERE md5_hash = ? AND status = 'moved';
            """, (temp_md5,))
            map_files = c.fetchall()

            for map_file in map_files:
                map_file_name, map_md5, map_exif, map_location = map_file
                exif_json_map = json.loads(map_exif)

                # Compare resolutions and move the lower quality one
                temp_file_info = {
                    'filename': temp_file_name,
                    'location': os.path.join(tmp_dir, temp_file_name),
                    'width': exif_json_temp.get('ImageWidth'),
                    'height': exif_json_temp.get('ImageHeight'),
                    'size': os.path.getsize(os.path.join(tmp_dir, temp_file_name))
                }

                map_file_info = {
                    'filename': map_file_name,
                    'location': map_location,
                    'width': exif_json_map.get('ImageWidth'),
                    'height': exif_json_map.get('ImageHeight'),
                    'size': os.path.getsize(map_location)
                }

                # Compare file quality and move the lower-quality file
                better_file = compare_file_quality(temp_file_info, map_file_info)
                if better_file == temp_file_info:
                    move_to_duplicates_directory(map_file_info, duplicates_dir)
                    # Update the database to reflect the new location for the duplicate file
                    c.execute("""
                        UPDATE FileList SET status = ?, new_location = ? WHERE file_name = ?;
                    """, ("duplicate_moved", map_file_info['location'], map_file_info['filename']))
                else:
                    move_to_duplicates_directory(temp_file_info, duplicates_dir)
                    c.execute("""
                        UPDATE FileList SET status = ?, new_location = ? WHERE file_name = ?;
                    """, ("duplicate_moved", temp_file_info['location'], temp_file_info['filename']))

        conn.commit()
        logging.info("Processed all duplicates based on MD5 hash, filename, and creation time.")
    except sqlite3.Error as e:
        logging.error(f"Database error during duplicate processing: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing duplicates: {e}")
        raise


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

