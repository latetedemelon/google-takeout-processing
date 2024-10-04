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

# Extract archives (ZIP and TGZ) in parallel and process files in batches
def extract_archives_in_parallel(archives, tmp_dir, conn):
    try:
        # Using ThreadPoolExecutor to parallelize archive extraction
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_archive = {executor.submit(extract_and_process_archive, archive, tmp_dir, conn): archive for archive in archives}
            
            for future in concurrent.futures.as_completed(future_to_archive):
                archive = future_to_archive[future]
                try:
                    future.result()  # This will raise any exceptions caught during processing
                    logging.info(f"Successfully processed {archive}.")
                except Exception as exc:
                    logging.error(f"Error processing archive {archive}: {exc}")

    except Exception as e:
        logging.error(f"Error during parallel archive extraction: {e}")
        raise

# Extract and process a single archive (ZIP or TGZ)
def extract_and_process_archive(archive, tmp_dir, conn):
    archive_path = os.path.join(tmp_dir, archive)
    logging.info(f"Extracting {archive_path}...")
    
    if archive.endswith('.zip'):
        extract_zip(archive_path, tmp_dir)
    elif archive.endswith('.tgz'):
        extract_tgz(archive_path, tmp_dir)
    else:
        logging.warning(f"Unsupported archive format: {archive}")
        return
    
    # After extraction, process the files in this archive
    process_extracted_files_in_parallel(conn, tmp_dir)

# Extract ZIP files
def extract_zip(archive_path, extract_dir):
    try:
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
            logging.info(f"Successfully extracted ZIP: {archive_path}")
    except zipfile.BadZipFile as e:
        logging.error(f"Bad ZIP file: {archive_path}, Error: {e}")
        raise
    except Exception as e:
        logging.error(f"Error extracting ZIP: {archive_path}, Error: {e}")
        raise

# Extract TGZ files
def extract_tgz(archive_path, extract_dir):
    try:
        with tarfile.open(archive_path, 'r:gz') as tar_ref:
            tar_ref.extractall(extract_dir)
            logging.info(f"Successfully extracted TGZ: {archive_path}")
    except tarfile.TarError as e:
        logging.error(f"Bad TGZ file: {archive_path}, Error: {e}")
        raise
    except Exception as e:
        logging.error(f"Error extracting TGZ: {archive_path}, Error: {e}")
        raise

# Generate MD5 hash for a file
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

# Process the extracted files: Generate MD5, update DB in parallel
def process_extracted_files_in_parallel(conn, tmp_dir):
    try:
        c = conn.cursor()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_file = {}
            
            for root, dirs, files in os.walk(tmp_dir):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    future = executor.submit(process_single_file, conn, file_name, file_path)
                    future_to_file[future] = file_name
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_name = future_to_file[future]
                try:
                    future.result()  # This will raise any exceptions caught during processing
                    logging.info(f"Successfully processed file: {file_name}")
                except Exception as exc:
                    logging.error(f"Error processing file {file_name}: {exc}")
        
        conn.commit()
        logging.info(f"Successfully processed all files in {tmp_dir} and updated the database.")
    except sqlite3.Error as e:
        logging.error(f"Database error while processing extracted files: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing extracted files: {e}")
        raise

# Process a single file: Generate MD5 and update the database
def process_single_file(conn, file_name, file_path):
    md5_hash = generate_md5(file_path)

    # Update the database with the MD5 hash and status
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO FileList (file_name, md5_hash, status)
        VALUES (?, ?, ?);
    """, (file_name, md5_hash, "extracted"))

# Extract EXIF data from a file
def extract_exif(file_path):
    exif_data = {}
    try:
        with Image.open(file_path) as img:
            exif_raw = img._getexif()
            if exif_raw is not None:
                exif_data = {TAGS.get(tag, tag): value for tag, value in exif_raw.items()}
            else:
                logging.warning(f"No EXIF data found for {file_path}")
        logging.info(f"EXIF data extracted for {file_path}")
    except Exception as e:
        logging.warning(f"Failed to extract EXIF data from {file_path}: {e}")
    
    return exif_data

# Repair EXIF data using Google Photos sidecar data (if EXIF is missing or incomplete)
def repair_exif_from_sidecar(file_path, sidecar_path, exif_data):
    try:
        with open(sidecar_path, 'r') as f:
            sidecar_data = json.load(f)
            logging.info(f"Sidecar data loaded for {file_path}")
            
        # Repair EXIF fields with sidecar data if missing
        if 'DateTime' not in exif_data and 'photoTakenTime' in sidecar_data:
            exif_data['DateTime'] = time.strftime('%Y:%m:%d %H:%M:%S', time.gmtime(int(sidecar_data['photoTakenTime']['timestamp'])))
            logging.info(f"Repaired missing DateTime EXIF for {file_path} using sidecar")

        if 'GPSInfo' not in exif_data and 'geoData' in sidecar_data:
            exif_data['GPSInfo'] = {
                'GPSLatitude': sidecar_data['geoData']['latitude'],
                'GPSLongitude': sidecar_data['geoData']['longitude']
            }
            logging.info(f"Repaired missing GPS EXIF for {file_path} using sidecar")
        
        return exif_data
    except Exception as e:
        logging.warning(f"Failed to repair EXIF for {file_path} using sidecar: {e}")
        return exif_data

# Use file creation time as EXIF creation time if no EXIF and no sidecar data available
def get_file_creation_time(file_path):
    try:
        creation_time = os.path.getmtime(file_path)
        return time.strftime('%Y:%m:%d %H:%M:%S', time.gmtime(creation_time))
    except Exception as e:
        logging.error(f"Error getting creation time for {file_path}: {e}")
        return None

# Process extracted files for EXIF extraction and repair
def process_exif_for_files(conn, tmp_dir):
    try:
        c = conn.cursor()

        for root, dirs, files in os.walk(tmp_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                sidecar_path = file_path + ".json"  # Assuming the sidecar file is named with the same base filename
                
                # Extract EXIF
                exif_data = extract_exif(file_path)
                
                # Repair missing fields with sidecar data
                if not exif_data or 'DateTime' not in exif_data or 'GPSInfo' not in exif_data:
                    if os.path.exists(sidecar_path):
                        exif_data = repair_exif_from_sidecar(file_path, sidecar_path, exif_data)
                
                # If still no EXIF data, use the file creation time
                if 'DateTime' not in exif_data:
                    file_creation_time = get_file_creation_time(file_path)
                    if file_creation_time:
                        exif_data['DateTime'] = file_creation_time
                        logging.info(f"Using file creation time as EXIF DateTime for {file_name}")
                
                # Update the database with EXIF data
                if exif_data:
                    c.execute("""
                        UPDATE FileList SET exif_data = ?, status = ?
                        WHERE file_name = ?;
                    """, (json.dumps(exif_data), "exif_processed", file_name))
        
        conn.commit()
        logging.info(f"Successfully processed EXIF data and updated the database.")
    except sqlite3.Error as e:
        logging.error(f"Database error while processing EXIF data: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing EXIF data: {e}")
        raise

# Match the files from the temporary table with the Google Photos API map
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

                # Update the Google Photos API map with the new status and MD5 hash
                photos_map[matched_photo_id]['md5_hash'] = md5_hash
                photos_map[matched_photo_id]['status'] = 'moved'

                logging.info(f"File {file_name} matched with Google Photos metadata and moved to {new_location}")
            else:
                logging.warning(f"No match found for {file_name} in Google Photos API map.")

        conn.commit()
        logging.info(f"All matched files have been moved, and the database and map have been updated.")
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

# Verify if two files are likely duplicates based on primary checks
def verify_potential_duplicates(file1, file2):
    # Compare filename
    if file1['filename'] != file2['filename']:
        return False
    
    # Compare creation time (both EXIF and Google Photos)
    if file1['creation_time'][:10] != file2['creation_time'][:10]:  # Compare only the date part
        return False

    # If primary checks pass, consider them for further comparison
    return True

# Determine which file is of higher quality based on secondary checks
def compare_file_quality(file1, file2):
    # Compare resolution (width * height)
    resolution1 = file1['width'] * file1['height'] if file1['width'] and file1['height'] else 0
    resolution2 = file2['width'] * file2['height'] if file2['width'] and file2['height'] else 0
    
    # If one resolution is higher, prefer that file
    if resolution1 > resolution2:
        return file1
    elif resolution2 > resolution1:
        return file2
    
    # Compare file size (if available, larger size generally indicates better quality)
    if file1['size'] and file2['size']:
        if file1['size'] > file2['size']:
            return file1
        elif file2['size'] > file1['size']:
            return file2
    
    # If all else fails, default to file1 (first file)
    return file1

# Remove lower quality versions, using primary and secondary checks
def remove_lower_quality_versions(conn, photos_map):
    try:
        c = conn.cursor()

        # Find files with the same filename
        c.execute("""
            SELECT file_name, COUNT(*) as count FROM FileList 
            WHERE status = 'moved' 
            GROUP BY file_name HAVING count > 1;
        """)
        duplicate_filenames = c.fetchall()

        for duplicate in duplicate_filenames:
            file_name, count = duplicate
            logging.info(f"Found {count} versions of {file_name}")

            # Fetch all files with this filename
            c.execute("""
                SELECT file_name, new_location, exif_data FROM FileList 
                WHERE file_name = ? AND status = 'moved';
            """, (file_name,))
            file_versions = c.fetchall()

            # Identify duplicates and use secondary checks to determine which to keep
            verified_duplicates = []
            best_version = None

            for i, version1 in enumerate(file_versions):
                exif_data1 = json.loads(version1[2])
                file1 = {
                    'filename': version1[0],
                    'location': version1[1],
                    'creation_time': exif_data1.get('DateTime', photos_map[version1[0]]['creation_time']),
                    'size': os.path.getsize(version1[1]) if os.path.exists(version1[1]) else None,
                    'width': exif_data1.get('ImageWidth'),
                    'height': exif_data1.get('ImageHeight')
                }

                for version2 in file_versions[i+1:]:
                    exif_data2 = json.loads(version2[2])
                    file2 = {
                        'filename': version2[0],
                        'location': version2[1],
                        'creation_time': exif_data2.get('DateTime', photos_map[version2[0]]['creation_time']),
                        'size': os.path.getsize(version2[1]) if os.path.exists(version2[1]) else None,
                        'width': exif_data2.get('ImageWidth'),
                        'height': exif_data2.get('ImageHeight')
                    }

                    # Primary check: ensure files are potential duplicates
                    if verify_potential_duplicates(file1, file2):
                        # Compare quality using secondary checks
                        higher_quality_file = compare_file_quality(file1, file2)
                        lower_quality_file = file1 if higher_quality_file == file2 else file2
                        
                        # Add the lower-quality version to the list for removal
                        verified_duplicates.append(lower_quality_file)

                        # Update the best version if needed
                        if best_version is None or compare_file_quality(best_version, higher_quality_file) == higher_quality_file:
                            best_version = higher_quality_file

            # Remove verified duplicates
            for duplicate in verified_duplicates:
                remove_file(duplicate['location'])
                c.execute("""
                    DELETE FROM FileList WHERE file_name = ? AND new_location = ?;
                """, (duplicate['filename'], duplicate['location']))

            logging.info(f"Kept the highest-quality version of {file_name} and removed lower-quality duplicates.")

        conn.commit()
        logging.info("Lower quality versions removed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during lower quality file removal: {e}")
        raise
    except Exception as e:
        logging.error(f"Error removing lower quality files: {e}")
        raise

# Helper function to remove a file
def remove_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"File {file_path} removed.")
        else:
            logging.warning(f"File {file_path} not found for removal.")
    except Exception as e:
        logging.error(f"Error removing file {file_path}: {e}")
        raise

# Move duplicates to the parallel 'duplicates' structure instead of deleting
def move_duplicates_to_parallel_structure(conn, photos_map, duplicates_dir):
    try:
        c = conn.cursor()

        # Find files with the same filename
        c.execute("""
            SELECT file_name, COUNT(*) as count FROM FileList 
            WHERE status = 'moved' 
            GROUP BY file_name HAVING count > 1;
        """)
        duplicate_filenames = c.fetchall()

        for duplicate in duplicate_filenames:
            file_name, count = duplicate
            logging.info(f"Found {count} versions of {file_name}")

            # Fetch all files with this filename
            c.execute("""
                SELECT file_name, new_location, exif_data FROM FileList 
                WHERE file_name = ? AND status = 'moved';
            """, (file_name,))
            file_versions = c.fetchall()

            # Identify duplicates and use secondary checks to determine which to keep
            verified_duplicates = []
            best_version = None

            for i, version1 in enumerate(file_versions):
                exif_data1 = json.loads(version1[2])
                file1 = {
                    'filename': version1[0],
                    'location': version1[1],
                    'creation_time': exif_data1.get('DateTime', photos_map[version1[0]]['creation_time']),
                    'size': os.path.getsize(version1[1]) if os.path.exists(version1[1]) else None,
                    'width': exif_data1.get('ImageWidth'),
                    'height': exif_data1.get('ImageHeight')
                }

                for version2 in file_versions[i+1:]:
                    exif_data2 = json.loads(version2[2])
                    file2 = {
                        'filename': version2[0],
                        'location': version2[1],
                        'creation_time': exif_data2.get('DateTime', photos_map[version2[0]]['creation_time']),
                        'size': os.path.getsize(version2[1]) if os.path.exists(version2[1]) else None,
                        'width': exif_data2.get('ImageWidth'),
                        'height': exif_data2.get('ImageHeight')
                    }

                    # Primary check: ensure files are potential duplicates
                    if verify_potential_duplicates(file1, file2):
                        # Compare quality using secondary checks
                        higher_quality_file = compare_file_quality(file1, file2)
                        lower_quality_file = file1 if higher_quality_file == file2 else file2
                        
                        # Add the lower-quality version to the list for moving
                        verified_duplicates.append(lower_quality_file)

                        # Update the best version if needed
                        if best_version is None or compare_file_quality(best_version, higher_quality_file) == higher_quality_file:
                            best_version = higher_quality_file

            # Move verified duplicates to the parallel 'duplicates' directory
            for duplicate in verified_duplicates:
                new_location = move_file_to_duplicates_directory(duplicate['location'], duplicates_dir, duplicate['creation_time'])
                c.execute("""
                    UPDATE FileList SET status = ?, new_location = ?
                    WHERE file_name = ? AND new_location = ?;
                """, ("duplicate_moved", new_location, duplicate['filename'], duplicate['location']))

            logging.info(f"Moved lower-quality duplicates of {file_name} to the duplicates directory.")

        conn.commit()
        logging.info("Lower quality versions moved to duplicates directory successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during moving duplicates: {e}")
        raise
    except Exception as e:
        logging.error(f"Error moving duplicates: {e}")
        raise

# Move the file to the parallel 'duplicates' directory, organized by year/month
def move_file_to_duplicates_directory(file_path, duplicates_dir, creation_time):
    try:
        # Extract year and month from the creation time
        if creation_time:
            year = creation_time[:4]
            month = creation_time[5:7]
        else:
            year = 'unknown_year'
            month = 'unknown_month'

        # Create destination path in the duplicates directory
        final_duplicates_dir = os.path.join(duplicates_dir, year, month)
        if not os.path.exists(final_duplicates_dir):
            os.makedirs(final_duplicates_dir)

        # Move the file to the duplicates directory
        new_path = os.path.join(final_duplicates_dir, os.path.basename(file_path))
        shutil.move(file_path, new_path)

        logging.info(f"Moved file {file_path} to duplicates directory {new_path}")
        return new_path
    except Exception as e:
        logging.error(f"Error moving file {file_path} to duplicates directory: {e}")
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

