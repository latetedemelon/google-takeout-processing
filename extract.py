import os
import hashlib
import sqlite3
import json
import shutil
import logging
import zipfile
import tarfile
import pyexiv2
from PIL.ExifTags import GPSTAGS
from PIL import Image
from PIL.ExifTags import TAGS
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime
import time

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

# Check if database exists and create tables if necessary
def initialize_database():
    try:
        with conn:
            # Create the tables if they don't exist
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
    except google.auth.exceptions.RefreshError:
        logging.error("Google API token is expired or invalid. Please refresh or authenticate again.")
        print("Error: Google API token is expired or invalid. Please refresh or authenticate again.")
        exit(1)
    except googleapiclient.errors.HttpError as e:
        logging.error(f"Google Photos API error: {str(e)}")
        print(f"Error: Google Photos API error: {str(e)}")
        exit(1)
    except Exception as e:
        logging.error(f"Unknown error while fetching Google Photos metadata: {str(e)}")
        print(f"Error: Unknown error while fetching Google Photos metadata: {str(e)}")
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
def verify_takeout_files(source_dir, tmp_dir, dry_run=True):
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
            extract_full_archive(archive_path, tmp_dir)

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
    except MemoryError:
        logging.error(f"Memory error while processing large archive: {archive_path}")
        print(f"Error: Unable to process large archive {archive_path} due to memory issues.")
        exit(1)
    except Exception as e:
        logging.error(f"Error extracting JSON files from {archive_path}: {str(e)}")

# Extract full archive (photos and JSON files)
def extract_full_archive(archive_path, tmp_dir):
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)
                logging.info(f"Extracted full archive {archive_path}")
        elif archive_path.endswith('.tgz'):
            with tarfile.open(archive_path, 'r:gz') as tar_ref:
                tar_ref.extractall(tmp_dir)
                logging.info(f"Extracted full archive {archive_path}")
    except MemoryError:
        logging.error(f"Memory error while processing large archive: {archive_path}")
        print(f"Error: Unable to process large archive {archive_path} due to memory issues.")
        exit(1)
    except Exception as e:
        logging.error(f"Error extracting full archive from {archive_path}: {str(e)}")

# Step 3: Build the database from the JSON files if necessary
def build_db_from_json(json_dir):
    json_files = [os.path.join(json_dir, f) for f in os.listdir(json_dir) if f.endswith('.json')]
    for json_file in json_files:
        with open(json_file, 'r') as f:
            try:
                json_data = json.load(f)
                process_json_data(json_data)
            except json.JSONDecodeError as e:
                logging.error(f"JSON decoding error in file {json_file}: {str(e)}")
                print(f"Error: JSON file is malformed or corrupted. Check the logs for details.")
            except Exception as e:
                logging.error(f"Error processing JSON file {json_file}: {str(e)}")

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
        logging.error(f"KeyError in JSON file structure: Missing key {str(e)}")
    except Exception as e:
        logging.error(f"Unexpected error processing JSON: {str(e)}")

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
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error generating MD5 hash for {file_path}: {str(e)}")
        return None

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
    try:
        image = Image.open(file_path)
        return image.width, image.height
    except Exception as e:
        logging.error(f"Error getting dimensions for {file_path}: {str(e)}")
        return None

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
                    create_directory(month_dir)
                    shutil.move(file_path, os.path.join(month_dir, file))
            except Exception as e:
                logging.error(f"Error moving photo {file_path}: {str(e)}")

# Step 7: Repair EXIF data from JSON sidecar files
try:
    import pyexiv2
except ImportError:
    logging.error("pyexiv2 library is not installed. Please install pyexiv2 to proceed with EXIF repair.")
    print("Error: pyexiv2 is not installed. Please install pyexiv2 to enable EXIF repair.")
    exit(1)

# Convert decimal degrees to EXIF format (degrees, minutes, seconds)
def convert_to_degrees(value):
    degrees = int(value)
    minutes = int((value - degrees) * 60)
    seconds = (value - degrees - minutes / 60) * 3600
    return (degrees, minutes, seconds)

# Convert decimal to rational (numerator/denominator) for EXIF format
def convert_to_rational(value):
    return (int(value * 100), 100)

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

        # Use geoDataExif first, fallback to geoData
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

        # Write back the metadata to the photo
        metadata.write()

    except KeyError as e:
        logging.error(f"KeyError in JSON file: {str(e)}")
    except Exception as e:
        logging.error(f"Error repairing EXIF data for {photo_path}: {str(e)}")
        print(f"Error: Could not repair EXIF data for {photo_path}.")



# Main function
def main():
    logging.info('Script started...')
    
    source_dir = 'path_to_takeout_files'
    tmp_dir = 'path_to_tmp_directory'
    destination_dir = 'path_to_photos_directory'

    # Step 1: Initialize database (create tables if they don't exist)
    initialize_database()

    # Step 2: Backup the database
    backup_database()

    # Step 3: Create map/list of Google Photos
    create_google_photos_map()

    # Step 4: Verify Takeout files (Dry Run or Full Run)
    verify_takeout_files(source_dir, tmp_dir, dry_run=False)

    # Step 5: Build database from JSON files
    build_db_from_json(tmp_dir)

    # Step 6: Process and deduplicate photos
    move_files_to_designated_location(tmp_dir, destination_dir)

    conn.close()
    logging.info('Script completed.')

if __name__ == "__main__":
    main()
