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

# Create directory safely with permission handling
def create_directory(path):
    try:
        if not os.path.exists(path):
            os.makedirs(path)
    except OSError as e:
        logging.error(f"Permission denied: Unable to create directory at {path}: {str(e)}")
        print(f"Error: Permission denied. Unable to create directory at {path}. Check permissions.")
        exit(1)

# Retry mechanism for transient errors (e.g., API or DB operations)
def retry_operation(operation, retries=3, delay=2, *args, **kwargs):
    for attempt in range(retries):
        try:
            return operation(*args, **kwargs)
        except Exception as e:
            logging.warning(f"Operation failed on attempt {attempt+1}: {str(e)}")
            time.sleep(delay)
    logging.error(f"Operation failed after {retries} attempts.")
    return None

# Check if archive is already processed
def is_archive_processed(archive_name):
    return retry_operation(lambda: c.execute("SELECT status FROM ArchiveProcessing WHERE archive_name = ? AND status = 'completed'", (archive_name,)).fetchone())

# Mark archive as processed in the database
def mark_archive_as_processed(archive_name):
    retry_operation(lambda: c.execute("INSERT OR REPLACE INTO ArchiveProcessing (archive_name, status) VALUES (?, ?)", (archive_name, 'completed')))
    conn.commit()

# Extract full archive in batches to avoid memory overload
def extract_full_archive_in_batches(archive_path, tmp_dir, batch_size=100):
    archive_name = os.path.basename(archive_path)
    if is_archive_processed(archive_name):
        logging.info(f"Skipping {archive_name}, already processed.")
        return

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

        mark_archive_as_processed(archive_name)

    except Exception as e:
        logging.error(f"Error extracting full archive from {archive_path}: {str(e)}")

# Process batch: Deduplicate, fix EXIF, move files
def process_batch(batch, tmp_dir):
    logging.info(f"Processing files in batch: {batch}")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_file, os.path.join(tmp_dir, file)): file for file in batch}
        for future in concurrent.futures.as_completed(futures):
            file = futures[future]
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error processing {file}: {str(e)}")

# Process a single file: Deduplicate, fix EXIF, move to proper folder
def process_file(file_path):
    # Step 1: Deduplicate
    if deduplicate_photos(file_path):
        return  # Skip duplicates

    # Step 2: Repair EXIF
    json_sidecar = find_json_sidecar(file_path)
    if json_sidecar:
        with open(json_sidecar, 'r') as f:
            json_data = json.load(f)
            repair_exif_data(file_path, json_data)

    # Step 3: Move files to designated folder based on EXIF timestamp
    move_file_based_on_exif(file_path)

# Deduplicate photos by MD5 hash and check for lower resolution
def deduplicate_photos(photo_path):
    md5_hash = generate_hash(photo_path)
    size = os.path.getsize(photo_path)
    if is_duplicate(md5_hash, size):
        logging.info(f"Duplicate photo found: {photo_path}")
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

# Check for lower-resolution duplicate
def check_for_lower_resolution(photo_path, md5_hash, size):
    dimensions = get_image_dimensions(photo_path)
    existing_photos = retry_operation(lambda: c.execute("SELECT file_name, width, height FROM FileList WHERE width >= ? AND height >= ?", dimensions).fetchall())
    if existing_photos:
        logging.info(f"Lower resolution duplicate found for {photo_path}")
        mark_as_duplicate(photo_path)
    else:
        add_photo_to_db(photo_path, md5_hash, dimensions, size)

def get_image_dimensions(file_path):
    try:
        image = Image.open(file_path)
        return image.width, image.height
    except Exception as e:
        logging.error(f"Error getting dimensions for {file_path}: {str(e)}")
        return None

def mark_as_duplicate(photo_path):
    retry_operation(lambda: c.execute("UPDATE FileList SET status = 'duplicate' WHERE file_name = ?", (photo_path,)))
    conn.commit()

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

# Move files based on EXIF date, with a fallback to file creation/modification date
def move_file_based_on_exif(photo_path):
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

        # Prevent overwrite by checking for existing files
        target_path = os.path.join(month_dir, os.path.basename(photo_path))
        if os.path.exists(target_path):
            target_path = os.path.join(month_dir, f"{os.path.splitext(os.path.basename(photo_path))[0]}_{int(time.time())}{os.path.splitext(photo_path)[1]}")

        shutil.move(photo_path, target_path)
        logging.info(f"Moved {photo_path} to {target_path}")
    except Exception as e:
        logging.error(f"Error moving photo {photo_path}: {str(e)}")

# Clean up the batch after processing
def clean_up_batch(batch, tmp_dir):
    for file in batch:
        file_path = os.path.join(tmp_dir, file)
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"Deleted file: {file_path}")

def verify_takeout_files(source_dir, tmp_dir, dry_run=True, batch_size=100):
    """
    Function to verify Google Takeout files from archives (.zip and .tgz).
    In dry run mode, it will only extract JSON files for verification.
    In full run mode, it will extract all files (photos and JSON).
    
    Args:
        source_dir (str): The directory containing the Google Takeout archives.
        tmp_dir (str): The temporary directory for extracting files.
        dry_run (bool): Whether to perform a dry run (only extract JSON files).
        batch_size (int): Number of files to process in each batch.
    """
    
    # Create the temp directory if it doesn't exist
    create_directory(tmp_dir)
    
    # List all .zip and .tgz files in the source directory
    archive_files = [f for f in os.listdir(source_dir) if f.endswith(('.zip', '.tgz'))]

    if dry_run:
        logging.info("Running in dry-run mode. Only JSON files will be extracted.")
        print("Dry-run mode: Only JSON files will be extracted.")
    else:
        logging.info("Running full extraction mode.")
        print("Full extraction mode: Photos and JSON files will be processed.")

    # Iterate through each archive
    for archive_file in archive_files:
        archive_path = os.path.join(source_dir, archive_file)
        
        # Perform extraction based on the mode (dry run or full extraction)
        if dry_run:
            extract_json_files_only(archive_path, tmp_dir)
        else:
            extract_full_archive_in_batches(archive_path, tmp_dir, batch_size)


# Main function
def main():
    logging.info('Script started...')
    
    source_dir = 'path_to_takeout_files'
    tmp_dir = 'path_to_tmp_directory'
    global destination_dir
    destination_dir = 'path_to_photos_directory'

    initialize_database()
    backup_database()
    create_google_photos_map()
    verify_takeout_files(source_dir, tmp_dir, dry_run=False, batch_size=100)
    conn.close()

    logging.info('Script completed.')

if __name__ == "__main__":
    main()
