import json
import re
from datetime import datetime
import zipfile
import os
import hashlib
import shutil
import sqlite3
import Levenshtein
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import pyexiv2
import logging

# Setup logging
logging.basicConfig(filename='script.log', level=logging.INFO)

# Define the database connection
conn = sqlite3.connect('processing_log.db')
c = conn.cursor()

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
                status TEXT,
                size INTEGER,
                md5_hash TEXT
            )
        """)
def handle_zips(source_dir, tmp_dir):
    os.makedirs(tmp_dir, exist_ok=True)
    zip_files = [f for f in os.listdir(source_dir) if f.endswith('.zip')]
    
    for zip_file in zip_files:
        zip_path = os.path.join(source_dir, zip_file)
        unpack_zip(zip_path, tmp_dir)

def unpack_zip(zip_path, extract_to):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
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
        logging.error(f'Failed to unpack {zip_path}: {error_message}')
    finally:
        with conn:
            c.execute("""
                INSERT INTO ZipProcessing (zip_file, status, error_message)
                VALUES (?, ?, ?)
            """, (zip_path, status, error_message))

def centralize_files(src_dir, dest_dir):
    try:
        files_list = os.listdir(src_dir)
        for file in files_list:
            shutil.move(os.path.join(src_dir, file), os.path.join(dest_dir, file))
        status = 'Success'
        error_message = ''
    except Exception as e:
        status = 'Failed'
        error_message = str(e)
        logging.error(f'Failed to centralize files: {error_message}')
    finally:
        # Assuming every file move is logged into the database
        with conn:
            for file in files_list:
                c.execute("""
                    INSERT INTO FileProcessing (file_name, status, error_message)
                    VALUES (?, ?, ?)
                """, (file, status, error_message))

def generate_file_list(src_dir):
    files_list = os.listdir(src_dir)
    for file in files_list:
        file_path = os.path.join(src_dir, file)
        size = os.path.getsize(file_path)
        md5_hash = generate_hash(file_path)
        status = 'extracted'
        with conn:
            c.execute("""
                INSERT INTO FileList (file_name, status, size, md5_hash)
                VALUES (?, ?, ?, ?)
            """, (file, status, size, md5_hash))

def generate_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
    
def deduplicate_phase_one(dest_dir):
    seen_hashes = {}  # Dictionary to store seen hashes and their corresponding file paths
    files_list = os.listdir(dest_dir)
    for file in files_list:
        file_path = os.path.join(dest_dir, file)
        size = os.path.getsize(file_path)
        md5_hash = generate_hash(file_path)
        if md5_hash in seen_hashes and size == seen_hashes[md5_hash][0]:
            # This is a duplicate
            os.remove(file_path)
            update_file_status(file, 'deleted')
        else:
            seen_hashes[md5_hash] = (size, file_path)
            update_file_status(file, 'centralized')

def deduplicate_phase_two(dest_dir, threshold=0.8):
    files_list = os.listdir(dest_dir)
    checked_files = set()  # Keep track of files that have been checked
    for file in files_list:
        file_path = os.path.join(dest_dir, file)
        size = os.path.getsize(file_path)
        for compare_file in files_list:
            if file != compare_file and compare_file not in checked_files:
                compare_file_path = os.path.join(dest_dir, compare_file)
                compare_size = os.path.getsize(compare_file_path)
                if size == compare_size:
                    similarity = levenshtein_similarity(file, compare_file)
                    if similarity >= threshold:
                        # Files are similar and have the same size, delete the duplicate
                        os.remove(compare_file_path)
                        update_file_status(compare_file, 'deleted')
                        checked_files.add(compare_file)
        checked_files.add(file)

def levenshtein_similarity(s1, s2):
    """Calculate the normalized Levenshtein similarity of two strings."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0  # both strings are empty
    distance = Levenshtein.distance(s1, s2)
    similarity = 1 - distance / max_len
    return similarity


def find_json_sidecar(file_path):
    # Get the directory and base name of the file
    directory, filename = os.path.split(file_path)
    base_name, _ = os.path.splitext(filename)

    # Create a pattern to match the base name of the file in any JSON sidecar file name
    pattern = re.compile(re.escape(base_name) + r'.*\.json$', re.IGNORECASE)

    # Look for matching files in the directory
    for sidecar_name in os.listdir(directory):
        if pattern.match(sidecar_name):
            return os.path.join(directory, sidecar_name)
    
    return None

def extract_date_from_filename(filename):
    # Look for a sequence of 8 digits in the filename
    match = re.search(r'(19|20)\d{6}', filename)
    if match:
        date_string = match.group(1)
        try:
            # Try to convert the 8 digits to a date object
            date_obj = datetime.strptime(date_string, '%Y%m%d')
            # Format the date object to the desired format
            formatted_date = date_obj.strftime('%Y:%m:%d 00:00:00')
            print(f'Date extracted from {filename}: {formatted_date}')
            return formatted_date
        except ValueError:
            # If conversion fails, the 8 digits do not represent a valid date
            print(f'Could not extract date from {filename}')
            pass
    return None

def convert_to_degrees(value):
    # Convert decimal degrees to EXIF format (degree, minute, second)
    degree = int(value)
    minute = int((value - degree) * 60)
    second = ((value - degree - minute/60) * 3600)
    return f"{degree}/1,{minute}/1,{second}/1"

def convert_to_rational(value):
    # Convert decimal to rational (numerator/denominator) for EXIF format
    return f"{int(value * 100)}/100"

def update_exif_data(file_path, new_data):
    metadata = pyexiv2.ImageMetadata(file_path)
    metadata.read()
    for tag, value in new_data.items():
        metadata[tag] = value
    metadata.write()

def process_image_exif(file_path):
    try:
        image = Image.open(file_path)
        exif_data = {TAGS[key]: value for key, value in image._getexif().items() if key in TAGS}
  
        date_taken = exif_data.get('DateTimeOriginal')
        gps_info = exif_data.get('GPSInfo')
      
        json_sidecar_path = find_json_sidecar(file_path)
        json_data = None
      
        if json_sidecar_path:
            with open(json_sidecar_path, 'r') as f:
                json_data = json.load(f)
      
        if not date_taken:
            update_date_exif(file_path, json_data)
    
        if not gps_info:
            update_gps_exif(file_path, json_data)
    except Exception as e:
        logging.error(f'Failed to process EXIF data for {file_path}: {str(e)}')


def update_date_exif(file_path, json_data):
    try:
        new_date = None
    
        if json_data:
            photo_taken_time = json_data.get('photoTakenTime', {}).get('timestamp')
            creation_time = json_data.get('creationTime', {}).get('timestamp')
        
            if photo_taken_time:
                new_date = datetime.utcfromtimestamp(int(photo_taken_time)).strftime('%Y:%m:%d %H:%M:%S')
            elif creation_time:
                new_date = datetime.utcfromtimestamp(int(creation_time)).strftime('%Y:%m:%d %H:%M:%S')
    
        if not new_date:
            new_date = extract_date_from_filename(file_path)
    
        if new_date:
            new_exif_data = {'DateTimeOriginal': new_date}
            update_exif_data(file_path, new_exif_data)
    except Exception as e:
        logging.error(f'Failed to update EXIF data for {file_path}: {str(e)}')

    
def update_gps_exif(file_path, gps_info, json_data):
    if not json_data:
        # Proceed to the next stage
        return
    
    new_gps_data = {}
    geo_data_exif = json_data.get('geoDataExif', {})
    geo_data = json_data.get('geoData', {})
    
   if geo_data_exif.get('latitude') and geo_data_exif.get('longitude'):
        new_gps_data = {
            GPSTAGS['GPSLatitude']: convert_to_degrees(geo_data_exif['latitude']),
            GPSTAGS['GPSLongitude']: convert_to_degrees(geo_data_exif['longitude']),
            GPSTAGS['GPSAltitude']: convert_to_rational(geo_data_exif.get('altitude', 0))
        }
    elif geo_data.get('latitude') and geo_data.get('longitude'):
        new_gps_data = {
            GPSTAGS['GPSLatitude']: convert_to_degrees(geo_data['latitude']),
            GPSTAGS['GPSLongitude']: convert_to_degrees(geo_data['longitude']),
            GPSTAGS['GPSAltitude']: convert_to_rational(geo_data.get('altitude', 0))
        }
    
    if new_gps_data:
        new_exif_data = {'GPSInfo': new_gps_data}
        update_exif_data(file_path, {'GPSInfo': new_exif_data})


def update_file_status(file_name, status):
    with conn:
        c.execute("""
            UPDATE FileList
            SET status = ?
            WHERE file_name = ?
        """, (status, file_name))

def process_files(dest_dir):
    with conn:
        c.execute("SELECT file_name FROM FileList WHERE status != 'deleted'")
        files = c.fetchall()
    for file_tuple in files:
        file_name = file_tuple[0]
        file_path = os.path.join(dest_dir, file_name)
        print(f'Processing {file_name}...')  # User update
        logging.info(f'Processing {file_name}...')
        process_image_exif(file_path)
        update_file_status(file_name, 'processed')
        print(f'{file_name} processed.')  # User update
        logging.info(f'{file_name} processed.')

def main():
    # Main function to execute script
    print('Script started...')  # User update
    logging.info('Script started...')
    source_dir = 'path_to_source'
    destination_dir = 'path_to_destination'
    tmp_dir = os.path.join(destination_dir, 'tmp')
    create_tables()
    handle_zips(source_dir, tmp_dir)
    generate_file_list(tmp_dir)
    centralize_files(tmp_dir, destination_dir)
    deduplicate_phase_one(files_list)
    deduplicate_phase_two(files_list)
    process_files(destination_dir)
    print('Processing completed.')  # User update
    logging.info('Processing completed.')

if __name__ == "__main__":
    main()
