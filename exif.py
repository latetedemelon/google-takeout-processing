from PIL import Image
from PIL.ExifTags import TAGS
import os
import json
import time

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
