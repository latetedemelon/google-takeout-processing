from PIL import Image
from PIL.ExifTags import TAGS
import json
import os
import logging

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

