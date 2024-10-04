from PIL import Image
from PIL.ExifTags import TAGS
import json

# Extract EXIF data from a file
def extract_exif(file_path):
    exif_data = {}
    try:
        with Image.open(file_path) as img:
            exif_raw = img._getexif()
            if exif_raw is not None:
                exif_data = {TAGS.get(tag, tag): value for tag, value in exif_raw.items()}
        logging.info(f"EXIF data extracted for {file_path}")
    except Exception as e:
        logging.warning(f"Failed to extract EXIF data from {file_path}: {e}")
    
    return exif_data

# Repair EXIF data using Google Photos sidecar data (if EXIF is missing or incomplete)
def repair_exif_from_sidecar(file_path, sidecar_path):
    try:
        with open(sidecar_path, 'r') as f:
            sidecar_data = json.load(f)
            logging.info(f"Sidecar data loaded for {file_path}")
            
        # If EXIF is missing or incomplete, use sidecar data to fill in missing info
        exif_data = extract_exif(file_path)
        
        if 'photoTakenTime' not in exif_data and 'photoTakenTime' in sidecar_data:
            exif_data['DateTime'] = sidecar_data['photoTakenTime']['timestamp']
            logging.info(f"Repaired missing DateTime EXIF for {file_path} using sidecar")
        
        return exif_data
    except Exception as e:
        logging.warning(f"Failed to repair EXIF for {file_path} using sidecar: {e}")
        return None

# Process extracted files for EXIF extraction and repair
def process_exif_for_files(conn, tmp_dir):
    try:
        c = conn.cursor()

        for root, dirs, files in os.walk(tmp_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                sidecar_path = file_path + ".json"  # Assuming the sidecar file is named with the same base filename
                
                # Extract EXIF and repair if needed
                exif_data = extract_exif(file_path)
                
                if not exif_data and os.path.exists(sidecar_path):
                    exif_data = repair_exif_from_sidecar(file_path, sidecar_path)
                
                # Update the database with EXIF data
                if exif_data:
                    c.execute("""
                        UPDATE FileList SET exif_data = ?, status = ?
                        WHERE file_name = ?;
                    """, (json.dumps(exif_data), "exif_repaired", file_name))

        conn.commit()
        logging.info(f"Successfully processed EXIF data and updated the database.")
    except sqlite3.Error as e:
        logging.error(f"Database error while processing EXIF data: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing EXIF data: {e}")
        raise
