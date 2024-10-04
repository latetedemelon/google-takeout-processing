import hashlib
import zipfile
import tarfile
import os
import concurrent.futures
import sqlite3

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
