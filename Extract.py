import hashlib
import zipfile
import tarfile
import os
import concurrent.futures
import sqlite3

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
