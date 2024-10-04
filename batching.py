# Function to process files in batches
def process_in_batches(conn, tmp_dir, destination_dir, duplicates_dir, batch_size=100):
    try:
        c = conn.cursor()

        # Fetch files in batches
        c.execute("SELECT COUNT(*) FROM FileList WHERE status = 'extracted'")
        total_files = c.fetchone()[0]
        logging.info(f"Total files to process: {total_files}")

        # Calculate the number of batches
        total_batches = (total_files // batch_size) + (1 if total_files % batch_size > 0 else 0)

        for batch_num in range(total_batches):
            # Fetch the next batch of files
            c.execute("""
                SELECT file_name, exif_data FROM FileList 
                WHERE status = 'extracted' LIMIT ? OFFSET ?;
            """, (batch_size, batch_num * batch_size))
            batch_files = c.fetchall()

            if not batch_files:
                break  # No more files to process

            logging.info(f"Processing batch {batch_num + 1} of {total_batches}...")

            # Process the current batch of files
            for file_record in batch_files:
                file_name, exif_data = file_record
                file_path = os.path.join(tmp_dir, file_name)

                # Match files to Google Photos API metadata and move them
                match_and_move_files(conn, tmp_dir, destination_dir, photos_map)

            # After processing, handle duplicates
            handle_duplicates(conn, tmp_dir, duplicates_dir)

        logging.info("Batch processing completed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during batch processing: {e}")
        raise
    except Exception as e:
        logging.error(f"Error during batch processing: {e}")
        raise

# Main function to run the entire script
def main():
    db_path = "path_to_your_database.db"
    token_path = "path_to_your_token.json"
    tmp_dir = "path_to_tmp_directory"
    destination_dir = "path_to_photos_directory"
    duplicates_dir = "path_to_duplicates_directory"
    batch_size = 100  # Number of files to process per batch

    try:
        conn = get_db_connection(db_path)

        # Step 1: Fetch Google Photos metadata and update database
        fetch_and_store_google_photos(conn, token_path)

        # Step 2: Extract and process photos/videos from Takeout archives
        archives = ["path_to_takeout_file1.zip", "path_to_takeout_file2.tgz"]  # Replace with your actual paths
        extract_archives_in_parallel(archives, tmp_dir, conn)

        # Step 3: Process EXIF data
        process_exif_for_files(conn, tmp_dir)

        # Step 4: Process files in batches (matching, moving, handling duplicates)
        process_in_batches(conn, tmp_dir, destination_dir, duplicates_dir, batch_size)

    finally:
        close_db_connection(conn)
        logging.info("Processing complete.")

if __name__ == "__main__":
    main()
