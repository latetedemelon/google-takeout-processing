# Function to process files in batches with progress updates and summary
def process_in_batches(conn, tmp_dir, destination_dir, duplicates_dir, batch_size=100):
    try:
        c = conn.cursor()

        # Fetch the total number of files to process
        c.execute("SELECT COUNT(*) FROM FileList WHERE status = 'extracted'")
        total_files = c.fetchone()[0]
        logging.info(f"Total files to process: {total_files}")

        # Initialize counters for progress tracking
        files_extracted = 0
        files_processed = 0
        files_organized = 0
        files_deduplicated = 0

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

            # Initialize counters for this batch
            batch_files_processed = 0
            batch_files_organized = 0
            batch_files_deduplicated = 0

            # Process the current batch of files
            for file_record in batch_files:
                file_name, exif_data = file_record
                file_path = os.path.join(tmp_dir, file_name)

                # Step 1: Match files to Google Photos API metadata and move them
                match_and_move_files(conn, tmp_dir, destination_dir, photos_map)
                batch_files_processed += 1

            # Step 2: Handle duplicates after batch processing
            handle_duplicates(conn, tmp_dir, duplicates_dir)
            batch_files_deduplicated += batch_size  # Assuming all duplicates are checked

            # Update the total counters
            files_extracted += batch_size
            files_processed += batch_files_processed
            files_organized += batch_files_organized
            files_deduplicated += batch_files_deduplicated

            # Output a one-line progress update after each batch
            print(f"Batch {batch_num + 1}/{total_batches} | Extracted: {files_extracted} | Processed: {files_processed} | Organized: {files_organized} | Deduplicated: {files_deduplicated}")

        # After all batches are processed, output a summary report
        print(f"\nSUMMARY REPORT:")
        print(f"Total files extracted: {files_extracted}")
        print(f"Total files processed: {files_processed}")
        print(f"Total files organized: {files_organized}")
        print(f"Total files deduplicated: {files_deduplicated}")

        logging.info("Batch processing completed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during batch processing: {e}")
        raise
    except Exception as e:
        logging.error(f"Error during batch processing: {e}")
        raise

# Main function to run the entire script with batch updates
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

        # Step 4: Process files in batches (matching, moving, handling duplicates), with progress updates
        process_in_batches(conn, tmp_dir, destination_dir, duplicates_dir, batch_size)

    finally:
        close_db_connection(conn)
        logging.info("Processing complete.")

if __name__ == "__main__":
    main()
