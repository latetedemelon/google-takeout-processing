import shutil

# Function to match files with Google Photos API metadata and move them to the final location
def match_and_move_files(conn, tmp_dir, destination_dir, photos_map):
    try:
        c = conn.cursor()

        # Query the temporary table to get all the processed files
        c.execute("SELECT file_name, exif_data FROM FileList WHERE status = 'exif_processed'")
        processed_files = c.fetchall()

        for file_record in processed_files:
            file_name, exif_data = file_record
            file_path = os.path.join(tmp_dir, file_name)

            # Find a match in the Google Photos API map using filename and creation time
            matched_photo_id = None
            for photo_id, photo_data in photos_map.items():
                if file_name == photo_data['filename']:
                    exif_json = json.loads(exif_data)
                    file_creation_time = exif_json.get('DateTime', None)

                    # Match using creation time if available
                    if file_creation_time and photo_data['creation_time'].startswith(file_creation_time[:10]):
                        matched_photo_id = photo_id
                        break
                    elif not file_creation_time:
                        matched_photo_id = photo_id  # Fallback to filename match only

            if matched_photo_id:
                # Move the file to its final destination
                matched_photo = photos_map[matched_photo_id]
                new_location = move_file_to_final_location(file_path, destination_dir, matched_photo, exif_data)
                
                # Generate MD5 hash for the moved file
                md5_hash = generate_md5(new_location)
                
                # Update the database with the new location and status
                c.execute("""
                    UPDATE FileList SET status = ?, new_location = ?, md5_hash = ?
                    WHERE file_name = ?;
                """, ("moved", new_location, md5_hash, file_name))

                logging.info(f"File {file_name} matched with Google Photos metadata and moved to {new_location}")
            else:
                logging.warning(f"No match found for {file_name} in Google Photos API map.")

        conn.commit()
        logging.info(f"All matched files have been moved and the database updated.")
    except sqlite3.Error as e:
        logging.error(f"Database error during file matching and moving: {e}")
        raise
    except Exception as e:
        logging.error(f"Error during file matching and moving: {e}")
        raise

# Move the file to the final destination directory, organized by year/month from EXIF or Google Photos API data
def move_file_to_final_location(file_path, destination_dir, photo_data, exif_data):
    try:
        # Extract year and month from EXIF data first, then fall back on Google Photos metadata if needed
        creation_time = None
        exif_json = json.loads(exif_data)
        if 'DateTime' in exif_json:
            creation_time = exif_json['DateTime']
        else:
            creation_time = photo_data.get('creation_time')

        if creation_time:
            year = creation_time[:4]
            month = creation_time[5:7]
        else:
            year = 'unknown_year'
            month = 'unknown_month'

        # Create destination path based on year/month structure
        final_dir = os.path.join(destination_dir, year, month)
        if not os.path.exists(final_dir):
            os.makedirs(final_dir)

        # Move the file to the final directory
        new_path = os.path.join(final_dir, photo_data['filename'])
        shutil.move(file_path, new_path)

        return new_path
    except Exception as e:
        logging.error(f"Error moving file {file_path} to final location: {e}")
        raise
