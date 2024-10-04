import os
import shutil
import sqlite3

# Function to compare file quality (e.g., resolution, file size)
def compare_file_quality(file1, file2):
    resolution1 = file1['width'] * file1['height'] if file1['width'] and file1['height'] else 0
    resolution2 = file2['width'] * file2['height'] if file2['width'] and file2['height'] else 0
    
    # Compare resolutions first
    if resolution1 > resolution2:
        return file1
    elif resolution2 > resolution1:
        return file2
    else:
        # If resolution is the same, use file size as a secondary check
        if file1['size'] and file2['size']:
            return file1 if file1['size'] > file2['size'] else file2
        else:
            # If no size or resolution difference, keep file1 by default
            return file1

# Move the lower-quality duplicate to the 'duplicates' directory
def move_to_duplicates_directory(file_info, duplicates_dir):
    try:
        creation_time = os.path.getmtime(file_info['location'])
        year = time.strftime('%Y', time.gmtime(creation_time))
        month = time.strftime('%m', time.gmtime(creation_time))

        final_duplicates_dir = os.path.join(duplicates_dir, year, month)
        if not os.path.exists(final_duplicates_dir):
            os.makedirs(final_duplicates_dir)

        new_path = os.path.join(final_duplicates_dir, os.path.basename(file_info['location']))
        shutil.move(file_info['location'], new_path)

        logging.info(f"Moved file {file_info['location']} to duplicates directory {new_path}")
        return new_path
    except Exception as e:
        logging.error(f"Error moving file {file_info['location']} to duplicates directory: {e}")
        raise

# Function to handle duplicates based on MD5, filename, and creation time
def handle_duplicates(conn, tmp_dir, duplicates_dir):
    try:
        c = conn.cursor()

        # Query the temporary table for MD5 hashes
        c.execute("SELECT file_name, md5_hash, exif_data FROM FileList WHERE status = 'extracted'")
        temp_files = c.fetchall()

        # Check the map and the temporary table for MD5 matches
        for temp_file in temp_files:
            temp_file_name, temp_md5, temp_exif = temp_file
            exif_json_temp = json.loads(temp_exif)

            # Search in both the processed map and the temporary table for MD5 hash matches
            c.execute("""
                SELECT file_name, md5_hash, exif_data, new_location FROM FileList 
                WHERE md5_hash = ? AND status = 'moved';
            """, (temp_md5,))
            map_files = c.fetchall()

            for map_file in map_files:
                map_file_name, map_md5, map_exif, map_location = map_file
                exif_json_map = json.loads(map_exif)

                # Compare resolutions and move the lower quality one
                temp_file_info = {
                    'filename': temp_file_name,
                    'location': os.path.join(tmp_dir, temp_file_name),
                    'width': exif_json_temp.get('ImageWidth'),
                    'height': exif_json_temp.get('ImageHeight'),
                    'size': os.path.getsize(os.path.join(tmp_dir, temp_file_name))
                }

                map_file_info = {
                    'filename': map_file_name,
                    'location': map_location,
                    'width': exif_json_map.get('ImageWidth'),
                    'height': exif_json_map.get('ImageHeight'),
                    'size': os.path.getsize(map_location)
                }

                # Compare file quality and move the lower-quality file
                better_file = compare_file_quality(temp_file_info, map_file_info)
                if better_file == temp_file_info:
                    move_to_duplicates_directory(map_file_info, duplicates_dir)
                    # Update the database to reflect the new location for the duplicate file
                    c.execute("""
                        UPDATE FileList SET status = ?, new_location = ? WHERE file_name = ?;
                    """, ("duplicate_moved", map_file_info['location'], map_file_info['filename']))
                else:
                    move_to_duplicates_directory(temp_file_info, duplicates_dir)
                    c.execute("""
                        UPDATE FileList SET status = ?, new_location = ? WHERE file_name = ?;
                    """, ("duplicate_moved", temp_file_info['location'], temp_file_info['filename']))

        conn.commit()
        logging.info("Processed all duplicates based on MD5 hash, filename, and creation time.")
    except sqlite3.Error as e:
        logging.error(f"Database error during duplicate processing: {e}")
        raise
    except Exception as e:
        logging.error(f"Error processing duplicates: {e}")
        raise
