# Verify if two files are likely duplicates based on primary checks
def verify_potential_duplicates(file1, file2):
    # Compare filename
    if file1['filename'] != file2['filename']:
        return False
    
    # Compare creation time (both EXIF and Google Photos)
    if file1['creation_time'][:10] != file2['creation_time'][:10]:  # Compare only the date part
        return False

    # If primary checks pass, consider them for further comparison
    return True

# Determine which file is of higher quality based on secondary checks
def compare_file_quality(file1, file2):
    # Compare resolution (width * height)
    resolution1 = file1['width'] * file1['height'] if file1['width'] and file1['height'] else 0
    resolution2 = file2['width'] * file2['height'] if file2['width'] and file2['height'] else 0
    
    # If one resolution is higher, prefer that file
    if resolution1 > resolution2:
        return file1
    elif resolution2 > resolution1:
        return file2
    
    # Compare file size (if available, larger size generally indicates better quality)
    if file1['size'] and file2['size']:
        if file1['size'] > file2['size']:
            return file1
        elif file2['size'] > file1['size']:
            return file2
    
    # If all else fails, default to file1 (first file)
    return file1

# Remove lower quality versions, using primary and secondary checks
def remove_lower_quality_versions(conn, photos_map):
    try:
        c = conn.cursor()

        # Find files with the same filename
        c.execute("""
            SELECT file_name, COUNT(*) as count FROM FileList 
            WHERE status = 'moved' 
            GROUP BY file_name HAVING count > 1;
        """)
        duplicate_filenames = c.fetchall()

        for duplicate in duplicate_filenames:
            file_name, count = duplicate
            logging.info(f"Found {count} versions of {file_name}")

            # Fetch all files with this filename
            c.execute("""
                SELECT file_name, new_location, exif_data FROM FileList 
                WHERE file_name = ? AND status = 'moved';
            """, (file_name,))
            file_versions = c.fetchall()

            # Identify duplicates and use secondary checks to determine which to keep
            verified_duplicates = []
            best_version = None

            for i, version1 in enumerate(file_versions):
                exif_data1 = json.loads(version1[2])
                file1 = {
                    'filename': version1[0],
                    'location': version1[1],
                    'creation_time': exif_data1.get('DateTime', photos_map[version1[0]]['creation_time']),
                    'size': os.path.getsize(version1[1]) if os.path.exists(version1[1]) else None,
                    'width': exif_data1.get('ImageWidth'),
                    'height': exif_data1.get('ImageHeight')
                }

                for version2 in file_versions[i+1:]:
                    exif_data2 = json.loads(version2[2])
                    file2 = {
                        'filename': version2[0],
                        'location': version2[1],
                        'creation_time': exif_data2.get('DateTime', photos_map[version2[0]]['creation_time']),
                        'size': os.path.getsize(version2[1]) if os.path.exists(version2[1]) else None,
                        'width': exif_data2.get('ImageWidth'),
                        'height': exif_data2.get('ImageHeight')
                    }

                    # Primary check: ensure files are potential duplicates
                    if verify_potential_duplicates(file1, file2):
                        # Compare quality using secondary checks
                        higher_quality_file = compare_file_quality(file1, file2)
                        lower_quality_file = file1 if higher_quality_file == file2 else file2
                        
                        # Add the lower-quality version to the list for removal
                        verified_duplicates.append(lower_quality_file)

                        # Update the best version if needed
                        if best_version is None or compare_file_quality(best_version, higher_quality_file) == higher_quality_file:
                            best_version = higher_quality_file

            # Remove verified duplicates
            for duplicate in verified_duplicates:
                remove_file(duplicate['location'])
                c.execute("""
                    DELETE FROM FileList WHERE file_name = ? AND new_location = ?;
                """, (duplicate['filename'], duplicate['location']))

            logging.info(f"Kept the highest-quality version of {file_name} and removed lower-quality duplicates.")

        conn.commit()
        logging.info("Lower quality versions removed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during lower quality file removal: {e}")
        raise
    except Exception as e:
        logging.error(f"Error removing lower quality files: {e}")
        raise

# Helper function to remove a file
def remove_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logging.info(f"File {file_path} removed.")
        else:
            logging.warning(f"File {file_path} not found for removal.")
    except Exception as e:
        logging.error(f"Error removing file {file_path}: {e}")
        raise

# Move duplicates to the parallel 'duplicates' structure instead of deleting
def move_duplicates_to_parallel_structure(conn, photos_map, duplicates_dir):
    try:
        c = conn.cursor()

        # Find files with the same filename
        c.execute("""
            SELECT file_name, COUNT(*) as count FROM FileList 
            WHERE status = 'moved' 
            GROUP BY file_name HAVING count > 1;
        """)
        duplicate_filenames = c.fetchall()

        for duplicate in duplicate_filenames:
            file_name, count = duplicate
            logging.info(f"Found {count} versions of {file_name}")

            # Fetch all files with this filename
            c.execute("""
                SELECT file_name, new_location, exif_data FROM FileList 
                WHERE file_name = ? AND status = 'moved';
            """, (file_name,))
            file_versions = c.fetchall()

            # Identify duplicates and use secondary checks to determine which to keep
            verified_duplicates = []
            best_version = None

            for i, version1 in enumerate(file_versions):
                exif_data1 = json.loads(version1[2])
                file1 = {
                    'filename': version1[0],
                    'location': version1[1],
                    'creation_time': exif_data1.get('DateTime', photos_map[version1[0]]['creation_time']),
                    'size': os.path.getsize(version1[1]) if os.path.exists(version1[1]) else None,
                    'width': exif_data1.get('ImageWidth'),
                    'height': exif_data1.get('ImageHeight')
                }

                for version2 in file_versions[i+1:]:
                    exif_data2 = json.loads(version2[2])
                    file2 = {
                        'filename': version2[0],
                        'location': version2[1],
                        'creation_time': exif_data2.get('DateTime', photos_map[version2[0]]['creation_time']),
                        'size': os.path.getsize(version2[1]) if os.path.exists(version2[1]) else None,
                        'width': exif_data2.get('ImageWidth'),
                        'height': exif_data2.get('ImageHeight')
                    }

                    # Primary check: ensure files are potential duplicates
                    if verify_potential_duplicates(file1, file2):
                        # Compare quality using secondary checks
                        higher_quality_file = compare_file_quality(file1, file2)
                        lower_quality_file = file1 if higher_quality_file == file2 else file2
                        
                        # Add the lower-quality version to the list for moving
                        verified_duplicates.append(lower_quality_file)

                        # Update the best version if needed
                        if best_version is None or compare_file_quality(best_version, higher_quality_file) == higher_quality_file:
                            best_version = higher_quality_file

            # Move verified duplicates to the parallel 'duplicates' directory
            for duplicate in verified_duplicates:
                new_location = move_file_to_duplicates_directory(duplicate['location'], duplicates_dir, duplicate['creation_time'])
                c.execute("""
                    UPDATE FileList SET status = ?, new_location = ?
                    WHERE file_name = ? AND new_location = ?;
                """, ("duplicate_moved", new_location, duplicate['filename'], duplicate['location']))

            logging.info(f"Moved lower-quality duplicates of {file_name} to the duplicates directory.")

        conn.commit()
        logging.info("Lower quality versions moved to duplicates directory successfully.")
    except sqlite3.Error as e:
        logging.error(f"Database error during moving duplicates: {e}")
        raise
    except Exception as e:
        logging.error(f"Error moving duplicates: {e}")
        raise

# Move the file to the parallel 'duplicates' directory, organized by year/month
def move_file_to_duplicates_directory(file_path, duplicates_dir, creation_time):
    try:
        # Extract year and month from the creation time
        if creation_time:
            year = creation_time[:4]
            month = creation_time[5:7]
        else:
            year = 'unknown_year'
            month = 'unknown_month'

        # Create destination path in the duplicates directory
        final_duplicates_dir = os.path.join(duplicates_dir, year, month)
        if not os.path.exists(final_duplicates_dir):
            os.makedirs(final_duplicates_dir)

        # Move the file to the duplicates directory
        new_path = os.path.join(final_duplicates_dir, os.path.basename(file_path))
        shutil.move(file_path, new_path)

        logging.info(f"Moved file {file_path} to duplicates directory {new_path}")
        return new_path
    except Exception as e:
        logging.error(f"Error moving file {file_path} to duplicates directory: {e}")
        raise
