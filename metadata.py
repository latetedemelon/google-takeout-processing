import sqlite3
import logging
import os
import time
from datetime import datetime
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SCOPES = ['https://www.googleapis.com/auth/photoslibrary.readonly']  # Define your scopes

# Get Google Photos service setup
def get_google_service(token_path):
    try:
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
        service = build('photoslibrary', 'v1', credentials=creds)
        logging.info("Google Photos API service successfully initialized.")
        return service
    except RefreshError as e:
        logging.error("Failed to refresh Google API token. Please check token.json.")
        raise
    except Exception as e:
        logging.error(f"Error setting up Google Photos API service: {e}")
        raise

# Decorator for handling API errors and rate limiting
def handle_api_errors_and_rate_limit(func):
    def wrapper(*args, **kwargs):
        retries = 3
        delay = 2
        for attempt in range(retries):
            try:
                result = func(*args, **kwargs)
                return result
            except HttpError as e:
                if e.resp.status == 429:  # Too many requests (rate limiting)
                    logging.warning(f"Rate limit exceeded. Retrying in {delay * (attempt + 1)} seconds...")
                    time.sleep(delay * (attempt + 1))
                else:
                    logging.error(f"Google Photos API error: {str(e)}")
                    if attempt < retries - 1:
                        time.sleep(delay)
                    else:
                        raise
            except Exception as e:
                logging.error(f"An error occurred: {e}")
                if attempt < retries - 1:
                    time.sleep(delay)
                else:
                    raise
    return wrapper

# Fetch Google Photos albums
@handle_api_errors_and_rate_limit
def fetch_albums(service):
    albums_map = {}
    try:
        next_page_token = None
        while True:
            albums_response = service.albums().list(pageSize=50, pageToken=next_page_token).execute()
            for album in albums_response.get('albums', []):
                albums_map[album['id']] = album['title']
            next_page_token = albums_response.get('nextPageToken')
            if not next_page_token:
                break
        logging.info(f"Fetched {len(albums_map)} albums.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos albums: {e}")
    return albums_map

# Fetch Google Photos metadata
@handle_api_errors_and_rate_limit
def fetch_google_photos_metadata(service):
    photos_map = {}
    albums_map = fetch_albums(service)  # Get album data first
    try:
        next_page_token = None
        while True:
            results = service.mediaItems().list(pageSize=100, pageToken=next_page_token).execute()
            items = results.get('mediaItems', [])
            for item in items:
                photo_data = {
                    'id': item['id'],
                    'filename': item['filename'],
                    'creation_time': item['mediaMetadata']['creationTime'],
                    'mime_type': item['mimeType'],
                    'width': item['mediaMetadata'].get('width'),
                    'height': item['mediaMetadata'].get('height'),
                    'albums': []
                }
                for album_id in item.get('albumIds', []):
                    if album_id in albums_map:
                        photo_data['albums'].append(albums_map[album_id])
                photos_map[item['id']] = photo_data

            next_page_token = results.get('nextPageToken')
            if not next_page_token:
                break

        logging.info(f"Fetched {len(photos_map)} Google Photos items.")
    except Exception as e:
        logging.error(f"Error fetching Google Photos metadata: {e}")
    return photos_map

# Save photo metadata in the database
def save_photos_in_batches(conn, photos_map):
    try:
        c = conn.cursor()
        for photo in photos_map.values():
            c.execute("""
                INSERT OR REPLACE INTO PhotoList (photo_id, filename, creation_time, mime_type, width, height, albums)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (photo["id"], photo["filename"], photo["creation_time"], photo["mime_type"], 
                  photo["width"], photo["height"], ','.join(photo["albums"])))
        
        conn.commit()
        logging.info(f"Successfully saved {len(photos_map)} photos to the database.")
    except sqlite3.Error as e:
        logging.error(f"Error saving photo metadata to database: {e}")
        raise

# Fetch and store photos metadata
def fetch_and_store_google_photos(conn, token_path):
    try:
        # Step 1: Initialize the Google Photos API service
        service = get_google_service(token_path)

        # Step 2: Fetch photo metadata from Google Photos API
        photos_map = fetch_google_photos_metadata(service)

        # Step 3: Save photo metadata to the database in batches
        save_photos_in_batches(conn, photos_map)
        
        logging.info(f"Fetched and mapped {len(photos_map)} photos from Google API.")
        
    except Exception as e:
        logging.error(f"An error occurred during photo metadata fetching and storing: {e}")
        raise

