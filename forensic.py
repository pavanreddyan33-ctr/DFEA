import hashlib
import os
from datetime import datetime


# Function to calculate SHA-256 hash
def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# Function to extract file metadata
def extract_metadata(file_path):
    stats = os.stat(file_path)

    stored_filename = os.path.basename(file_path)

    # Remove the unique ID added during upload
    if "_" in stored_filename:
        original_filename = stored_filename.split("_", 1)[1]
    else:
        original_filename = stored_filename

    metadata = {
        "File Name": original_filename,
        "File Size": stats.st_size,
        "Created Date": datetime.fromtimestamp(
            stats.st_ctime
        ).strftime("%Y-%m-%d %H:%M:%S"),

        "Modified Date": datetime.fromtimestamp(
            stats.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S"),

        "File Type": os.path.splitext(original_filename)[1]
    }

    return metadata


# Function to verify file integrity
def verify_integrity(original_hash, current_hash):

    if original_hash == current_hash:
        return "VERIFIED"

    else:
        return "MODIFIED"
