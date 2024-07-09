#!/usr/bin/env python3

import argparse
import os
import requests
import subprocess
import shutil
from pathlib import Path
from google.cloud import storage
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# we upload like this because the python library does not expose a way to upload a file in parallel which is way, way faster
def upload_parallel(src: Path, dst):
    cmd = [
        "gsutil",
        "-o",
        "GSUtil:parallel_composite_upload_threshold=1",
        "-m",
        "cp",
        "-r",
        src,
        dst,
    ]

    # Execute the command
    print(cmd)
    result = subprocess.run(cmd)

    # Check if the command was executed successfully
    if result.returncode == 0:
        print("Command executed successfully.")
        print("Output:", result.stdout)
        return 0
    else:
        print("Command failed with return code:", result.returncode)
        print("Error Output:", result.stderr)
        return result.returncode



class GCSUploadHandler(FileSystemEventHandler):
    def __init__(self, watch_directory, bucket_name, destination_prefix, url):
        self.watch_directory = watch_directory
        self.bucket_name = bucket_name
        self.destination_prefix = destination_prefix
        self.storage_client = storage.Client()
        self.bucket = self.storage_client.bucket(bucket_name)
        self.url = url

    def on_created(self, event):
        # Only proceed if it's a directory that was created
        if event.is_directory:
            folder_path = event.src_path
            folder_name = os.path.basename(folder_path)
            upload_parallel(folder_path, f"gs://{self.bucket_name}/{self.destination_prefix}/{folder_name}")
            shutil.rmtree(folder_path)  # Delete the directory after upload
            print(f"Uploaded and deleted {folder_name}")

# def send_slack_update(url, bucket, destination_path, job_url=""):
#     payload = {
#         "text": f"new incremental accounts_hash mismatch\n{job_url}\n```\ngcloud storage ls gs://{bucket}/{destination_path}\n```"
#     }
#     print(f'{payload=}')
#     response = requests.post(url, json=payload)
#     if response.status_code == 200:
#         print("Message sent successfully.")
#     else:
#         print(f"Failed to send message. Status code: {response.status_code}, Response: {response.text}")

def main():
    parser = argparse.ArgumentParser(description='Watch a directory and upload new directories to Google Cloud Storage')
    parser.add_argument('--google-application-credentials',
                        default='/etc/firedancer-scratch-bucket-key.json',
                        help='Path to the Google Application Credentials JSON file')
    parser.add_argument('--watch-directory',
                        default=os.path.expanduser('~/bad-slots'),
                        help='Path to the directory to watch for changes')
    parser.add_argument('--bucket-name',
                        default='firedancer-scratch',
                        help='Name of the Google Cloud Storage bucket')
    parser.add_argument('--destination-prefix',
                        default='ci/mainnet',
                        help='Prefix to use for objects in the bucket')
    parser.add_argument('--slack-url',
                        default='',
                        help='If configured, send a message to this Slack webhook URL when a directory is uploaded')
    args = parser.parse_args()

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = args.google_application_credentials

    event_handler = GCSUploadHandler(args.watch_directory, args.bucket_name, args.destination_prefix, args.slack_url)
    observer = Observer()
    observer.schedule(event_handler, args.watch_directory, recursive=False)  # Monitor only the direct children
    observer.start()
    
    print(f"Monitoring {args.watch_directory} for new directories...")
    try:
        observer.join()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()

