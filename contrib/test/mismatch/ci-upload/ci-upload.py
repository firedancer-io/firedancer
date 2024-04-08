#!/usr/bin/env python3

import argparse
import os
import requests
import shutil
from google.cloud import storage
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

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
            self.upload_directory(folder_path, folder_name)
            shutil.rmtree(folder_path)  # Delete the directory after upload
            print(f"Uploaded and deleted {folder_name}")

    def upload_directory(self, folder_path, folder_name):
        # Determine the full path for the files on GCS
        destination_path = os.path.join(self.destination_prefix, folder_name)
        github_job_url = ""

        for root, _, files in os.walk(folder_path):
            for filename in files:
                local_path = os.path.join(root, filename)
                relative_path = os.path.relpath(local_path, folder_path)
                gcs_path = os.path.join(destination_path, relative_path)

                blob = self.bucket.blob(gcs_path)
                blob.upload_from_filename(local_path)
                print(f"Uploaded {local_path} to gs://{self.bucket_name}/{gcs_path}")

                if filename == 'github_job_url.txt':
                    with open(local_path, 'r') as file:
                        github_job_url = file.read().strip()

        if self.url and folder_name.startswith('incremental'):
            send_slack_update(self.url, self.bucket_name, destination_path, github_job_url)

def send_slack_update(url, bucket, destination_path, job_url=""):
    payload = {
        "text": f"new incremental accounts_hash mismatch\n{job_url}\n```\ngcloud storage ls gs://{bucket}/{destination_path}\n```"
    }
    print(f'{payload=}')
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print("Message sent successfully.")
    else:
        print(f"Failed to send message. Status code: {response.status_code}, Response: {response.text}")

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
                        default='ci/testnet',
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
