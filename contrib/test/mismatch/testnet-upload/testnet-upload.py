#!/usr/bin/env python3

import argparse
import re
import requests
import subprocess
import time
import os
import shutil
import glob
from pathlib import Path
from google.cloud import storage
from tempfile import TemporaryDirectory

parser = argparse.ArgumentParser(description="Process and upload Solana snapshots.", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--google-application-credentials", default="/etc/firedancer-scratch-bucket-key.json",
                    help="Path to the Google Application Credentials JSON file")
parser.add_argument("--data-dir", default=Path("/data/solana/data"), type=Path,
                    help="Directory containing Solana data")
parser.add_argument("--tmp-path", default=Path("/data/solana"), type=Path,
                    help="Path in which temporary paths are created")
parser.add_argument("--bucket-name", default="firedancer-scratch",
                    help="Google Cloud Storage bucket name")
parser.add_argument("--destination-prefix", default="ci/testnet/",
                    help="Destination prefix path in the GCS bucket. Ending slash is critical to include.")
parser.add_argument("--fd-frank-ledger", default="/opt/solana/fd_frank_ledger", type=str, help="Path to the fd_frank_ledger executable.")
parser.add_argument("--pages", default=40, type=int, help="Number of pages.")
parser.add_argument("--indexmax", default=5000, type=int, help="Index max.")
parser.add_argument("--poll-interval", default=1, type=float, help="How long to sleep before checking for new directories.")
parser.add_argument('--slack-url', default='', help='If configured, send a message to this Slack webhook URL when a directory is uploaded')
args = parser.parse_args()


def copy_glob(pattern: str, target_dir: Path):
    for file_path in glob.glob(str(pattern)):
        filename = os.path.basename(file_path)
        target_path = os.path.join(target_dir, filename)
        shutil.copy(file_path, target_path)
        print(f"Copied {filename} to {target_dir}")


def copy_genesis(source_dir: Path, target_dir: Path):
    copy_glob(source_dir / "genesis*", target_dir)


def copy_snapshot(source_dir: Path, target_dir: Path, slot: int):
    copy_glob(source_dir / f"snapshot-{slot}*tar.zst", target_dir)


def copy_snapshot_incremental(source_dir: Path, target_dir: Path, snapshot_slot: int, incremental_slot: int):
    copy_glob(source_dir / f"incremental-snapshot-{snapshot_slot}-{incremental_slot}*tar.zst", target_dir)


def find_latest_snapshots(data_dir: Path, slot: int):
    incremental_files = []
    pattern = re.compile(r'incremental-snapshot-(\d+)-(\d+)-([A-Za-z0-9]+)\.tar\.zst')

    # List all files in the data directory and filter by the 'incremental' prefix
    for filename in os.listdir(data_dir):
        if pattern.match(filename):
            snapshot_slot = int(filename.split('-')[2])
            incremental_slot = int(filename.split('-')[3])
            if incremental_slot <= slot:
                incremental_files.append((filename, snapshot_slot, incremental_slot))

    if not incremental_files:
        print("No incremental files found within the slot limit.")
        return None

    # Find the file with the largest slot number not exceeding slot
    latest_file, snapshot_slot, incremental_slot = max(incremental_files, key=lambda x: x[2])

    return latest_file, snapshot_slot, incremental_slot


def rocksdb_minify(source_rocksdb, target_rocksdb, startslot, endslot, fd_frank_ledger=args.fd_frank_ledger, pages=args.pages, indexmax=args.indexmax):
    cmd = [
        fd_frank_ledger,
        "--cmd", "minify",
        "--rocksdb", source_rocksdb,
        "--minidb", target_rocksdb,
        "--startslot", str(startslot),
        "--endslot", str(endslot),
        "--pages", str(pages),
        "--indexmax", str(indexmax)
    ]

    # Execute the command
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


def upload_directory(source_path, folder_name, bucket_name=args.bucket_name, destination_prefix=args.destination_prefix):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    github_job_url = ""
    for root, _, files in os.walk(source_path):
        for filename in files:
            local_path = os.path.join(root, filename)
            relative_path = os.path.relpath(local_path, source_path)
            gcs_path = Path(destination_prefix) / folder_name / relative_path

            blob = bucket.blob(str(gcs_path))
            blob.upload_from_filename(local_path)
            print(f"Uploaded {local_path} to gs://{bucket_name}/{gcs_path}")

    if args.slack_url:
        github_job_url_path = Path(destination_prefix) / folder_name / 'github_job_url.txt'
        blob = bucket.blob(str(github_job_url_path))
        job_url = blob.download_as_text().strip() if blob.exists() else f'job_url unavailable {github_job_url_path}'

        send_slack_update(args.slack_url, args.bucket_name, Path(destination_prefix) / folder_name, job_url)


def process(folder_name, data_dir=args.data_dir, tmp_path=args.tmp_path):
    # Extract the slot number from the folder name
    try:
        slot = int(Path(folder_name).parts[-1])
        print(f"Processing folder: {folder_name} {slot}")
    except:
        # ignore the folders that are not named as slot numbers
        return
    with TemporaryDirectory(dir=tmp_path) as _tmp:
        tmp_dir = Path(_tmp)
        _, snapshot_slot, incremental_slot = find_latest_snapshots(data_dir, slot)
        copy_snapshot(data_dir, tmp_dir, snapshot_slot)
        copy_snapshot_incremental(data_dir, tmp_dir, snapshot_slot, incremental_slot)
        copy_genesis(data_dir, tmp_dir)
        if rocksdb_minify(data_dir / 'rocksdb', tmp_dir / 'rocksdb', incremental_slot, slot+10):
            print("Failed to minify rocksdb")
            return
        upload_directory(tmp_dir, str(slot))


def list_immediate_subdirectories(client, bucket_name, prefix):
    bucket = client.bucket(bucket_name)
    iterator = bucket.list_blobs(prefix=prefix, delimiter='/')
    prefixes = set()

    # The iterator's 'prefixes' attribute contains the immediate subdirectory paths
    for page in iterator.pages:
        prefixes.update(page.prefixes)

    return prefixes


def check_for_rocksdb(bucket_name, prefix):
    client = storage.Client()
    subdirectories = []
    for subdirectory in list_immediate_subdirectories(client, bucket_name, prefix):
        # Check if the 'rocksdb' folder exists within this subdirectory
        rocksdb_path = f"{subdirectory}rocksdb/"
        rocksdb_blobs = list(client.list_blobs(bucket_name, prefix=rocksdb_path, max_results=1))
        if not rocksdb_blobs:
            subdirectories.append(subdirectory)
    return subdirectories


def send_slack_update(url, bucket, destination_path, job_url=""):
    payload = {
        "text": f"new bank hash mismatch\n{job_url}\n```\ngcloud storage ls gs://{bucket}/{destination_path}\n```"
    }
    print(f'{payload=}')
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print("Message sent successfully.")
    else:
        print(f"Failed to send message. Status code: {response.status_code}, Response: {response.text}")


def main():
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = args.google_application_credentials
    bucket_name = args.bucket_name
    prefix = args.destination_prefix

    while True:
        dirs_to_process = check_for_rocksdb(bucket_name, prefix)
        for d in dirs_to_process:
            process(d)
        time.sleep(args.poll_interval)

if __name__ == "__main__":
    main()