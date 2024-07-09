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
parser.add_argument("--destination-prefix", default="ci/mainnet/",
                    help="Destination prefix path in the GCS bucket. Ending slash is critical to include.")
parser.add_argument("--fd-frank-ledger", default="/opt/solana/fd_frank_ledger", type=str, help="Path to the fd_frank_ledger executable.")
parser.add_argument("--pages", default=40, type=int, help="Number of pages.")
parser.add_argument("--indexmax", default=5000, type=int, help="Index max.")
parser.add_argument("--poll-interval", default=1, type=float, help="How long to sleep before checking for new directories.")
parser.add_argument('--slack-url', default='', help='If configured, send a message to this Slack webhook URL when a directory is uploaded')
args = parser.parse_args()


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
        "--indexmax", str(indexmax),
        "--copytxnstatus", "false",
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


def process(folder_name, data_dir=args.data_dir, bucket_name=args.bucket_name, tmp_path=args.tmp_path):
    # Extract the slot number from the folder name
    try:
        slot = int(Path(folder_name).parts[-1].split('-')[0])
        print(f"Processing folder: {folder_name} {slot}")
    except:
        # ignore the folders that are not named as slot numbers
        return
    with TemporaryDirectory(dir=tmp_path) as _tmp:
        tmp_dir = Path(_tmp)
        _, snapshot_slot, incremental_slot = find_latest_snapshots(data_dir, slot)

        if rocksdb_minify(data_dir / 'rocksdb', tmp_dir / 'rocksdb', incremental_slot, slot+10):
            print("Failed to minify rocksdb")
            return

        data_to_copy = [
            (tmp_dir / 'rocksdb', 'rocksdb'),
            (data_dir / "genesis*", ''),
            (data_dir / f"snapshot-{snapshot_slot}*tar.zst", ''),
            (data_dir / f"incremental-snapshot-{snapshot_slot}-{incremental_slot}*tar.zst", ''),
        ]

        for src, dst in data_to_copy:
            dst_path = f"gs://{bucket_name}/{folder_name}{dst}"
            print(f"Uploading {src} to {dst_path}")
            upload_parallel(src, dst_path)
            print(f"Uploaded {src} to {dst_path}")

    if args.slack_url:
        client = storage.Client()
        bucket = client.bucket(bucket_name)

        github_job_url_path = f"{folder_name}github_job_url.txt"
        blob = bucket.blob(str(github_job_url_path))
        job_url = blob.download_as_text().strip() if blob.exists() else f'job_url unavailable {github_job_url_path}'

        crash_path = f"{folder_name}gdb.log"
        blob = bucket.blob(str(crash_path))
        crash = blob.download_as_text().strip() if blob.exists() else f''

        send_slack_update(args.slack_url, args.bucket_name, folder_name, job_url, crash)



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


def send_slack_update(url, bucket, destination_path, job_url="", crash=""):
    # payload = {
    #     "text": f"new issue\n{job_url}\n```\ngcloud storage ls gs://{bucket}/{destination_path}\n```\n```{crash}\n```"
    # }
    payload = {
        "text": f"```\ngcloud storage ls gs://{bucket}/{destination_path}\n```"
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
