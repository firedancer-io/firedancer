import json
import os
import subprocess
from pathlib import Path
from typing import Dict
from generate.event_types import Event, check_schema, validate_compatability

def get_files_from_commit(commit: str, directory: Path):
    result = subprocess.run(
        ['git', 'ls-tree', '--name-only', commit, directory],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True
    )
    return result.stdout.decode('utf-8').splitlines()

def load_file_content(commit: str, file_path: str):
    result = subprocess.run(
        ['git', 'show', f'{commit}:{file_path}'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True
    ).stdout.decode('utf-8')
    return json.loads(result)

def load_current_file_content(file_path: str):
    with open(file_path, 'r') as file:
        return json.load(file)

def check_schema_compatability(ref: str):
    directory = Path(__file__).parent / 'schema'

    parent_commit = subprocess.run(
        ['git', 'rev-parse', f'origin/{ref}'],
        stdout=subprocess.PIPE,
        check=True
    ).stdout.strip().decode('utf-8')

    parent_schemas: Dict[str, Event] = {}
    parent_files = get_files_from_commit(parent_commit, directory)
    for file in parent_files:
        if file.endswith('.json'):
            parent_schemas[file[:-5]] = load_file_content(parent_commit, os.path.join(directory, file))

    current_schemas: Dict[str, Event] = {}
    working_directory_files = [
        os.path.relpath(os.path.join(root, file), start=directory)
        for root, _, files in os.walk(directory)
        for file in files
    ]
    for file in working_directory_files:
        if file.endswith('.json'):
            current_schemas[file[:-5]] = load_current_file_content(os.path.join(directory, file))

    check_schema(parent_schemas)
    check_schema(current_schemas)
    validate_compatability(parent_schemas, current_schemas)

if __name__ == "__main__":
    check_schema_compatability(os.environ['GITHUB_BASE_REF'])
