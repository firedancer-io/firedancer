import re
import os
import subprocess
import json
from pathlib import Path
from enum import Enum
from typing import Dict, List, Any

class ClickHouseType(Enum):
    DATETIME_64_9 = 0
    STRING = 1
    ENUM_8 = 2
    LOW_CARDINALITY_STRING = 3
    UINT16 = 4
    UINT32 = 5
    UINT64 = 6
    TUPLE = 7
    NESTED = 8
    IPV6 = 9

class Field:
    def __init__(self, name: str, field: Any):
        self.name = name

        if not 'description' in field:
            raise ValueError(f"Field `{name}` is missing description")

        self.description: str = field['description']

        if self.name.strip() == '':
            raise ValueError("Field name is empty")
        
        if self.description.strip() == '':
            raise ValueError(f"Field `{name}` has empty description")
        
        self.deprecated: bool = False
        if 'deprecated' in field:
            self.deprecated = field['deprecated']

        self.server_only = False
        if 'server_only' in field:
            self.server_only = field['server_only']
        
        if field['type'] == "DateTime64(9)":
            self.type = ClickHouseType.DATETIME_64_9
        elif field['type'] == "String" or field['type'] == "LowCardinality(String)":
            if field['type'] == "String":
                self.type = ClickHouseType.STRING
            else:
                self.type = ClickHouseType.LOW_CARDINALITY_STRING

            self.max_length = None
            if 'max_length' in field:
                self.max_length = int(field['max_length'])
                if field['max_length'] < 1:
                    raise ValueError(f"String field `{name}` has max_length less than 1")
        elif field['type'] == "Enum8":
            self.type = ClickHouseType.ENUM_8

            self.variants: Dict[str, int] = {}
            for (variant, value) in field['variants'].items():
                if variant in self.variants:
                    raise ValueError(f"Duplicate variant {variant}")
                
                if not re.match(r'^[a-z][a-z0-9]*(_[a-z0-9]+)*$', variant):
                    raise ValueError(f"Enum `{name}` variant `{variant}` must contain only lowercase characters and underscores")
                
                if value < -128:
                    raise ValueError(f"Enum `{name}` variant `{variant}` has value less than -128")
                if value > 127:
                    raise ValueError(f"Enum `{name}` variant `{variant}` has value greater than 127")

                self.variants[variant] = value
            if len(self.variants) == 0:
                raise ValueError(f"Enum `{name}` has no variants")
        elif field['type'] == "UInt16":
            self.type = ClickHouseType.UINT16
        elif field['type'] == "UInt32":
            self.type = ClickHouseType.UINT32
        elif field['type'] == "UInt64":
            self.type = ClickHouseType.UINT64
        elif field['type'] == "IPv6":
            self.type = ClickHouseType.IPV6
        elif field['type'] == 'Tuple':
            self.type = ClickHouseType.TUPLE

            self.sub_fields: Dict[str, Field] = {}
            for sub_field in field['fields']:
                if sub_field in self.sub_fields:
                    raise ValueError(f"Duplicate sub-field {sub_field}")
                
                self.sub_fields[sub_field] = Field(sub_field, field['fields'][sub_field])
        elif field['type'] == "Nested":
            self.type = ClickHouseType.NESTED

            self.sub_fields: Dict[str, Field] = {}
            for sub_field in field['fields']:
                if sub_field in self.sub_fields:
                    raise ValueError(f"Duplicate sub-field {sub_field}")
                
                self.sub_fields[sub_field] = Field(sub_field, field['fields'][sub_field])
        else:
            raise ValueError(f"Unknown field type {field['type']}")

class Event:
    def __init__(self, json: Any):
        self.name: str = json['name']
        self.id: int = json['id']
        self.description: str = json['description']
        self.deprecated: bool = False
        if 'deprecated' in json:
            self.deprecated = json['deprecated']

        if not re.match(r'^[a-z][a-z0-9]*(_[a-z0-9]+)*$', self.name):
            raise ValueError(f"Event `{self.name}` must contain only lowercase characters and underscores")

        if self.name.strip() == '':
            raise ValueError("Event name is empty")
        
        if self.description.strip() == '':
            raise ValueError(f"Event `{self.name}` has empty description")
        
        self.fields: Dict[str, Field] = {}
        for (name, field) in json['fields'].items():
            if name in self.fields:
                raise ValueError(f"Duplicate field {name}")

            self.fields[name] = Field(name, field)

def get_files_from_commit(commit: str, directory: Path):
    result = subprocess.run(
        ['git', 'ls-tree', '--name-only', commit, directory],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        raise Exception(f"Error getting files from commit {commit}: {result.stderr}")
    return result.stdout.splitlines()

def load_file_content(commit: str, file_path: str):
    result = subprocess.run(
        ['git', 'show', f'{commit}:{file_path}'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        raise Exception(f"Error loading file {file_path} from commit {commit}: {result.stderr}")
    return json.loads(result.stdout)

def load_current_file_content(file_path: str):
    with open(file_path, 'r') as file:
        return json.load(file)
    
def validate_compatability(before: Dict[str, Event], after: Dict[str, Event]):
    for event in before:
        if event not in after:
            raise ValueError(f"Event `{event}` is missing in new schema")
        
        # id changes don't matter, as they don't make it up to
        # clickhouse
        
        if before[event].deprecated and not after[event].deprecated:
            raise ValueError(f"Event `{event}` is no longer deprecated")
        
        if not before[event].deprecated and after[event].deprecated:
            # Deprecating an event is fine, any other changes are 
            # allowed, as long as the deprecated name remains in
            # place.
            continue

        for field in before[event].fields:
            if field not in after[event].fields:
                raise ValueError(f"Field `{field}` in event `{event}` is missing in new schema")
            
            if before[event].fields[field].deprecated and not after[event].fields[field].deprecated:
                raise ValueError(f"Field `{field}` in event `{event}` is no longer deprecated")
            
            if not before[event].fields[field].deprecated and after[event].fields[field].deprecated:
                # Deprecating a field is fine, any other changes are 
                # allowed, as long as the deprecated name remains in
                # place.
                continue

            if before[event].fields[field].type != after[event].fields[field].type:
                raise ValueError(f"Field `{field}` in event `{event}` has changed type")
            
            # max_length changes are allowed, since schema is an arbitrary length string

            if before[event].fields[field].type == ClickHouseType.ENUM_8:
                for variant in before[event].fields[field].variants:
                    if variant not in after[event].fields[field].variants:
                        raise ValueError(f"Field `{field}` in event `{event}` has missing variant `{variant}`")

                    if before[event].fields[field].variants[variant] != after[event].fields[field].variants[variant]:
                        raise ValueError(f"Field `{field}` in event `{event}` has changed value for variant `{variant}`")
    
def check_schema(schema: Dict[str, Event]):
    for (name, event) in schema.items():
        if event.name != name:
            raise ValueError(f"Event name `{event.name}` does not match the key `{name}`")

        if event.name != 'common' and event.name != 'metrics' and not re.match(r'^[a-z]+_[a-z]+$', event.name):
            raise ValueError(f"Event name `{event.name}` must contain only lowercase characters, and be in the format `{{category}}_{{name}}`")

    if not 'common' in schema:
        raise ValueError("Missing `common` event")

    for event in schema:
        for other in schema:
            if event == other:
                continue
            
            if schema[event].id == schema[other].id:
                raise ValueError(f"Event `{event}` and `{other}` have the same id")
            
    ids: List[int] = []
    for event in schema:
        if event == 'common':
            continue

        ids.append(schema[event].id)

    ids.sort()
    for i in range(1, len(ids)):
        if ids[i] - ids[i - 1] != 1:
            raise ValueError(f"Missing id between {ids[i - 1]} and {ids[i]}")
        
    for event in schema:
        if event == 'common':
            continue

        for field in schema[event].fields.values():
            if field.name in schema['common'].fields:
                raise ValueError(f"Field `{field.name}` in event `{event}` is also present in `common` event")

def check_schema_compatability(ref: str = 'HEAD^'):
    directory = Path(__file__).parent / 'schema'

    parent_commit = subprocess.run(
        ['git', 'rev-parse', ref],
        stdout=subprocess.PIPE,
        text=True
    ).stdout.strip()

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
    check_schema_compatability('origin/main')
