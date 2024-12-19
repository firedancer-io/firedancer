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
    
def validate_field_compatiblity(before: Field, after: Field):
    if before.deprecated and not after.deprecated:
        raise ValueError(f"Field `{before.name}` is no longer deprecated")

    if before.type != after.type:
        raise ValueError(f"Field `{before.name}` has changed type")
    
    if before.type == ClickHouseType.ENUM_8:
        for variant in before.variants:
            if variant not in after.variants:
                raise ValueError(f"Field `{before.name}` has missing variant `{variant}`")

            if before.variants[variant] != after.variants[variant]:
                raise ValueError(f"Field `{before.name}` has changed value for variant `{variant}`")
    elif before.type == ClickHouseType.TUPLE:
        for sub_field in before.sub_fields:
            if sub_field not in after.sub_fields:
                raise ValueError(f"Sub-field `{sub_field}` in field `{before.name}` is missing in new schema")
            
            validate_field_compatiblity(before.sub_fields[sub_field], after.sub_fields[sub_field])
    elif before.type == ClickHouseType.NESTED:
        for sub_field in before.sub_fields:
            if sub_field not in after.sub_fields:
                raise ValueError(f"Sub-field `{sub_field}` in field `{before.name}` is missing in new schema")
            
            validate_field_compatiblity(before.sub_fields[sub_field], after.sub_fields[sub_field])
    
def validate_compatability(before: Dict[str, Event], after: Dict[str, Event]):
    for event in before:
        if event not in after:
            raise ValueError(f"Event `{event}` is missing in new schema")
        
        # id changes don't matter, as they don't make it up to
        # clickhouse
        
        if before[event].deprecated and not after[event].deprecated:
            raise ValueError(f"Event `{event}` is no longer deprecated")

        for field in before[event].fields:
            if field not in after[event].fields:
                raise ValueError(f"Field `{field}` in event `{event}` is missing in new schema")
            
            validate_field_compatiblity(before[event].fields[field], after[event].fields[field])

def check_field(is_nested: bool, field: Field):
    if field.name.strip() == '':
        raise ValueError("Field name is empty")
    
    if field.description.strip() == '':
        raise ValueError(f"Field `{field.name}` has empty description")
    
    if field.type == ClickHouseType.ENUM_8:
        if len(field.variants) == 0:
            raise ValueError(f"Enum `{field.name}` has no variants")
        
        for variant in field.variants:
            if not re.match(r'^[a-z][a-z0-9]*(_[a-z0-9]+)*$', variant):
                raise ValueError(f"Enum `{field.name}` variant `{variant}` must contain only lowercase characters and underscores")
            
            if field.variants[variant] < -128:
                raise ValueError(f"Enum `{field.name}` variant `{variant}` has value less than -128")
            if field.variants[variant] > 127:
                raise ValueError(f"Enum `{field.name}` variant `{variant}` has value greater than 127")
    elif field.type == ClickHouseType.TUPLE:
        for sub_field in field.sub_fields:
            check_field(is_nested, field.sub_fields[sub_field])
    elif field.type == ClickHouseType.NESTED:
        if is_nested:
            raise ValueError(f"Nested fields are not allowed in nested fields")

        for sub_field in field.sub_fields:
            check_field(True, field.sub_fields[sub_field])
    
def check_schema(schema: Dict[str, Event]):
    for (name, event) in schema.items():
        if event.name != name:
            raise ValueError(f"Event name `{event.name}` does not match the key `{name}`")

        if event.name != 'common' and not re.match(r'^[a-z]+_[a-z]+$', event.name):
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
            
            check_field(False, field)
