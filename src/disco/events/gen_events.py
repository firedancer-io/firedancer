#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional

def to_pascal_case(s: str) -> str:
    return "".join(word.capitalize() for word in s.split("_"))

def to_screaming_snake_case(s: str) -> str:
    result = []
    for i, c in enumerate(s):
        if c.isupper() and i > 0:
            result.append('_')
        result.append(c.upper())
    return ''.join(result)

class ClickHouseType(Enum):
    IPv6 = auto()
    UInt8 = auto()
    UInt16 = auto()
    UInt64 = auto()
    String = auto()
    Bytes = auto()
    LowCardinalityString = auto()
    Flatten = auto()

    _FROM_STR = {
        "IPv6": "IPv6",
        "UInt8": "UInt8",
        "UInt16": "UInt16",
        "UInt64": "UInt64",
        "String": "String",
        "Bytes": "Bytes",
        "LowCardinality(String)": "LowCardinalityString",
        "Flatten": "Flatten",
    }

    _TO_PROTO = {
        "IPv6": "bytes",
        "UInt8": "uint32",
        "UInt16": "uint32",
        "UInt64": "uint64",
        "String": "bytes",
        "Bytes": "bytes",
        "LowCardinalityString": "string",
        "Flatten": None,
    }

    @classmethod
    def from_str(cls, s: str) -> "ClickHouseType":
        if s not in cls._FROM_STR.value:
            raise ValueError(f"Unsupported ClickHouse type: {s}")
        return cls[cls._FROM_STR.value[s]]

    def to_protobuf_type(self) -> str:
        return self._TO_PROTO.value[self.name]

@dataclass
class Variant:
    description: str

@dataclass
class Field:
    chtype: ClickHouseType
    description: str
    variants: Optional[Dict[str, Variant]] = None
    fields: Optional[Dict[str, "Field"]] = None
    shared_name: Optional[str] = None

@dataclass
class Schema:
    name: str
    id: int
    description: str
    fields: Dict[str, Field]

def parse_field(f: dict, shared_types: Dict[str, dict]) -> Field:
    if f["type"].startswith("ref:"):
        field = parse_field(shared_types[f["type"][4:]], shared_types)
        field.shared_name = f["type"][4:]
        return field
    
    fields = None
    if f["type"] == "Flatten":
        fields = {k: parse_field(v, shared_types) for k, v in f["fields"].items()}

    return Field(
        chtype=ClickHouseType.from_str(f["type"]),
        description=f["description"],
        variants={k: Variant(v["description"]) for k, v in f.get("variants", {}).items()} or None,
        fields=fields
    )

def parse_schema(path: Path, shared_types: Dict[str, dict]) -> Schema:
    data = json.loads(path.read_text())

    fields = {k: parse_field(v, shared_types) for k, v in data["fields"].items()}
    return Schema(data["name"], data["id"], data["description"], fields)

def collect_nested_messages(fields: Dict[str, Field], prefix: str = "") -> List[tuple]:
    msgs = []

    for name, f in fields.items():
        if f.chtype == ClickHouseType.Flatten:
            new_prefix = f.shared_name or f"{prefix}{to_pascal_case(name)}"
            msgs.append((new_prefix, f.fields, f.description))
            msgs += collect_nested_messages(f.fields, new_prefix)

    return msgs

def generate_message_fields(fields: Dict[str, Field], prefix: str = "") -> List[str]:
    lines = []

    for i, (name, f) in enumerate(fields.items(), 1):
        if f.chtype == ClickHouseType.Flatten or f.variants:
            proto_type = f.shared_name or f"{prefix}{to_pascal_case(name)}"
        else:
            proto_type = f.chtype.to_protobuf_type()
        lines += [f"  // {f.description}", f"  {proto_type} {name} = {i};"]

    return lines

def generate_enums(fields: Dict[str, Field], prefix: str, generated: set) -> List[str]:
    lines = []
    for name, f in fields.items():
        if f.variants:
            enum = f.shared_name or f"{prefix}{to_pascal_case(name)}"
            if enum in generated:
                continue

            generated.add(enum)
            ep = to_screaming_snake_case(enum)
            lines += [f"// {f.description}", f"enum {enum} {{", f"  {ep}_UNSPECIFIED = 0;"]
            for i, (vn, v) in enumerate(f.variants.items(), 1):
                lines.append(f"  {ep}_{to_screaming_snake_case(vn)} = {i};  // {v.description}")
            lines += ["}", ""]
        if f.chtype == ClickHouseType.Flatten:
            nested_prefix = f.shared_name or nested_prefix = f"{prefix}{to_pascal_case(name)}"
            lines += generate_enums(f.fields, nested_prefix, generated)
    return lines

def generate_protobuf(schemas: List[Schema]) -> str:
    lines = ['syntax = "proto3";', "", "package events.v1;", ""]

    generated_enums = set()
    for s in schemas:
        schema_prefix = to_pascal_case(s.name)
        lines += generate_enums(s.fields, schema_prefix, generated_enums)

    generated_msgs = set()
    for s in schemas:
        schema_prefix = to_pascal_case(s.name)
        for msg, flds, desc in reversed(collect_nested_messages(s.fields, schema_prefix)):
            if msg in generated_msgs:
                continue

            generated_msgs.add(msg)
            lines += [f"// {desc}", f"message {msg} {{"] + generate_message_fields(flds, msg) + ["}", ""]

    for s in schemas:
        schema_prefix = to_pascal_case(s.name)
        lines += [f"// {s.description}", f"message {schema_prefix} {{"] + generate_message_fields(s.fields, schema_prefix) + ["}", ""]

    lines += ["// Combined event type", "message Event {", "  oneof event {"]
    for s in schemas:
        lines.append(f"    {to_pascal_case(s.name)} {s.name} = {s.id};")
    lines += ["  }", "}", ""]

    return "\n".join(lines)

def check_breaking_changes(schema_dir: Path) -> None:
    buf_path: Optional[str] = shutil.which("buf")
    if not buf_path:
        raise SystemExit("ERROR: buf not found. Install it with: curl -sSL 'https://github.com/bufbuild/buf/releases/download/v1.47.2/buf-Linux-x86_64' -o ~/.local/bin/buf && chmod +x ~/.local/bin/buf")

    repo_root: Path = schema_dir.parent.parent.parent.parent
    rel_path = schema_dir.relative_to(repo_root)
    result = subprocess.run(
        [buf_path, "breaking", "--against", f"{repo_root}/.git#subdir={rel_path}"],
        text=True,
        cwd=schema_dir,
        check=True
    )

    print("No breaking changes detected")

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate protobuf from JSON schemas")
    parser.add_argument("--skip-check", action="store_true", help="Skip buf breaking changes check")
    args = parser.parse_args()

    schema_dir = Path(__file__).parent / "schema"
    proto_path = schema_dir / "events.proto"

    shared_types = json.loads((schema_dir / "shared.json").read_text())
    schema_files = [f for f in schema_dir.glob("*.json") if f.name != "shared.json"]
    schemas = sorted([parse_schema(f, shared_types) for f in schema_files], key=lambda s: s.id)
    proto_path.write_text(generate_protobuf(schemas))

    print(f"Protobuf generated successfully from {len(schemas)} schemas")

    if not args.skip_check:
        check_breaking_changes(schema_dir)

if __name__ == "__main__":
    main()
