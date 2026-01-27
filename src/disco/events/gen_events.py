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

@dataclass
class Schema:
    name: str
    id: int
    description: str
    fields: Dict[str, Field]

def parse_field(f: dict) -> Field:
        return self._TO_PROTO.value[self.name]

def parse_field(f: dict) -> Field:
    fields = None
    if f["type"] == "Flatten":
        fields = {k: parse_field(v) for k, v in f["fields"].items()}

    return Field(
        chtype=ClickHouseType.from_str(f["type"]),
        description=f["description"],
        variants={k: Variant(v["description"]) for k, v in f.get("variants", {}).items()} or None,
        fields=fields
    )

def parse_schema(path: Path) -> Schema:
    data = json.loads(path.read_text())

    fields = {k: parse_field(v) for k, v in data["fields"].items()}
    return Schema(data["name"], data["id"], data["description"], fields)

def collect_nested_messages(schema_name: str, fields: Dict[str, Field], prefix: str = "") -> List[tuple]:
    msgs = []

    for name, f in fields.items():
        if f.chtype == ClickHouseType.Flatten:
            prefix = f"{prefix}{to_pascal_case(name)}"
            msgs.append((f"{to_pascal_case(schema_name)}{prefix}", f.fields, f.description))
            msgs += collect_nested_messages(schema_name, f.fields, prefix)

    return msgs

def generate_message_fields(schema_name: str, fields: Dict[str, Field], prefix: str = "") -> List[str]:
    lines = []

    for i, (name, f) in enumerate(fields.items(), 1):
        if f.chtype == ClickHouseType.Flatten or f.variants:
            proto_type = f"{to_pascal_case(schema_name)}{prefix}{to_pascal_case(name)}"
        else:
            proto_type = f.chtype.to_protobuf_type()
        lines += [f"  // {f.description}", f"  {proto_type} {name} = {i};"]

    return lines

def generate_enums(schema_name: str, fields: Dict[str, Field], prefix: str = "") -> List[str]:
    lines = []
    for name, f in fields.items():
        if f.variants:
            enum = f"{to_pascal_case(schema_name)}{prefix}{to_pascal_case(name)}"
            ep = to_screaming_snake_case(enum)
            lines += [f"// {f.description}", f"enum {enum} {{", f"  {ep}_UNSPECIFIED = 0;"]
            for i, (vn, v) in enumerate(f.variants.items(), 1):
                lines.append(f"  {ep}_{to_screaming_snake_case(vn)} = {i};  // {v.description}")
            lines += ["}", ""]
        if f.chtype == ClickHouseType.Flatten:
            lines += generate_enums(schema_name, f.fields, f"{prefix}{to_pascal_case(name)}")
    return lines

def generate_protobuf(schemas: List[Schema]) -> str:
    lines = ['syntax = "proto3";', "", "package events.v1;", ""]

    for s in schemas:
        lines += generate_enums(s.name, s.fields)

    for s in schemas:
        for msg, flds, desc in reversed(collect_nested_messages(s.name, s.fields)):
            prefix = msg[len(to_pascal_case(s.name)):]
            lines += [f"// {desc}", f"message {msg} {{"] + generate_message_fields(s.name, flds, prefix) + ["}", ""]

    for s in schemas:
        lines += [f"// {s.description}", f"message {to_pascal_case(s.name)} {{"] + generate_message_fields(s.name, s.fields) + ["}", ""]

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

    print("✓ No breaking changes detected")

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate protobuf from JSON schemas")
    parser.add_argument("--skip-check", action="store_true", help="Skip buf breaking changes check")
    args = parser.parse_args()

    schema_dir = Path(__file__).parent / "schema"
    proto_path = schema_dir / "events.proto"

    schemas = sorted([parse_schema(f) for f in schema_dir.glob("*.json")], key=lambda s: s.id)
    proto_path.write_text(generate_protobuf(schemas))

    print(f"✓ Protobuf generated successfully for {len(schemas)} schemas")

    if not args.skip_check:
        check_breaking_changes(schema_dir)

if __name__ == "__main__":
    main()
