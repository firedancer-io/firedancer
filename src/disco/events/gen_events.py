#!/usr/bin/env python3
from dataclasses import dataclass, field as dataclass_field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Union
import json

def to_pascal_case(s: str) -> str:
    return "".join(word.capitalize() for word in s.split("_"))

@dataclass
class Variant:
    description: str

@dataclass
class Field:
    type_name: str
    description: str
    variants: Optional[Dict[str, Variant]] = None
    fields: Optional[Dict[str, "Field"]] = None

@dataclass
class Schema:
    name: str
    id: int
    description: str
    fields: Dict[str, Field]

class ClickHouseType(Enum):
    IPv6 = auto()
    UInt8 = auto()
    UInt16 = auto()
    UInt64 = auto()
    String = auto()
    LowCardinalityString = auto()
    Flatten = auto()
    FlattenSum = auto()

    _FROM_STR = {
        "IPv6": "IPv6",
        "UInt8": "UInt8",
        "UInt16": "UInt16",
        "UInt64": "UInt64",
        "String": "String",
        "LowCardinality(String)": "LowCardinalityString",
        "Flatten": "Flatten",
        "FlattenSum": "FlattenSum",
    }

    _TO_PROTO = {
        "IPv6": "bytes",
        "UInt8": "uint32",
        "UInt16": "uint32",
        "UInt64": "uint64",
        "String": "bytes",
        "LowCardinalityString": "string",
        "Flatten": None,
        "FlattenSum": None,
    }

    @classmethod
    def from_str(cls, s: str) -> "ClickHouseType":
        if s not in cls._FROM_STR.value:
            raise ValueError(f"Unsupported ClickHouse type: {s}")
        return cls[cls._FROM_STR.value[s]]

    def to_protobuf_type(self) -> str:
        return self._TO_PROTO.value[self.name]


def parse_field(name: str, f: dict) -> Field:
    """Parse a field, recursively handling Flatten and FlattenSum types."""
    nested_fields = None
    if f["type"] in ("Flatten", "FlattenSum") and "fields" in f:
        nested_fields = {}
        for nested_name, nested_f in f["fields"].items():
            nested_fields[nested_name] = parse_field(nested_name, nested_f)
    
    return Field(
        type_name=f["type"],
        description=f["description"],
        variants={k: Variant(v["description"]) for k, v in f["variants"].items()} if "variants" in f else None,
        fields=nested_fields
    )


def validate_field_types(fields: Dict[str, Field]):
    """Recursively validate all field types."""
    for name, field in fields.items():
        ClickHouseType.from_str(field.type_name)
        if field.fields:
            validate_field_types(field.fields)


def parse_schema(path: Path) -> Schema:
    data = json.loads(path.read_text())
    fields = {}
    for name, f in data["fields"].items():
        fields[name] = parse_field(name, f)
    validate_field_types(fields)
    return Schema(data["name"], data["id"], data["description"], fields)

def to_screaming_snake_case(s: str) -> str:
    """Convert PascalCase or camelCase to SCREAMING_SNAKE_CASE."""
    result = []
    for i, c in enumerate(s):
        if c.isupper() and i > 0:
            result.append('_')
        result.append(c.upper())
    return ''.join(result)


def collect_nested_messages(schema_name: str, fields: Dict[str, Field], prefix: str = "") -> List[tuple]:
    """Collect all nested message definitions from Flatten and FlattenSum fields.
    
    Returns list of (message_name, fields_dict, description) tuples.
    """
    messages = []
    for field_name, field in fields.items():
        if field.type_name in ("Flatten", "FlattenSum") and field.fields:
            msg_name = f"{to_pascal_case(schema_name)}{prefix}{to_pascal_case(field_name)}"
            messages.append((msg_name, field.fields, field.description))
            nested_prefix = f"{prefix}{to_pascal_case(field_name)}"
            messages.extend(collect_nested_messages(schema_name, field.fields, nested_prefix))
    return messages


def generate_message_fields(schema_name: str, fields: Dict[str, Field], prefix: str = "") -> List[str]:
    """Generate protobuf field declarations, handling Flatten and FlattenSum types."""
    lines = []
    field_num = 1
    for field_name, field in fields.items():
        if field.type_name in ("Flatten", "FlattenSum"):
            proto_type = f"{to_pascal_case(schema_name)}{prefix}{to_pascal_case(field_name)}"
        elif field.variants:
            proto_type = f"{to_pascal_case(schema_name)}{prefix}{to_pascal_case(field_name)}"
        else:
            proto_type = ClickHouseType.from_str(field.type_name).to_protobuf_type()
        
        lines.append(f"  // {field.description}")
        lines.append(f"  {proto_type} {field_name} = {field_num};")
        field_num += 1
    return lines


def generate_protobuf(schemas: List[Schema]) -> str:
    lines: List[str] = ["syntax = \"proto3\";", "", "package events.v1;", ""]

    # First pass: generate all enums (including from nested messages)
    for schema in schemas:
        def collect_enums(fields: Dict[str, Field], prefix: str = ""):
            for field_name, field in fields.items():
                if field.variants:
                    enum_name = f"{to_pascal_case(schema.name)}{prefix}{to_pascal_case(field_name)}"
                    enum_prefix = to_screaming_snake_case(enum_name)
                    lines.append(f"// {field.description}")
                    lines.append(f"enum {enum_name} {{")
                    lines.append(f"  // Unspecified")
                    lines.append(f"  {enum_prefix}_UNSPECIFIED = 0;")
                    for i, (variant_name, variant) in enumerate(field.variants.items(), start=1):
                        lines.append(f"  // {variant.description}")
                        lines.append(f"  {enum_prefix}_{to_screaming_snake_case(variant_name)} = {i};")
                    lines.extend(["}", ""])
                if field.type_name in ("Flatten", "FlattenSum") and field.fields:
                    collect_enums(field.fields, f"{prefix}{to_pascal_case(field_name)}")
        collect_enums(schema.fields)

    # Second pass: generate nested messages (bottom-up order)
    for schema in schemas:
        nested = collect_nested_messages(schema.name, schema.fields)
        # Reverse to generate innermost messages first
        for msg_name, msg_fields, msg_desc in reversed(nested):
            lines.append(f"// {msg_desc}")
            lines.append(f"message {msg_name} {{")
            # Find the prefix for this nested message
            prefix = msg_name[len(to_pascal_case(schema.name)):]
            lines.extend(generate_message_fields(schema.name, msg_fields, prefix))
            lines.extend(["}", ""])

    # Third pass: generate top-level messages
    for schema in schemas:
        msg_name = to_pascal_case(schema.name)
        lines.append(f"// {schema.description}")
        lines.append(f"message {msg_name} {{")
        lines.extend(generate_message_fields(schema.name, schema.fields))
        lines.extend(["}", ""])

    lines.extend(["// Combined event type", "message Event {", "  oneof event {"])
    for schema in schemas:
        msg_name = to_pascal_case(schema.name)
        lines.append(f"    {msg_name} {schema.name} = {schema.id};")
    lines.extend(["  }", "}"])

    return "\n".join(lines)

def check_breaking_changes(schema_dir: Path) -> bool:
    """Check for breaking changes using buf. Returns True if compatible."""
    import os
    import shutil
    import subprocess
    
    if os.environ.get("SKIP_BUF_CHECK"):
        print("Skipping buf breaking check (SKIP_BUF_CHECK set)")
        return True
    
    buf_path = shutil.which("buf")
    if not buf_path:
        raise SystemExit("ERROR: buf not found. Install it with: curl -sSL 'https://github.com/bufbuild/buf/releases/download/v1.47.2/buf-Linux-x86_64' -o ~/.local/bin/buf && chmod +x ~/.local/bin/buf")
    
    proto_file = schema_dir / "events.proto"
    if not proto_file.exists():
        return True
    
    repo_root = schema_dir
    while repo_root.parent != repo_root:
        if (repo_root / ".git").exists():
            break
        repo_root = repo_root.parent
    else:
        raise SystemExit("ERROR: Not in a git repo, cannot check for breaking changes")
    
    try:
        rel_path = schema_dir.relative_to(repo_root)
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(rel_path / "events.proto")],
            capture_output=True,
            cwd=repo_root
        )
        if result.returncode != 0:
            print("events.proto not tracked in git yet, skipping compatibility check")
            return True
        
        result = subprocess.run(
            ["git", "show", f"HEAD:{rel_path}/events.proto"],
            capture_output=True,
            cwd=repo_root
        )
        if result.returncode != 0 or len(result.stdout.strip()) == 0:
            print("events.proto is empty or doesn't exist in git HEAD, skipping compatibility check")
            return True
        
        # Run buf breaking check against git HEAD
        # Use the repo root .git and specify the subdir where the proto files are
        result = subprocess.run(
            [buf_path, "breaking", "--against", f"{repo_root}/.git#subdir={rel_path}"],
            capture_output=True,
            text=True,
            cwd=schema_dir
        )
        
        if result.returncode != 0:
            print("ERROR: Breaking changes detected in events.proto:")
            print(result.stdout)
            print(result.stderr)
            return False
        
        print("✓ No breaking changes detected")
        return True
        
    except Exception as e:
        print(f"Warning: Could not check for breaking changes: {e}")
        return True

def main() -> None:
    script_dir = Path(__file__).parent
    schema_dir = script_dir / "schema"
    generated_dir = script_dir / "generated"
    schema_files = sorted(schema_dir.glob("*.json"))
    if not schema_files:
        raise FileNotFoundError(f"No JSON schema files found in {schema_dir}")

    schemas = sorted([parse_schema(p) for p in schema_files], key=lambda s: s.id)
    for s in schemas:
        print(f"✓ {s.name} (id: {s.id}, fields: {len(s.fields)})")

    protobuf = generate_protobuf(schemas)
    
    proto_path = schema_dir / "events.proto"
    old_content = proto_path.read_text() if proto_path.exists() else None
    proto_path.write_text(protobuf)
    
    if old_content is not None and old_content != protobuf:
        if not check_breaking_changes(schema_dir):
            proto_path.write_text(old_content)
            raise SystemExit("Aborting due to breaking changes in events.proto")
    
    # Generate the metric render C code
    metrics_schemas = [s for s in schemas if s.name.startswith("metrics_")]
    metric_render_code = generate_metric_render_c(metrics_schemas)
    render_path = generated_dir / "fd_event_metric_render.c"
    render_path.write_text(metric_render_code)
    print(f"\n✓ Generated {render_path}")


def render_fields_recursive(tile_name: str, fields: Dict[str, Field], indent: int = 2, is_common: bool = False) -> tuple:
    """Recursively render fields to C code, handling nested Flatten/FlattenSum.
    
    Args:
        tile_name: Name of the tile (e.g., "pack")
        fields: Dictionary of fields to render
        indent: Indentation level
        is_common: True if these fields are common tile metrics (inside "tile" Flatten)
    
    Returns (lines, field_num) where lines is list of C code lines and field_num is the
    next field number after all fields have been rendered.
    """
    lines = []
    pad = " " * indent
    field_num = 1
    
    for field_name, field in fields.items():
        if field.type_name in ("Flatten", "FlattenSum") and field.fields:
            nested_is_common = is_common or (field_name == "tile")
            
            lines.append(f"{pad}/* Field {field_num}: {field_name} (submessage) */")
            lines.append(f"{pad}if( FD_UNLIKELY( !fd_pb_submsg_open( enc, {field_num}U ) ) ) return -1;")
            
            nested_lines, _ = render_fields_recursive(tile_name, field.fields, indent, nested_is_common)
            lines.extend(nested_lines)
            
            lines.append(f"{pad}if( FD_UNLIKELY( !fd_pb_submsg_close( enc ) ) ) return -1;")
            field_num += 1
        elif field_name == "kind_id":
            lines.extend([
                f"{pad}if( FD_LIKELY( kind_id ) ) {{",
                f"{pad}  if( FD_UNLIKELY( !fd_pb_push_uint64( enc, {field_num}U, kind_id ) ) ) return -1;",
                f"{pad}}}",
            ])
            field_num += 1
        elif field_name == "sample_id":
            lines.extend([
                f"{pad}if( FD_LIKELY( sample_id ) ) {{",
                f"{pad}  if( FD_UNLIKELY( !fd_pb_push_uint64( enc, {field_num}U, sample_id ) ) ) return -1;",
                f"{pad}}}",
            ])
            field_num += 1
        elif field_name == "sample_reason":
            lines.extend([
                f"{pad}if( FD_LIKELY( sample_reason ) ) {{",
                f"{pad}  if( FD_UNLIKELY( !fd_pb_push_uint32( enc, {field_num}U, sample_reason ) ) ) return -1;",
                f"{pad}}}",
            ])
            field_num += 1
        elif field_name == "sample_slot":
            lines.extend([
                f"{pad}if( FD_LIKELY( sample_slot ) ) {{",
                f"{pad}  if( FD_UNLIKELY( !fd_pb_push_uint64( enc, {field_num}U, sample_slot ) ) ) return -1;",
                f"{pad}}}",
            ])
            field_num += 1
        else:
            metric_type, partial_name = get_tile_metric_parts(tile_name, field_name, is_common)
            lines.append(f"{pad}RENDER( {field_num}U, {metric_type}, {partial_name} );")
            field_num += 1
    
    return lines, field_num


def generate_metric_render_c(schemas: List[Schema]) -> str:
    """Generate fd_event_metric_render.c for rendering metrics to protobuf."""
    lines: List[str] = []
    
    # Header with macros
    lines.extend([
        "/* THIS FILE IS GENERATED BY gen_events.py. DO NOT HAND EDIT. */",
        "",
        "#include \"fd_event_metric_render.h\"",
        "#include \"../../metrics/fd_metrics.h\"",
        "#include \"../../metrics/generated/fd_metrics_all.h\"",
        "#include \"../../../ballet/pb/fd_pb_encode.h\"",
        "",
        "#define RENDER(field_id, type, name) do { \\",
        "    ulong _val = tile_metrics[ FD_METRICS_##type##_##name ]; \\",
        "    if( FD_LIKELY( _val ) ) { \\",
        "      if( FD_UNLIKELY( !fd_pb_push_uint64( enc, (field_id), _val ) ) ) return -1; \\",
        "    } \\",
        "  } while(0)",
        "",
    ])
    
    # Generate the Event oneof field IDs
    for schema in schemas:
        tile_name = schema.name.replace("metrics_", "")
        lines.append(f"#define FD_EVENT_FIELD_{tile_name.upper()} ({schema.id}U)")
    lines.append("")
    
    # Generate individual tile render functions
    for schema in schemas:
        tile_name = schema.name.replace("metrics_", "")
        func_name = f"render_metrics_{tile_name}"
        
        lines.extend([
            f"static int",
            f"{func_name}( fd_pb_encoder_t *      enc,",
            f"{' ' * len(func_name)}  ulong                  sample_id,",
            f"{' ' * len(func_name)}  uint                   sample_reason,",
            f"{' ' * len(func_name)}  ulong                  sample_slot,",
            f"{' ' * len(func_name)}  ulong                  kind_id,",
            f"{' ' * len(func_name)}  ulong volatile const * tile_metrics ) {{",
            "",
        ])
        
        field_lines, _ = render_fields_recursive(tile_name, schema.fields)
        lines.extend(field_lines)
        
        lines.extend([
            "  return 0;",
            "}",
            "",
        ])
    
    lines.extend([
        "long",
        "fd_event_metric_render( fd_topo_t const *      topo,",
        "                        fd_topo_tile_t const * tile,",
        "                        ulong                  sample_id,",
        "                        uint                   sample_reason,",
        "                        ulong                  sample_slot,",
        "                        ulong                  nonce,",
        "                        ulong                  event_id,",
        "                        long                   timestamp_nanos,",
        "                        uchar *                buf,",
        "                        ulong                  buf_sz ) {",
        "  (void)topo;",
        "",
        "  if( FD_UNLIKELY( !tile || !buf || buf_sz<64UL ) ) return -1;",
        "",
        "  char const * tile_name = tile->metrics_name[ 0 ] ? tile->metrics_name : tile->name;",
        "  ulong kind_id = tile->kind_id;",
        "",
        "  ulong volatile const * tile_metrics = fd_metrics_tile( tile->metrics );",
        "  if( FD_UNLIKELY( !tile_metrics ) ) return -1;",
        "",
        "  fd_pb_encoder_t enc[1];",
        "  fd_pb_encoder_init( enc, buf, buf_sz );",
        "",
        "  /* Field 1: nonce */",
        "  if( FD_LIKELY( nonce ) ) {",
        "    if( FD_UNLIKELY( !fd_pb_push_uint64( enc, 1U, nonce ) ) ) return -1;",
        "  }",
        "",
        "  /* Field 2: event_id */",
        "  if( FD_LIKELY( event_id ) ) {",
        "    if( FD_UNLIKELY( !fd_pb_push_uint64( enc, 2U, event_id ) ) ) return -1;",
        "  }",
        "",
        "  /* Field 3: timestamp (Timestamp submessage) */",
        "  if( FD_LIKELY( timestamp_nanos ) ) {",
        "    if( FD_UNLIKELY( !fd_pb_submsg_open( enc, 3U ) ) ) return -1;",
        "    long seconds = timestamp_nanos / 1000000000L;",
        "    int  nanos   = (int)(timestamp_nanos % 1000000000L);",
        "    if( FD_LIKELY( seconds ) ) {",
        "      if( FD_UNLIKELY( !fd_pb_push_int64( enc, 1U, seconds ) ) ) return -1;",
        "    }",
        "    if( FD_LIKELY( nanos ) ) {",
        "      if( FD_UNLIKELY( !fd_pb_push_int32( enc, 2U, nanos ) ) ) return -1;",
        "    }",
        "    if( FD_UNLIKELY( !fd_pb_submsg_close( enc ) ) ) return -1;",
        "  }",
        "",
        "  /* Field 4: event (Event oneof) */",
        "  if( FD_UNLIKELY( !fd_pb_submsg_open( enc, 4U ) ) ) return -1;",
        "",
        "  /* Render based on tile name - dispatch to tile-specific renderer */",
        "  int err = -1;",
    ])
    
    first = True
    for schema in schemas:
        tile_name = schema.name.replace("metrics_", "")
        keyword = "if" if first else "} else if"
        first = False
        lines.extend([
            f"  {keyword}( 0==strcmp( tile_name, \"{tile_name}\" ) ) {{",
            f"    if( FD_UNLIKELY( !fd_pb_submsg_open( enc, FD_EVENT_FIELD_{tile_name.upper()} ) ) ) return -1;",
            f"    err = render_metrics_{tile_name}( enc, sample_id, sample_reason, sample_slot, kind_id, tile_metrics );",
            f"    if( FD_UNLIKELY( !fd_pb_submsg_close( enc ) ) ) return -1;",
        ])
    
    lines.extend([
        "  } else {",
        "    FD_LOG_WARNING(( \"unknown tile name '%s' for event metric rendering\", tile_name ));",
        "    return -1;",
        "  }",
        "",
        "  if( FD_UNLIKELY( err ) ) return -1;",
        "",
        "  /* Close the Event submessage (field 4) */",
        "  if( FD_UNLIKELY( !fd_pb_submsg_close( enc ) ) ) return -1;",
        "",
        "  return (long)fd_pb_encoder_out_sz( enc );",
        "}",
    ])
    
    return "\n".join(lines)


# Cache for tile metric types (populated by scanning header files)
_tile_metric_types: Dict[str, Dict[str, str]] = {}
_common_metric_types: Optional[Dict[str, str]] = None


def _load_common_metric_types() -> Dict[str, str]:
    """Load common tile metric types from fd_metrics_all.h."""
    global _common_metric_types
    if _common_metric_types is not None:
        return _common_metric_types
    
    script_dir = Path(__file__).parent
    header_path = script_dir.parent / "metrics" / "generated" / "fd_metrics_all.h"
    
    if not header_path.exists():
        _common_metric_types = {}
        return {}
    
    import re
    metric_types = {}
    content = header_path.read_text()
    
    # Match patterns like: #define FD_METRICS_GAUGE_TILE_PID_OFF
    pattern = re.compile(r"#define FD_METRICS_(COUNTER|GAUGE)_TILE_([A-Z0-9_]+)_OFF\b")
    for match in pattern.finditer(content):
        metric_type = match.group(1)  # COUNTER or GAUGE
        metric_name = match.group(2)  # e.g., PID
        metric_types[metric_name.lower()] = metric_type
    
    _common_metric_types = metric_types
    return metric_types


def _load_tile_metric_types(tile_name: str) -> Dict[str, str]:
    """Load metric types for a tile from its generated header file."""
    if tile_name in _tile_metric_types:
        return _tile_metric_types[tile_name]
    
    # Find the metrics header file
    script_dir = Path(__file__).parent
    header_path = script_dir.parent / "metrics" / "generated" / f"fd_metrics_{tile_name}.h"
    
    if not header_path.exists():
        _tile_metric_types[tile_name] = {}
        return {}
    
    import re
    metric_types = {}
    content = header_path.read_text()
    
    # Match patterns like: #define FD_METRICS_COUNTER_NET_RX_PKT_CNT_OFF
    pattern = re.compile(rf"#define FD_METRICS_(COUNTER|GAUGE)_{tile_name.upper()}_([A-Z0-9_]+)_OFF\b")
    for match in pattern.finditer(content):
        metric_type = match.group(1)  # COUNTER or GAUGE
        metric_name = match.group(2)  # e.g., RX_PKT_CNT
        metric_types[metric_name.lower()] = metric_type
    
    _tile_metric_types[tile_name] = metric_types
    return metric_types


def get_tile_metric_parts(tile_name: str, field_name: str, is_common: bool) -> tuple:
    """Get (type, partial_name) for a metric.
    
    Args:
        tile_name: Name of the tile (e.g., "pack")
        field_name: Name of the field (e.g., "context_switch_involuntary_count")
        is_common: True if this is a common tile metric (inside "tile" Flatten)
    """
    field_upper = field_name.upper()
    
    if is_common:
        common_types = _load_common_metric_types()
        metric_type = common_types.get(field_name, "COUNTER")
        partial_name = f"TILE_{field_upper}_OFF"
    else:
        metric_types = _load_tile_metric_types(tile_name)
        metric_type = metric_types.get(field_name, "COUNTER")
        partial_name = f"{tile_name.upper()}_{field_upper}_OFF"
    
    return (metric_type, partial_name)


if __name__ == "__main__":
    main()
