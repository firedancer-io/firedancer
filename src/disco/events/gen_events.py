#!/usr/bin/env python3
import argparse
import json
import re
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
    UInt32 = auto()
    UInt64 = auto()
    UInt128 = auto()
    Int64 = auto()
    Pubkey = auto()
    Hash = auto()
    Signature = auto()
    Bool = auto()
    DateTime64 = auto()
    String = auto()
    Bytes = auto()
    LowCardinalityString = auto()
    Flatten = auto()
    Tuple = auto()
    Array = auto()

    _FROM_STR = {
        "IPv6": "IPv6",
        "UInt8": "UInt8",
        "UInt16": "UInt16",
        "UInt32": "UInt32",
        "UInt64": "UInt64",
        "UInt128": "UInt128",
        "Int64": "Int64",
        "Pubkey": "Pubkey",
        "Hash": "Hash",
        "Signature": "Signature",
        "Bool": "Bool",
        "DateTime64(9)": "DateTime64",
        "String": "String",
        "Bytes": "Bytes",
        "LowCardinality(String)": "LowCardinalityString",
        "Flatten": "Flatten",
        "Tuple": "Tuple",
        "Array": "Array",
    }

    _TO_PROTO = {
        "IPv6": "bytes",
        "UInt8": "uint32",
        "UInt16": "uint32",
        "UInt32": "uint32",
        "UInt64": "uint64",
        "UInt128": "bytes",
        "Int64": "sint64",
        "Pubkey": "bytes",
        "Hash": "bytes",
        "Signature": "bytes",
        "Bool": "bool",
        "DateTime64": "uint64",
        "String": "bytes",
        "Bytes": "bytes",
        "LowCardinalityString": "string",
        "Flatten": None,
        "Tuple": None,
        "Array": None,
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
    element: Optional["Field"] = None
    shared_name: Optional[str] = None
    max_len: Optional[int] = None
    dynamic: bool = False  # Array only: stored at the end of the C struct and
                           # shipped to the event tile at its used length
                           # rather than max_len capacity

@dataclass
class Schema:
    name: str
    id: int
    description: str
    fields: Dict[str, Field]
    internal: bool = False  # produced on the dedicated internal link and consumed
                            # in-process: C struct plus pack/unpack helpers only, no
                            # protobuf, no event tile dispatch, no ClickHouse column

_FIELD_KEYS = {"type", "description", "variants", "fields", "element", "max_len", "dynamic", "compression"}
_SCHEMA_KEYS = {"name", "id", "description", "fields", "internal"}

def parse_field(f: dict, shared_types: Dict[str, dict]) -> Field:
    unknown = set(f) - _FIELD_KEYS
    if unknown:
        raise ValueError(f"Unknown field keys (typo?): {sorted(unknown)}")
    if f["type"].startswith("ref:"):
        field = parse_field(shared_types[f["type"][4:]], shared_types)
        field.shared_name = f["type"][4:]
        return field

    fields = None
    if f["type"] in ("Flatten", "Tuple"):
        fields = {k: parse_field(v, shared_types) for k, v in f["fields"].items()}

    element = parse_field(f["element"], shared_types) if f["type"] == "Array" else None

    if f.get("dynamic") and f["type"] != "Array":
        raise ValueError("'dynamic' is only supported on Array fields")

    compression = f.get("compression")
    if compression is not None:
        if compression not in ("Delta, ZSTD", "DoubleDelta, ZSTD", "T64, ZSTD"):
            raise ValueError(f"Unsupported compression: {compression!r}")
        int_types = ("UInt8", "UInt16", "UInt32", "UInt64", "Int64")
        allowed = int_types if compression.startswith("T64") else int_types + ("DateTime64(9)",)
        if f["type"] not in allowed:
            raise ValueError(f"Compression {compression!r} not applicable to column type {f['type']}")

    # Variant keys become protobuf enum identifiers and, on the server,
    # upper-camel-cased Rust identifiers; restrict them so they can never
    # collide with either grammar or the server's reserved __unknown
    # sentinel (whose identifier is deliberately un-camel-caseable).
    for k in f.get("variants", {}):
        if not re.fullmatch(r"[a-z][a-z0-9_]*", k):
            raise ValueError(f"Invalid variant key {k!r}: must match [a-z][a-z0-9_]*")
        if k == "unspecified":
            raise ValueError("Variant key 'unspecified' is reserved: the generator emits <ENUM>_UNSPECIFIED = 0")

    return Field(
        chtype=ClickHouseType.from_str(f["type"]),
        description=f["description"],
        variants={k: Variant(v["description"]) for k, v in f.get("variants", {}).items()} or None,
        fields=fields,
        element=element,
        max_len=f.get("max_len"),
        dynamic=bool(f.get("dynamic")),
    )

def parse_schema(path: Path, shared_types: Dict[str, dict]) -> Schema:
    data = json.loads(path.read_text())
    unknown = set(data) - _SCHEMA_KEYS
    if unknown:
        raise ValueError(f"{path.name}: unknown schema keys (typo?): {sorted(unknown)}")
    fields = {k: parse_field(v, shared_types) for k, v in data["fields"].items()}
    schema = Schema(data["name"], data["id"], data["description"], fields, bool(data.get("internal")))
    if schema.internal:
        check_internal_schema(schema)
    return schema

def check_internal_schema(s: Schema) -> None:
    """An internal schema travels as a fixed prefix followed by the used entries
    of each dynamic array, so every variable-length field has to be such an
    array: an inline Bytes/String buffer or a max_len-sized Array would put
    worst-case capacity in the prefix, which for these schemas is megabytes."""
    for name, f in s.fields.items():
        if not field_is_supported(f):
            raise ValueError(f"{s.name}.{name}: type not supported by the C codegen")
        if f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
            raise ValueError(f"{s.name}.{name}: internal schemas carry bytes as a dynamic Array")
        if f.chtype == ClickHouseType.Array and not f.dynamic:
            raise ValueError(f"{s.name}.{name}: arrays of an internal schema must be dynamic")
    if not any(f.dynamic for f in s.fields.values()):
        raise ValueError(f"{s.name}: an internal schema needs at least one dynamic array")

def collect_nested_messages(fields: Dict[str, Field], prefix: str = "") -> List[tuple]:
    msgs = []

    for name, f in fields.items():
        inner = f.element if f.chtype == ClickHouseType.Array else f
        if inner.chtype in (ClickHouseType.Flatten, ClickHouseType.Tuple):
            new_prefix = inner.shared_name or f"{prefix}{to_pascal_case(name)}"
            msgs.append((new_prefix, inner.fields, inner.description))
            msgs += collect_nested_messages(inner.fields, new_prefix)

    return msgs

def generate_message_fields(fields: Dict[str, Field], prefix: str = "") -> List[str]:
    lines = []

    for i, (name, f) in enumerate(fields.items(), 1):
        inner = f.element if f.chtype == ClickHouseType.Array else f
        if inner.chtype in (ClickHouseType.Flatten, ClickHouseType.Tuple) or inner.variants:
            proto_type = inner.shared_name or f"{prefix}{to_pascal_case(name)}"
        else:
            proto_type = inner.chtype.to_protobuf_type()
        label = "repeated " if f.chtype == ClickHouseType.Array else ""
        lines += [f"  // {f.description}", f"  {label}{proto_type} {name} = {i};"]

    return lines

def generate_enums(fields: Dict[str, Field], prefix: str, generated: set) -> List[str]:
    lines = []
    for name, f in fields.items():
        inner = f.element if f.chtype == ClickHouseType.Array else f
        if inner.variants:
            enum = inner.shared_name or f"{prefix}{to_pascal_case(name)}"
            if enum in generated:
                continue

            generated.add(enum)
            ep = to_screaming_snake_case(enum)
            lines += [f"// {inner.description}", f"enum {enum} {{", f"  {ep}_UNSPECIFIED = 0;"]
            for i, (vn, v) in enumerate(inner.variants.items(), 1):
                lines.append(f"  {ep}_{to_screaming_snake_case(vn)} = {i};  // {v.description}")
            lines += ["}", ""]
        if inner.chtype in (ClickHouseType.Flatten, ClickHouseType.Tuple):
            nested_prefix = inner.shared_name or f"{prefix}{to_pascal_case(name)}"
            lines += generate_enums(inner.fields, nested_prefix, generated)
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

_FIXED_BYTE_SZ = {
    ClickHouseType.IPv6:      16,
    ClickHouseType.Pubkey:    32,
    ClickHouseType.Hash:      32,
    ClickHouseType.Signature: 64,
}

_SCALAR_C = {
    ClickHouseType.UInt8:      ("uchar",  "uint32"),
    ClickHouseType.UInt16:     ("ushort", "uint32"),
    ClickHouseType.UInt32:     ("uint",   "uint32"),
    ClickHouseType.UInt64:     ("ulong",  "uint64"),
    ClickHouseType.UInt128:    ("uint128", "bytes"),
    ClickHouseType.Int64:      ("long",   "sint64"),
    ClickHouseType.DateTime64: ("ulong",  "uint64"),
    ClickHouseType.Bool:       ("int",    "bool"),
}

def field_is_supported(f: Field) -> bool:
    """Whether the C codegen can emit a fixed-size struct + serializer for a
    field.  Variable-length types (Bytes/String/Array) are supported only when
    bounded by max_len.  An enum (LowCardinality(String)) is supported only at
    the top level and only with variants: variant-less enums have no C
    representation, and nested enums would get proto enums but no C value
    defines.  Tuple/Flatten subfields and non-Tuple Array elements are limited
    to what the emitters actually handle: scalar or fixed-byte (a shape
    outside this set previously passed the gate and then crashed the emitters
    with a raw KeyError)."""
    _NON_LEAF = (ClickHouseType.String, ClickHouseType.Bytes,
                 ClickHouseType.Flatten, ClickHouseType.Tuple, ClickHouseType.Array)
    _SUB_UNSUPPORTED = _NON_LEAF + (ClickHouseType.LowCardinalityString,)
    if f.chtype == ClickHouseType.LowCardinalityString:
        return f.variants is not None
    if f.chtype in (ClickHouseType.String, ClickHouseType.Bytes):
        return f.max_len is not None
    if f.chtype in (ClickHouseType.Flatten, ClickHouseType.Tuple):
        return all(sf.chtype not in _SUB_UNSUPPORTED and sf.variants is None
                   for sf in f.fields.values())
    if f.chtype == ClickHouseType.Array:
        if f.max_len is None:
            return False
        el = f.element
        if el.chtype in (ClickHouseType.Flatten, ClickHouseType.Tuple):
            return field_is_supported(el)
        return el.chtype not in _SUB_UNSUPPORTED and el.variants is None
    return True  # scalar or fixed-byte type

def schema_is_supported(s: Schema) -> bool:
    return all(field_is_supported(f) for f in s.fields.values())

# Protobuf wire-format max sizes (mirrors src/ballet/pb/fd_pb_wire.h).
_PB_TAG_MAX     = 5   # fd_pb_varint32_sz_max (a tag is a varint32)
_PB_VARINT32    = 5   # fd_pb_varint32_sz_max
_PB_VARINT64    = 10  # fd_pb_varint64_sz_max
_PB_BOOL        = 1   # fd_pb_bool_max_sz
_PB_LP_RESERVE  = 5   # length-prefix reserved by fd_pb_lp_open (fd_pb_varint32_sz_max)
# The encoder bounds-checks with a conservative 32-byte slack (see
# fd_pb_encoder_init docs); pad the buffer so a tight message never trips it.
_PB_ENCODER_SLACK = 32

def scalar_max_encoded_sz(f: Field) -> int:
    """Worst-case encoded bytes for a single (non-array) field value, including
    its tag.  For Tuple, this is the submessage (tag + length-prefix + body)."""
    if f.variants:                       # enum -> int32 varint
        return _PB_TAG_MAX + _PB_VARINT32
    if f.chtype in _FIXED_BYTE_SZ:       # fixed bytes: tag + length-prefix + data
        return _PB_TAG_MAX + _PB_VARINT32 + _FIXED_BYTE_SZ[f.chtype]
    if f.chtype == ClickHouseType.UInt128: # 16 bytes little-endian, length-prefixed
        return _PB_TAG_MAX + _PB_VARINT32 + 16
    if f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
        return _PB_TAG_MAX + _PB_VARINT32 + f.max_len
    if f.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
        body = sum(scalar_max_encoded_sz(sf) for sf in f.fields.values())
        return _PB_TAG_MAX + _PB_LP_RESERVE + body
    suffix = _SCALAR_C[f.chtype][1]
    if suffix == "bool":                    return _PB_TAG_MAX + _PB_BOOL
    if suffix in ("uint64", "sint64"):      return _PB_TAG_MAX + _PB_VARINT64
    return _PB_TAG_MAX + _PB_VARINT32    # uint32 (UInt8/UInt16)

def field_max_encoded_sz(f: Field) -> int:
    """Worst-case encoded bytes for one struct field (tag + value), accounting
    for arrays via their max_len bound."""
    if f.chtype == ClickHouseType.Array:
        return f.max_len * scalar_max_encoded_sz(f.element)
    return scalar_max_encoded_sz(f)

def event_buf_max(s: Schema) -> int:
    """Conservative upper bound on the encoded size of a whole event (tags
    modeled at worst-case varint width; real tags are 1-2 bytes) (envelope +
    Event submsg + inner submsg + all fields), padded for encoder slack."""
    # Envelope: 4 uint64 fields (nonce, event_id, link_seq, timestamp_nanos).
    envelope = 4 * (_PB_TAG_MAX + _PB_VARINT64)
    # Two submessage openers (Event, then the specific event): each is a
    # tag plus a reserved length-prefix.
    submsgs = 2 * (_PB_TAG_MAX + _PB_LP_RESERVE)
    fields = sum(field_max_encoded_sz(f) for f in s.fields.values())
    return envelope + submsgs + fields + _PB_ENCODER_SLACK

def event_buf_max_define(s: Schema) -> str:
    return to_screaming_snake_case(f"fd_event_{s.name}_buf_max")

def c_enum_value(schema_name: str, field_name: str, variant: str) -> str:
    return to_screaming_snake_case(f"fd_event_{schema_name}_{field_name}_{variant}")

def c_tuple_name(schema_name: str, field_name: str) -> str:
    """C struct type name for a Tuple field (or an Array-of-Tuple element)."""
    return f"fd_event_{schema_name}_{field_name}_t"

def tuple_fields_of(f: Field) -> Optional[Dict[str, Field]]:
    """If f (or its array element) is a Tuple/Flatten, return its fields."""
    inner = f.element if f.chtype == ClickHouseType.Array else f
    if inner.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
        return inner.fields
    return None

def gen_tuple_struct( schema_name: str, field_name: str, flds: Dict[str, Field], desc: str, dynamic: bool = False ) -> List[str]:
    """Emit a C struct definition for a Tuple field's element type.  Tuple
    subfields are themselves restricted to fixed-length scalar/enum/fixed-byte
    types (no nested arrays/bytes), which covers current schemas."""
    tn = c_tuple_name( schema_name, field_name )
    members = []
    for sn, sf in flds.items():
        if sf.variants:
            ctype, decl = "int", sn
        elif sf.chtype in _FIXED_BYTE_SZ:
            ctype, decl = "uchar", f"{sn}[ {_FIXED_BYTE_SZ[sf.chtype]}UL ]"
        else:
            ctype, decl = _SCALAR_C[sf.chtype][0], sn
        members.append((ctype, decl, sf.description))
    tw = max(len(c) for c, _, _ in members)
    dw = max(len(d) for _, d, _ in members)
    out = [f"/* {desc} */", f"struct {tn[:-2]} {{"]
    for ctype, decl, d in members:
        out.append(f"  {ctype:<{tw}} {decl + ';':<{dw + 1}} /* {d} */")
    out += ["} __attribute__((aligned(8)));" if dynamic else "};", f"typedef struct {tn[:-2]} {tn};", ""]
    return out

def serializer_signature(s: Schema, terminator: str) -> List[str]:
    """Emit the fd_event_<name>_serialize signature, type-column aligned, with
    continuation lines indented under the first parameter.  terminator is the
    text after the final parameter (e.g. ' );' for a prototype, ' ) {' for a
    definition)."""
    fn   = f"fd_event_{s.name}_serialize( "
    pad  = " " * len(fn)
    params = [
        ("fd_circq_t *",                       "circq"),
        ("fd_event_client_t *",                "client"),
        ("long",                               "timestamp_nanos"),
        ("ulong",                              "link_seq"),
        (f"fd_event_{s.name}_t const *",       "msg"),
    ]
    tw = max(len(t) for t, _ in params)
    out = [f"void", f"{fn}{params[0][0]:<{tw}} {params[0][1]},"]
    for t, n in params[1:-1]:
        out.append(f"{pad}{t:<{tw}} {n},")
    t, n = params[-1]
    out.append(f"{pad}{t:<{tw}} {n}{terminator}")
    return out

def generate_c_header(schemas: List[Schema]) -> str:
    eligible = [s for s in schemas if schema_is_supported(s)]
    lines = [
        "/* THIS FILE WAS GENERATED BY gen_events.py. DO NOT EDIT BY HAND! */",
        "#ifndef HEADER_fd_src_disco_events_generated_fd_event_gen_h",
        "#define HEADER_fd_src_disco_events_generated_fd_event_gen_h",
        "",
        "#include <stddef.h> /* offsetof */",
        "",
        '#include "../fd_circq.h"',
        '#include "../fd_event_client.h"',
        '#include "../fd_event_report.h"',
        "",
    ]


    # Enum #defines, structs, and per-event buffer sizes.
    for s in eligible:
        # Enums for LowCardinality(String) fields.  Values match the proto
        # enum (variants numbered from 1); the proto's mandatory
        # _UNSPECIFIED=0 sentinel is not emitted on the C side.
        for name, f in s.fields.items():
            if not f.variants:
                continue
            names = [c_enum_value(s.name, name, vn) for vn in f.variants]
            w = max(len(n) for n in names)
            lines.append(f"/* {f.description} */")
            for i, (vn, v) in enumerate(f.variants.items(), 1):
                lines.append(f"#define {c_enum_value(s.name, name, vn):<{w}} ({i}) /* {v.description} */")
            lines += [""]

        # Nested Tuple element structs (emitted before the main struct that
        # references them).
        for name, f in s.fields.items():
            tflds = tuple_fields_of( f )
            if tflds is not None:
                inner = f.element if f.chtype == ClickHouseType.Array else f
                lines += gen_tuple_struct( s.name, name, tflds, inner.description, f.dynamic )

        # Main struct.  Each field becomes one or more members:
        #   scalar/enum/fixed-byte -> single member
        #   Bytes/String(max_len)  -> uchar <name>[max_len]; ulong <name>_len;
        #   Tuple                  -> <tuple_t> <name>;
        #   Array(max_len)         -> <elem-decl>[max_len]; ulong <name>_cnt;
        # Arrays tagged "dynamic" are placed at the end of the struct (their
        # _cnt stays in the prefix) so the event can travel to the event tile
        # packed: prefix bytes followed by each dynamic array's used entries,
        # instead of full max_len capacity.
        def array_elem_decl(name, f):
            el = f.element
            if el.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
                return (c_tuple_name( s.name, name ), f"{name}[ {f.max_len}UL ]")
            if el.variants:
                return ("int", f"{name}[ {f.max_len}UL ]")
            if el.chtype in _FIXED_BYTE_SZ:
                return ("uchar", f"{name}[ {f.max_len}UL ][ {_FIXED_BYTE_SZ[el.chtype]}UL ]")
            return (_SCALAR_C[el.chtype][0], f"{name}[ {f.max_len}UL ]")

        members     = []  # (ctype, decl, desc) prefix members
        dyn_members = []  # (ctype, decl, desc) trailing dynamic arrays
        dyn_names   = [n for n, f in s.fields.items() if f.dynamic]
        for name, f in s.fields.items():
            if f.dynamic:
                ectype, decl = array_elem_decl( name, f )
                members.append(("ulong", f"{name}_cnt", f"Number of {name} entries (<= {f.max_len})"))
                dyn_members.append((ectype, decl, f.description + " (dynamic: stored at end, shipped at used length)"))
            elif f.variants:
                members.append(("int", name, f.description))
            elif f.chtype in _FIXED_BYTE_SZ:
                members.append(("uchar", f"{name}[ {_FIXED_BYTE_SZ[f.chtype]}UL ]", f.description))
            elif f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
                members.append(("uchar", f"{name}[ {f.max_len}UL ]", f.description))
                members.append(("ulong", f"{name}_len", f"Length of {name} (<= {f.max_len})"))
            elif f.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
                members.append((c_tuple_name( s.name, name ), name, f.description))
            elif f.chtype == ClickHouseType.Array:
                ectype, decl = array_elem_decl( name, f )
                members.append((ectype, decl, f.description))
                members.append(("ulong", f"{name}_cnt", f"Number of {name} entries (<= {f.max_len})"))
            else:
                members.append((_SCALAR_C[f.chtype][0], name, f.description))
        all_members = members + dyn_members
        tw = max(len(c) for c, _, _ in all_members)
        dw = max(len(d) for _, d, _ in all_members)
        lines += [f"/* {s.description} */", "struct fd_event_" + s.name + " {"]
        for ctype, decl, desc in all_members:
            lines.append(f"  {ctype:<{tw}} {decl + ';':<{dw + 1}} /* {desc} */")
        lines += ["};", f"typedef struct fd_event_{s.name} fd_event_{s.name}_t;", ""]

        # Dynamic-event support: the fixed prefix ends at the first dynamic
        # array member.  On the wire the event is the prefix followed by each
        # dynamic array's used entries (in declaration order), so the fixed
        # prefix of a packed event aliases the struct layout directly.
        if dyn_names:
            first = dyn_names[0]
            up = s.name.upper()
            lines += [
                f"#define FD_EVENT_{up}_PREFIX_SZ (offsetof(fd_event_{s.name}_t, {first}))",
                "",
            ]
            # Capacity of each dynamic array, so producers can clamp against
            # the real bound rather than a constant that might drift from it.
            for dn in dyn_names:
                lines += [f"#define FD_EVENT_{up}_{dn.upper()}_MAX ({s.fields[dn].max_len}UL)"]
            lines += [""]
            # 8-aligned record sizes keep the packed tail at natural
            # alignment and make max fill equal the struct size; the assert
            # name identifies the offending schema and field.
            for dn in dyn_names:
                lines += [f"FD_STATIC_ASSERT( sizeof(((fd_event_{s.name}_t *)0)->{dn}[0])%8UL==0UL, {s.name}_{dn}_align );"]
            lines += [
                "",
                f"/* Packed (wire) footprint of a {s.name} event: prefix plus used",
                "   dynamic array entries.  msg may point at a full struct or at a",
                "   packed event's prefix. */",
                "static inline ulong",
                f"fd_event_{s.name}_footprint( fd_event_{s.name}_t const * msg ) {{",
                f"  return FD_EVENT_{up}_PREFIX_SZ",
            ] + [
                f"       + msg->{dn}_cnt*sizeof(((fd_event_{s.name}_t *)0)->{dn}[0])"
                for dn in dyn_names
            ] + [
                "       ;",
                "}",
                "",
            ]

        # Conservative upper bound on this event's encoded size.
        lines += [
            f"/* Worst-case encoded size of a {s.name} event (envelope + Event",
            "   submsg + inner submsg + all fields, padded for encoder slack). */",
            f"#define {event_buf_max_define(s)} ({event_buf_max(s)}UL)",
            "",
        ]

    # Max sizeof over all generated event structs.  A sizeof-union stays O(n)
    # in the schema count; a nested ternary fold doubles per schema.
    if eligible:
        members = " ".join(f"fd_event_{s.name}_t {s.name}_;" for s in eligible)
        lines += [
            "/* Largest generated event struct; a consumer can stage any incoming",
            "   event in a buffer of this size, aligned to",
            "   FD_EVENT_GEN_STRUCT_ALIGN. */",
            f"#define FD_EVENT_GEN_STRUCT_MAX   (sizeof (union {{ {members} }}))",
            f"#define FD_EVENT_GEN_STRUCT_ALIGN (alignof(union {{ {members} }}))",
            "",
        ]

    # Serializer prototypes.
    lines += ["FD_PROTOTYPES_BEGIN", ""]
    for s in eligible:
        lines += [
            f"/* Serialize a {s.name} event into the circq, reserving an event id",
            "   from the client and writing the standard event envelope.  Mirrors",
            "   the hand-written fd_pb_* path. */",
        ] + serializer_signature( s, " );" ) + [""]

    # Dispatch by event type id (the frag sig set by fd_event_report_*).
    lines += [
        "/* Serialize an event of the given type id (the schema id carried in the",
        "   report frag's sig) from a fully-formed fd_event_<name>_t at ev. */",
        "void",
        "fd_event_serialize_by_type( ulong               type,",
        "                            fd_circq_t *        circq,",
        "                            fd_event_client_t * client,",
        "                            long                timestamp_nanos,",
        "                            ulong               link_seq,",
        "                            void const *        ev,",
        "                            ulong               ev_sz );",
        "",
    ]

    # Per-event report helpers: type-safe wrappers over fd_event_report_ that
    # ship a fully-formed event struct to the event tile via the thread-local
    # reporter.  No-op when the calling tile has no event link.  Schemas with
    # dynamic arrays are shipped packed (prefix + used entries of each dynamic
    # array) via the gather variant, so typical events consume only their
    # actual footprint of dcache rather than max_len capacity.
    for s in eligible:
        dyn_names = [n for n, f in s.fields.items() if f.dynamic]
        up = s.name.upper()
        lines += [
            f"/* FD_EVENT_{up}_ID is the type of a {s.name} event on an event link",
            "   (FD_EVENT_SIG_TYPE of its frag). */",
            f"#define FD_EVENT_{up}_ID ({s.id}UL)",
            "",
        ]
        if not dyn_names:
            lines += [
                f"/* Report a {s.name} event ({to_pascal_case(s.name)}, id {s.id}) to the event tile via",
                "   the thread-local reporter (no-op when the tile has no event link). */",
                "static inline void",
                f"fd_event_report_{s.name}( fd_event_{s.name}_t const * msg ) {{",
                f"  fd_event_report_( FD_EVENT_{up}_ID, msg, sizeof(fd_event_{s.name}_t) );",
                "}",
                "",
            ]
        else:
            iovs = [f"    {{ (void const *)msg, FD_EVENT_{up}_PREFIX_SZ }},"]
            for dn in dyn_names:
                iovs.append(f"    {{ (void const *)msg->{dn}, msg->{dn}_cnt*sizeof(msg->{dn}[0]) }},")
            lines += [
                f"/* Report a {s.name} event ({to_pascal_case(s.name)}, id {s.id}) to the event tile via",
                "   the thread-local reporter (no-op when the tile has no event link).",
                "   The event travels packed: fixed prefix followed by the used entries",
                "   of each dynamic array. */",
                "static inline void",
                f"fd_event_report_{s.name}( fd_event_{s.name}_t const * msg ) {{",
            ] + [
                f"  FD_TEST( msg->{dn}_cnt<={f.max_len}UL );" for dn, f in s.fields.items() if f.dynamic
            ] + [
                "  fd_event_report_iov_t iov[] = {",
            ] + iovs + [
                "  };",
                f"  fd_event_report_gather_( FD_EVENT_{up}_ID, iov, sizeof(iov)/sizeof(iov[0]) );",
                "}",
                "",
            ]

    lines += ["FD_PROTOTYPES_END", "", "#endif", ""]
    return "\n".join(lines)

def encode_scalar( f: Field, field_id: int, acc: str, ind: str, omit_default: bool ) -> List[str]:
    """Emit the fd_pb_push_* line for a scalar/enum/fixed-byte field.  acc is
    the C accessor expression for the value.  omit_default skips zero scalars
    (proto3 default); fixed-byte fields are always emitted."""
    if f.variants:
        guard = f"if( {acc} ) " if omit_default else ""
        return [f"{ind}{guard}ok &= !!fd_pb_push_int32 ( encoder, {field_id}U, {acc} );"]
    if f.chtype in _FIXED_BYTE_SZ:
        return [f"{ind}ok &= !!fd_pb_push_bytes ( encoder, {field_id}U, {acc}, {_FIXED_BYTE_SZ[f.chtype]}UL );"]
    if f.chtype == ClickHouseType.UInt128:
        guard = f"if( {acc} ) " if omit_default else ""
        return [f"{ind}{guard}ok &= !!fd_pb_push_bytes ( encoder, {field_id}U, (uchar const *)&{acc}, 16UL );"]
    suffix = _SCALAR_C[f.chtype][1]
    cast   = "(ulong)" if suffix == "uint64" else ("(uint)" if suffix == "uint32" else "")
    guard  = f"if( {acc} ) " if omit_default else ""
    return [f"{ind}{guard}ok &= !!fd_pb_push_{suffix:<6}( encoder, {field_id}U, {cast}{acc} );"]

def encode_tuple( f: Field, field_id: int, acc: str, ind: str ) -> List[str]:
    """Emit a submessage encoding a Tuple value at field_id.  acc is the C
    accessor for the tuple struct (e.g. 'msg->x' or 'msg->arr[ k ]')."""
    out = [f"{ind}ok &= !!fd_pb_submsg_open( encoder, {field_id}U );"]
    for j, (sn, sf) in enumerate(f.fields.items(), 1):
        out += encode_scalar( sf, j, f"{acc}.{sn}", ind, omit_default=True )
    out += [f"{ind}ok &= !!fd_pb_submsg_close( encoder );"]
    return out

def encode_field( f: Field, field_id: int, name: str, acc: str, ind: str ) -> List[str]:
    """Emit encode lines for one struct field of any supported type."""
    if f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
        return [f"{ind}if( {acc}_len ) ok &= !!fd_pb_push_bytes ( encoder, {field_id}U, {acc}, {acc}_len );"]
    if f.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
        return encode_tuple( f, field_id, acc, ind )
    if f.chtype == ClickHouseType.Array:
        el  = f.element
        out = [f"{ind}for( ulong k=0UL; k<{acc}_cnt; k++ ) {{"]
        if el.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
            out += encode_tuple( el, field_id, f"{acc}[ k ]", ind + "  " )
        else:
            # Scalar/enum/fixed-byte array element: always emit (do not omit
            # defaults - each element is a distinct repeated entry).
            out += encode_scalar( el, field_id, f"{acc}[ k ]", ind + "  ", omit_default=False )
        out += [f"{ind}}}"]
        return out
    return encode_scalar( f, field_id, acc, ind, omit_default=True )

def generate_c_source(schemas: List[Schema]) -> str:
    eligible = [s for s in schemas if schema_is_supported(s)]
    lines = [
        "/* THIS FILE WAS GENERATED BY gen_events.py. DO NOT EDIT BY HAND! */",
        '#include "fd_event_gen.h"',
        '#include "../../../ballet/pb/fd_pb_encode.h"',
        "",
    ]
    for s in eligible:
        bufmax = event_buf_max_define(s)
        lines += serializer_signature( s, " ) {" ) + [
            f"  uchar * buffer = fd_circq_push_back( circq, 1UL, {bufmax} );",
            "  FD_TEST( buffer );",
            "",
            "  ulong event_id = fd_event_client_id_reserve( client );",
            "",
            "  fd_pb_encoder_t encoder[1];",
            f"  fd_pb_encoder_init( encoder, buffer, {bufmax} );",
            "",
            "  /* Pushes fail (returning NULL) rather than overflow; accumulate so",
            f"     a {bufmax} that under-models the encoder aborts loudly instead",
            "     of silently truncating fields off published rows. */",
            "  int ok = 1;",
            "",
            "  FD_TEST( circq->cursor_push_seq );",
            "  ok &= !!fd_pb_push_uint64( encoder, 1U, circq->cursor_push_seq-1UL );",
            "  ok &= !!fd_pb_push_uint64( encoder, 2U, event_id );",
            "  ok &= !!fd_pb_push_uint64( encoder, 3U, link_seq );",
            "  ok &= !!fd_pb_push_uint64( encoder, 4U, (ulong)timestamp_nanos );",
            "",
        ]
        # Bound the variable-length fields against the generated struct
        # capacity before any encoder loop dereferences them, so a caller that
        # sets *_len / *_cnt above capacity is caught rather than reading OOB.
        bound_checks = []
        for name, f in s.fields.items():
            if f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
                bound_checks.append(f"  FD_TEST( msg->{name}_len<={f.max_len}UL );")
            elif f.chtype == ClickHouseType.Array:
                bound_checks.append(f"  FD_TEST( msg->{name}_cnt<={f.max_len}UL );")
        if bound_checks:
            lines += bound_checks + [""]
        # Dynamic arrays arrive packed after the fixed prefix (see the report
        # helper): compute their base pointers by walking from the prefix end
        # in declaration order.  Also works for a full in-memory struct only
        # if it was packed first; serializers only ever see packed events.
        dyn_names = [n for n, f in s.fields.items() if f.dynamic]
        if dyn_names:
            up = s.name.upper()
            lines += [f"  uchar const * _dyn = (uchar const *)msg + FD_EVENT_{up}_PREFIX_SZ;"]
            for dn in dyn_names:
                f  = s.fields[dn]
                el = f.element
                if el.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
                    ct = c_tuple_name( s.name, dn ) + " const *"
                elif el.variants:
                    ct = "int const *"
                elif el.chtype in _FIXED_BYTE_SZ:
                    ct = f"uchar const (*)[ {_FIXED_BYTE_SZ[el.chtype]}UL ]"
                else:
                    ct = _SCALAR_C[el.chtype][0] + " const *"
                if "(*)" in ct:
                    lines += [f"  uchar const (* {dn})[ {_FIXED_BYTE_SZ[el.chtype]}UL ] = (uchar const (*)[ {_FIXED_BYTE_SZ[el.chtype]}UL ])_dyn;"]
                    lines += [f"  _dyn += msg->{dn}_cnt*{_FIXED_BYTE_SZ[el.chtype]}UL;"]
                else:
                    lines += [f"  {ct} {dn} = ({ct})_dyn;"]
                    lines += [f"  _dyn += msg->{dn}_cnt*sizeof({dn}[0]);"]
                lines += [f"  ulong {dn}_cnt = msg->{dn}_cnt;"]
            lines += [""]
        lines += [
            "  ok &= !!fd_pb_submsg_open( encoder, 5U ); /* Event */",
            f"  ok &= !!fd_pb_submsg_open( encoder, {s.id}U ); /* {to_pascal_case(s.name)} */",
        ]
        # Encode each field.  proto3 omits scalar fields at their default
        # (0/false) - skipped here (a conformant reader reconstructs the
        # default).  Fixed-byte fields are always emitted (a 32-byte hash is
        # meaningful content, not the empty `bytes` default).  Dynamic arrays
        # are accessed via the packed-tail locals declared above.
        for i, (name, f) in enumerate(s.fields.items(), 1):
            acc = name if f.dynamic else f"msg->{name}"
            lines += encode_field( f, i, name, acc, "  " )
        lines += [
            "  ok &= !!fd_pb_submsg_close( encoder );",
            "  ok &= !!fd_pb_submsg_close( encoder );",
            "  FD_TEST( ok );",
            "  fd_circq_resize_back( circq, fd_pb_encoder_out_sz( encoder ) );",
            "}",
            "",
        ]

    # Dispatch by event type id.
    lines += [
        "void",
        "fd_event_serialize_by_type( ulong               type,",
        "                            fd_circq_t *        circq,",
        "                            fd_event_client_t * client,",
        "                            long                timestamp_nanos,",
        "                            ulong               link_seq,",
        "                            void const *        ev,",
        "                            ulong               ev_sz ) {",
        "  switch( type ) {",
    ]
    for s in eligible:
        dyn_names = [n for n, f in s.fields.items() if f.dynamic]
        if not dyn_names:
            lines += [
                f"  case {s.id}UL:",
                f"    FD_TEST( ev_sz==sizeof(fd_event_{s.name}_t) );",
                f"    fd_event_{s.name}_serialize( circq, client, timestamp_nanos, link_seq, (fd_event_{s.name}_t const *)ev );",
                "    break;",
            ]
        else:
            # Packed event: validate the size against the footprint implied by
            # the prefix's counts before touching the dynamic tail.
            up = s.name.upper()
            lines += [
                f"  case {s.id}UL: {{",
                f"    FD_TEST( ev_sz>=FD_EVENT_{up}_PREFIX_SZ );",
                f"    fd_event_{s.name}_t const * msg = (fd_event_{s.name}_t const *)ev;",
            ] + [
                f"    FD_TEST( msg->{dn}_cnt<={f.max_len}UL );" for dn, f in s.fields.items() if f.dynamic
            ] + [
                f"    FD_TEST( ev_sz==fd_event_{s.name}_footprint( msg ) );",
                f"    fd_event_{s.name}_serialize( circq, client, timestamp_nanos, link_seq, msg );",
                "    break;",
                "  }",
            ]
    lines += [
        '  default: FD_LOG_ERR(( "unexpected event type %lu", type ));',
        "  }",
        "}",
        "",
    ]
    return "\n".join(lines)

_CTYPE_MAX = { "ulong": "ULONG_MAX", "long": "LONG_MAX", "uint": "UINT_MAX",
               "int": "INT_MAX", "ushort": "USHORT_MAX", "uchar": "UCHAR_MAX",
               "uint128": "(uint128)-1" }

def fill_scalar( f: Field, acc: str, ind: str ) -> List[str]:
    """Emit lines setting a scalar/enum/fixed-byte field to the value with the
    largest encoded width its C type allows (bounded by the model width)."""
    if f.variants:
        # Widest legal enum varint (5 bytes, matching the int32 model bound;
        # negative enums, which would encode wider, cannot occur).
        return [f"{ind}{acc} = INT_MAX;"]
    if f.chtype in _FIXED_BYTE_SZ:
        return [f"{ind}fd_memset( {acc}, 0xFF, {_FIXED_BYTE_SZ[f.chtype]}UL );"]
    if _SCALAR_C[f.chtype][1] == "bool":
        return [f"{ind}{acc} = 1;"]
    return [f"{ind}{acc} = {_CTYPE_MAX[_SCALAR_C[f.chtype][0]]};"]

def fill_field( f: Field, acc: str, ind: str ) -> List[str]:
    """Emit max-fill lines for one struct field of any supported type,
    mirroring encode_field's shapes."""
    if f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
        return [f"{ind}fd_memset( {acc}, 0xFF, {f.max_len}UL );",
                f"{ind}{acc}_len = {f.max_len}UL;"]
    if f.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
        out = []
        for sn, sf in f.fields.items():
            out += fill_scalar( sf, f"{acc}.{sn}", ind )
        return out
    if f.chtype == ClickHouseType.Array:
        el  = f.element
        out = [f"{ind}{acc}_cnt = {f.max_len}UL;",
               f"{ind}for( ulong k=0UL; k<{f.max_len}UL; k++ ) {{"]
        if el.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
            for sn, sf in el.fields.items():
                out += fill_scalar( sf, f"{acc}[ k ].{sn}", ind + "  " )
        else:
            out += fill_scalar( el, f"{acc}[ k ]", ind + "  " )
        out += [f"{ind}}}"]
        return out
    return fill_scalar( f, acc, ind )

def generate_c_test_header(schemas: List[Schema]) -> str:
    eligible = [s for s in schemas if schema_is_supported(s)]
    lines = [
        "/* THIS FILE WAS GENERATED BY gen_events.py. DO NOT EDIT BY HAND! */",
        "#ifndef HEADER_fd_src_disco_events_generated_fd_event_gen_test_h",
        "#define HEADER_fd_src_disco_events_generated_fd_event_gen_test_h",
        "",
        "/* Test-only: per-event fillers that set every field to the value with",
        "   the largest encoded width the BUF_MAX model allows, so a unit test",
        "   can drive the real serializer at the modeled worst case (see",
        "   test_events.c). */",
        "",
        '#include "fd_event_gen.h"',
        "",
        "FD_PROTOTYPES_BEGIN",
        "",
    ]
    for s in eligible:
        lines += [
            "static inline void",
            f"fd_event_{s.name}_fill_max( fd_event_{s.name}_t * msg ) {{",
            "  fd_memset( msg, 0, sizeof(*msg) );",
        ]
        for name, f in s.fields.items():
            lines += fill_field( f, f"msg->{name}", "  " )
        lines += [
            "}",
            "",
            "static void",
            f"fd_event_{s.name}_fill_max_v( void * msg ) {{ fd_event_{s.name}_fill_max( (fd_event_{s.name}_t *)msg ); }}",
            "",
        ]
    lines += [
        "typedef struct {",
        "  ulong        type;    /* event schema id */",
        "  ulong        buf_max; /* modeled encode bound */",
        "  ulong        ev_sz;   /* struct size; == packed footprint at max fill (dynamic arrays are declared at max_len and their record sizes are 8-aligned, so no padding drifts) */",
        "  char const * name;",
        "  void       (*fill_max)( void * msg );",
        "} fd_event_gen_test_case_t;",
        "",
        "static const fd_event_gen_test_case_t fd_event_gen_test_cases[] = {",
    ]
    for s in eligible:
        lines.append(f'  {{ {s.id}UL, {event_buf_max_define(s)}, sizeof(fd_event_{s.name}_t), "{s.name}", fd_event_{s.name}_fill_max_v }},')
    lines += [
        "};",
        "",
        f"#define FD_EVENT_GEN_TEST_CASE_CNT ({len(eligible)}UL)",
        "",
        "FD_PROTOTYPES_END",
        "",
        "#endif",
        "",
    ]
    return "\n".join(lines)

def internal_elem_type(schema_name: str, field_name: str, f: Field) -> tuple:
    """(C type name of one array entry, sizeof expression, 1 if the entry is an
    array type and therefore needs a pointer-to-array declarator)."""
    el = f.element
    if el.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
        tn = c_tuple_name( schema_name, field_name )
        return (tn, f"sizeof({tn})", 0)
    if el.variants:
        return ("int", "sizeof(int)", 0)
    if el.chtype in _FIXED_BYTE_SZ:
        n = _FIXED_BYTE_SZ[el.chtype]
        return (f"uchar [ {n}UL ]", f"{n}UL", 1)
    ct = _SCALAR_C[el.chtype][0]
    return (ct, f"sizeof({ct})", 0)

def internal_ptr_decl(schema_name: str, field_name: str, f: Field) -> str:
    tn, _, is_arr = internal_elem_type( schema_name, field_name, f )
    if is_arr:
        base, dim = tn.split( " ", 1 )
        return f"{base} const (* {field_name}){dim}"
    return f"{tn} const * {field_name}"

def internal_ptr_cast(schema_name: str, field_name: str, f: Field) -> str:
    tn, _, is_arr = internal_elem_type( schema_name, field_name, f )
    if is_arr:
        base, dim = tn.split( " ", 1 )
        return f"({base} const (*){dim})"
    return f"({tn} const *)"

def generate_c_internal_header(schemas: List[Schema]) -> str:
    """Emit the C side of the internal schemas: the fixed prefix struct, the
    bounds of each dynamic array, a parts view (prefix plus one pointer per
    array), the packed footprint, the chunked publish helper and the unpack
    helper a consumer validates a received record with."""
    lines = [
        "/* THIS FILE WAS GENERATED BY gen_events.py. DO NOT EDIT BY HAND! */",
        "#ifndef HEADER_fd_src_disco_events_generated_fd_event_internal_gen_h",
        "#define HEADER_fd_src_disco_events_generated_fd_event_internal_gen_h",
        "",
        "/* Internal records travel on the dedicated internal link, from a",
        "   producer tile to one in-process consumer, as a fixed prefix",
        "   followed by the used entries of each dynamic array, each array",
        "   region padded to 8 bytes so every entry is naturally aligned.",
        "   They have no protobuf representation and the event tile never",
        "   sees them. */",
        "",
        "#include <stddef.h> /* offsetof */",
        "",
        '#include "../fd_event_report.h"',
        "",
        "FD_PROTOTYPES_BEGIN",
        "",
    ]

    for s in schemas:
        up       = s.name.upper()
        dyn      = [(n, f) for n, f in s.fields.items() if f.dynamic]

        # Enum #defines, matching the public generator's numbering.
        for name, f in s.fields.items():
            if not f.variants:
                continue
            names = [c_enum_value(s.name, name, vn) for vn in f.variants]
            w = max(len(n) for n in names)
            lines.append(f"/* {f.description} */")
            for i, (vn, v) in enumerate(f.variants.items(), 1):
                lines.append(f"#define {c_enum_value(s.name, name, vn):<{w}} ({i}) /* {v.description} */")
            lines += [""]

        # Element structs of the Tuple arrays.
        for name, f in s.fields.items():
            tflds = tuple_fields_of( f )
            if tflds is not None:
                inner = f.element if f.chtype == ClickHouseType.Array else f
                lines += gen_tuple_struct( s.name, name, tflds, inner.description )

        members = []
        for name, f in s.fields.items():
            if f.dynamic:
                members.append(("ulong", f"{name}_cnt", f"Number of {name} entries (<= {f.max_len})"))
            elif f.variants:
                members.append(("int", name, f.description))
            elif f.chtype in _FIXED_BYTE_SZ:
                members.append(("uchar", f"{name}[ {_FIXED_BYTE_SZ[f.chtype]}UL ]", f.description))
            elif f.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
                members.append((c_tuple_name( s.name, name ), name, f.description))
            else:
                members.append((_SCALAR_C[f.chtype][0], name, f.description))
        tw = max(len(c) for c, _, _ in members)
        dw = max(len(d) for _, d, _ in members)
        lines += [f"/* {s.description} */", f"struct fd_event_{s.name} {{"]
        for ctype, decl, desc in members:
            lines.append(f"  {ctype:<{tw}} {decl + ';':<{dw + 1}} /* {desc} */")
        lines += ["};", f"typedef struct fd_event_{s.name} fd_event_{s.name}_t;", ""]

        defines = [
            (f"FD_EVENT_{up}_ID",        f"({s.id}UL)"),
            (f"FD_EVENT_{up}_PREFIX_SZ", f"(sizeof(fd_event_{s.name}_t))"),
        ] + [
            (f"FD_EVENT_{up}_{n.upper()}_MAX", f"({f.max_len}UL)") for n, f in dyn
        ]
        nw = max(len(n) for n, _ in defines)
        lines += [f"#define {n:<{nw}} {v}" for n, v in defines]
        lines += [
            "",
            "/* Every array region starts at a multiple of 8 bytes from the start",
            "   of the record, which holds only if the prefix is a multiple of 8",
            "   too. */",
            f"FD_STATIC_ASSERT( FD_EVENT_{up}_PREFIX_SZ%8UL==0UL, {s.name}_prefix_align );",
            "",
        ]

        # Parts view.
        ptrs = [("fd_event_" + s.name + "_t const *", "prefix", "Fixed prefix")]
        lines += [
            f"/* fd_event_{s.name}_parts_t is one record as a set of pointers: the",
            "   prefix plus the base of each dynamic array.  A producer fills it",
            "   with its own buffers, a consumer gets it from the unpack helper",
            "   pointing into the received record. */",
            "",
            f"struct fd_event_{s.name}_parts {{",
            f"  fd_event_{s.name}_t const * prefix;",
        ] + [
            f"  {internal_ptr_decl( s.name, n, f )};" for n, f in dyn
        ] + [
            "};",
            f"typedef struct fd_event_{s.name}_parts fd_event_{s.name}_parts_t;",
            "",
        ]
        del ptrs

        # Bounds of the prefix's counts.
        lines += [
            f"/* fd_event_{s.name}_bounded returns 1 if every array count of the",
            "   prefix is within its bound. */",
            "",
            "FD_FN_PURE static inline int",
            f"fd_event_{s.name}_bounded( fd_event_{s.name}_t const * msg ) {{",
            "  return " + ( " &&\n         ".join( f"msg->{n}_cnt<=FD_EVENT_{up}_{n.upper()}_MAX" for n, f in dyn ) ) + ";",
            "}",
            "",
        ]

        # Packed footprint.
        lines += [
            f"/* fd_event_{s.name}_footprint is the packed size of the record the",
            "   prefix describes.  Only meaningful for a bounded prefix. */",
            "",
            "FD_FN_PURE static inline ulong",
            f"fd_event_{s.name}_footprint( fd_event_{s.name}_t const * msg ) {{",
            f"  return FD_EVENT_{up}_PREFIX_SZ",
        ] + [
            f"       + fd_ulong_align_up( msg->{n}_cnt*{internal_elem_type( s.name, n, f )[1]}, 8UL )"
            for n, f in dyn
        ] + [
            "       ;",
            "}",
            "",
        ]

        # Array table and publish helpers.  The table lets a producer pack
        # a contiguous range of the arrays and splice in its own iov entries
        # for one it holds in pieces (instruction data and account data live
        # in buffers of their own), so nothing large is ever staged.
        arr_defs = [(f"FD_EVENT_{up}_ARR_CNT", f"({len(dyn)}UL)")]
        arr_defs += [(f"FD_EVENT_{up}_ARR_{n.upper()}", f"({i}UL)") for i, (n, _) in enumerate( dyn )]
        arr_defs += [(f"FD_EVENT_{up}_IOV_MAX", f"({2*len(dyn)+1}UL)")]
        nw = max(len(n) for n, _ in arr_defs)
        lines += [f"#define {n:<{nw}} {v}" for n, v in arr_defs] + [""]

        lines += [
            f"/* fd_event_{s.name}_arrs describes the record's dynamic arrays in",
            "   wire order, for the generic packing helper. */",
            "",
            "FD_FN_CONST static inline fd_event_internal_arr_t const *",
            f"fd_event_{s.name}_arrs( void ) {{",
            f"  static fd_event_internal_arr_t const arrs[ FD_EVENT_{up}_ARR_CNT ] = {{",
        ] + [
            "    { (ushort)offsetof(fd_event_" + s.name + "_t, " + n + "_cnt), " +
            "(ushort)offsetof(fd_event_" + s.name + "_parts_t, " + n + "), " +
            internal_elem_type( s.name, n, f )[1] + " },"
            for n, f in dyn
        ] + [
            "  };",
            "  return arrs;",
            "}",
            "",
            f"/* fd_event_{s.name}_iov appends the arrays [first,last) of the",
            "   record to iov and returns the new count.  A producer that holds",
            "   one array in pieces packs the arrays below it, appends its own",
            "   pieces (each padded to 8 bytes, with the array's count equal to",
            "   the total), then packs the arrays above it. */",
            "",
            "static inline ulong",
            f"fd_event_{s.name}_iov( fd_event_{s.name}_parts_t const * parts,",
            f"{' '*len(f'fd_event_{s.name}_iov( ')}fd_event_report_iov_t *          iov,",
            f"{' '*len(f'fd_event_{s.name}_iov( ')}ulong                            iov_cnt,",
            f"{' '*len(f'fd_event_{s.name}_iov( ')}ulong                            first,",
            f"{' '*len(f'fd_event_{s.name}_iov( ')}ulong                            last ) {{",
            f"  return fd_event_internal_iov_arrs( parts->prefix, parts, fd_event_{s.name}_arrs()+first, last-first, iov, iov_cnt );",
            "}",
            "",
            f"/* fd_event_report_{s.name} publishes one record on the internal",
            "   link, chunked into consecutive frags.  A no-op when the calling",
            "   tile has no internal link, and a no-op for a prefix whose counts",
            "   are out of bounds: a producer must never fail on its own hot",
            "   path. */",
            "",
            "static inline void",
            f"fd_event_report_{s.name}( fd_event_{s.name}_parts_t const * parts ) {{",
            "  if( FD_LIKELY( !fd_event_internal_tl ) ) return;",
            f"  if( FD_UNLIKELY( !fd_event_{s.name}_bounded( parts->prefix ) ) ) return;",
            "",
            f"  fd_event_report_iov_t iov[ FD_EVENT_{up}_IOV_MAX ];",
            "  iov[ 0 ].base = (void const *)parts->prefix;",
            f"  iov[ 0 ].sz   = FD_EVENT_{up}_PREFIX_SZ;",
            f"  ulong iov_cnt = fd_event_{s.name}_iov( parts, iov, 1UL, 0UL, FD_EVENT_{up}_ARR_CNT );",
            f"  fd_event_report_chunked_( FD_EVENT_{up}_ID, iov, iov_cnt );",
            "}",
            "",
        ]

        # Unpack helper.
        fn  = f"fd_event_{s.name}_unpack( "
        pad = " "*len(fn)
        ptw = len(f"fd_event_{s.name}_parts_t *")
        lines += [
            f"/* fd_event_{s.name}_unpack points parts at the arrays of a received",
            "   record.  Returns 0 on success, or -1 if the record is too short,",
            "   its counts are out of bounds, or its size does not match the",
            "   footprint its counts imply.  rec must be 8 byte aligned. */",
            "",
            "static inline int",
            f"{fn}{'void const *':<{ptw}} rec,",
            f"{pad}{'ulong':<{ptw}} rec_sz,",
            f"{pad}{f'fd_event_{s.name}_parts_t *':<{ptw}} parts ) {{",
            f"  if( FD_UNLIKELY( rec_sz<FD_EVENT_{up}_PREFIX_SZ ) ) return -1;",
            "  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rec, 8UL ) ) ) return -1;",
            f"  fd_event_{s.name}_t const * msg = (fd_event_{s.name}_t const *)rec;",
            f"  if( FD_UNLIKELY( !fd_event_{s.name}_bounded( msg ) ) ) return -1;",
            f"  if( FD_UNLIKELY( rec_sz!=fd_event_{s.name}_footprint( msg ) ) ) return -1;",
            "",
            f"  uchar const * cur = (uchar const *)rec + FD_EVENT_{up}_PREFIX_SZ;",
            "  parts->prefix = msg;",
        ]
        for k, (n, f) in enumerate( dyn ):
            esz = internal_elem_type( s.name, n, f )[1]
            lines += [f"  parts->{n} = {internal_ptr_cast( s.name, n, f )}cur;"]
            if k+1<len(dyn):
                lines += [f"  cur += fd_ulong_align_up( msg->{n}_cnt*{esz}, 8UL );"]
        lines += [
            "  return 0;",
            "}",
            "",
        ]

    lines += ["FD_PROTOTYPES_END", "", "#endif", ""]
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

    shared_path = schema_dir / "shared.json"
    shared_types = json.loads(shared_path.read_text()) if shared_path.exists() else {}
    schema_files = [f for f in schema_dir.glob("*.json") if f.name != "shared.json"]
    schemas = sorted([parse_schema(f, shared_types) for f in schema_files], key=lambda s: s.id)
    seen_ids: Dict[int, str] = {}
    seen_names: Dict[str, int] = {}
    for s in schemas:
        if not (1 <= s.id <= 255):
            raise SystemExit(f"ERROR: schema id {s.id} ({s.name}) must fit the 8-bit event type of FD_EVENT_SIG (1..255)")
        if s.id in seen_ids:
            raise SystemExit(f"ERROR: duplicate schema id {s.id}: {seen_ids[s.id]} and {s.name}")
        if s.name in seen_names:
            raise SystemExit(f"ERROR: duplicate schema name {s.name!r} (ids {seen_names[s.name]} and {s.id})")
        seen_ids[s.id]     = s.name
        seen_names[s.name] = s.id

    internal = [s for s in schemas if s.internal]
    public   = [s for s in schemas if not s.internal]

    proto_path.write_text(generate_protobuf(public))

    print(f"Protobuf generated successfully from {len(public)} schemas")

    gen_dir = Path(__file__).parent / "generated"
    gen_dir.mkdir(exist_ok=True)
    (gen_dir / "fd_event_gen.h").write_text(generate_c_header(public))
    (gen_dir / "fd_event_gen.c").write_text(generate_c_source(public))
    (gen_dir / "fd_event_gen_test.h").write_text(generate_c_test_header(public))
    (gen_dir / "fd_event_internal_gen.h").write_text(generate_c_internal_header(internal))
    eligible = [s.name for s in public if schema_is_supported(s)]
    skipped  = [s.name for s in public if not schema_is_supported(s)]
    print(f"C structs/serializers generated for fixed-length schemas: {eligible}")
    print(f"  (skipped variable-length schemas: {skipped})")
    print(f"C structs/pack helpers generated for internal schemas: {[s.name for s in internal]}")

    if not args.skip_check:
        check_breaking_changes(schema_dir)

if __name__ == "__main__":
    main()
