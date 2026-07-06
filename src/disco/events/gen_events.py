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
    UInt32 = auto()
    UInt64 = auto()
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
    if f["type"] in ("Flatten", "Tuple"):
        fields = {k: parse_field(v, shared_types) for k, v in f["fields"].items()}

    element = parse_field(f["element"], shared_types) if f["type"] == "Array" else None

    return Field(
        chtype=ClickHouseType.from_str(f["type"]),
        description=f["description"],
        variants={k: Variant(v["description"]) for k, v in f.get("variants", {}).items()} or None,
        fields=fields,
        element=element,
        max_len=f.get("max_len"),
    )

def parse_schema(path: Path, shared_types: Dict[str, dict]) -> Schema:
    data = json.loads(path.read_text())

    fields = {k: parse_field(v, shared_types) for k, v in data["fields"].items()}
    return Schema(data["name"], data["id"], data["description"], fields)

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
    ClickHouseType.Int64:      ("long",   "sint64"),
    ClickHouseType.DateTime64: ("ulong",  "uint64"),
    ClickHouseType.Bool:       ("int",    "bool"),
}

def field_is_supported(f: Field) -> bool:
    """Whether the C codegen can emit a fixed-size struct + serializer for a
    field.  Variable-length types (Bytes/String/Array) are supported only when
    bounded by max_len.  Tuples/Flattens are supported when all subfields are."""
    if f.chtype in (ClickHouseType.String, ClickHouseType.Bytes):
        return f.max_len is not None
    if f.chtype in (ClickHouseType.Flatten, ClickHouseType.Tuple):
        return all(field_is_supported(sf) for sf in f.fields.values())
    if f.chtype == ClickHouseType.Array:
        return f.max_len is not None and field_is_supported(f.element)
    return True  # scalar, enum, or fixed-byte type

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
    """Tight upper bound on the encoded size of a whole event (envelope +
    Event submsg + inner submsg + all fields), padded for encoder slack."""
    # Envelope: 3 uint64 fields (nonce, event_id, timestamp_nanos).
    envelope = 3 * (_PB_TAG_MAX + _PB_VARINT64)
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

def gen_tuple_struct( schema_name: str, field_name: str, flds: Dict[str, Field], desc: str ) -> List[str]:
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
    out += ["};", f"typedef struct {tn[:-2]} {tn};", ""]
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
        '#include "../fd_circq.h"',
        '#include "../fd_event_client.h"',
        '#include "../fd_event_report.h"',
        "",
    ]

    struct_max_names = [f"sizeof(fd_event_{s.name}_t)" for s in eligible]

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
                lines += gen_tuple_struct( s.name, name, tflds, inner.description )

        # Main struct.  Each field becomes one or more members:
        #   scalar/enum/fixed-byte -> single member
        #   Bytes/String(max_len)  -> uchar <name>[max_len]; ulong <name>_len;
        #   Tuple                  -> <tuple_t> <name>;
        #   Array(max_len)         -> <elem-decl>[max_len]; ulong <name>_cnt;
        members = []  # (ctype, decl, desc)
        for name, f in s.fields.items():
            if f.variants:
                members.append(("int", name, f.description))
            elif f.chtype in _FIXED_BYTE_SZ:
                members.append(("uchar", f"{name}[ {_FIXED_BYTE_SZ[f.chtype]}UL ]", f.description))
            elif f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
                members.append(("uchar", f"{name}[ {f.max_len}UL ]", f.description))
                members.append(("ulong", f"{name}_len", f"Length of {name} (<= {f.max_len})"))
            elif f.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
                members.append((c_tuple_name( s.name, name ), name, f.description))
            elif f.chtype == ClickHouseType.Array:
                el = f.element
                if el.chtype in (ClickHouseType.Tuple, ClickHouseType.Flatten):
                    ectype = c_tuple_name( s.name, name )
                elif el.variants:
                    ectype = "int"
                elif el.chtype in _FIXED_BYTE_SZ:
                    ectype = None  # handled specially below
                else:
                    ectype = _SCALAR_C[el.chtype][0]
                if ectype is None:
                    # Array of fixed-byte values: <name>[max_len][N]
                    n = _FIXED_BYTE_SZ[el.chtype]
                    members.append(("uchar", f"{name}[ {f.max_len}UL ][ {n}UL ]", f.description))
                else:
                    members.append((ectype, f"{name}[ {f.max_len}UL ]", f.description))
                members.append(("ulong", f"{name}_cnt", f"Number of {name} entries (<= {f.max_len})"))
            else:
                members.append((_SCALAR_C[f.chtype][0], name, f.description))
        tw = max(len(c) for c, _, _ in members)
        dw = max(len(d) for _, d, _ in members)
        lines += [f"/* {s.description} */", "struct fd_event_" + s.name + " {"]
        for ctype, decl, desc in members:
            lines.append(f"  {ctype:<{tw}} {decl + ';':<{dw + 1}} /* {desc} */")
        lines += ["};", f"typedef struct fd_event_{s.name} fd_event_{s.name}_t;", ""]

        # Tight upper bound on this event's encoded size.
        lines += [
            f"/* Worst-case encoded size of a {s.name} event (envelope + Event",
            "   submsg + inner submsg + all fields, padded for encoder slack). */",
            f"#define {event_buf_max_define(s)} ({event_buf_max(s)}UL)",
            "",
        ]

    # Max sizeof over all generated event structs.
    if struct_max_names:
        expr = struct_max_names[0]
        for n in struct_max_names[1:]:
            expr = f"( {n} > {expr} ? {n} : {expr} )"
        lines += [
            "/* Largest generated event struct; a consumer can stage any incoming",
            "   event in a buffer of this size. */",
            f"#define FD_EVENT_GEN_STRUCT_MAX ({expr})",
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
    # reporter.  No-op when the calling tile has no event link.
    for s in eligible:
        lines += [
            f"/* Report a {s.name} event ({to_pascal_case(s.name)}, id {s.id}) to the event tile via",
            "   the thread-local reporter (no-op when the tile has no event link). */",
            "static inline void",
            f"fd_event_report_{s.name}( fd_event_{s.name}_t const * msg ) {{",
            f"  fd_event_report_( {s.id}UL, msg, sizeof(fd_event_{s.name}_t) );",
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
        return [f"{ind}{guard}fd_pb_push_int32 ( encoder, {field_id}U, {acc} );"]
    if f.chtype in _FIXED_BYTE_SZ:
        return [f"{ind}fd_pb_push_bytes ( encoder, {field_id}U, {acc}, {_FIXED_BYTE_SZ[f.chtype]}UL );"]
    suffix = _SCALAR_C[f.chtype][1]
    cast   = "(ulong)" if suffix == "uint64" else ("(uint)" if suffix == "uint32" else "")
    guard  = f"if( {acc} ) " if omit_default else ""
    return [f"{ind}{guard}fd_pb_push_{suffix:<6}( encoder, {field_id}U, {cast}{acc} );"]

def encode_tuple( f: Field, field_id: int, acc: str, ind: str ) -> List[str]:
    """Emit a submessage encoding a Tuple value at field_id.  acc is the C
    accessor for the tuple struct (e.g. 'msg->x' or 'msg->arr[ k ]')."""
    out = [f"{ind}fd_pb_submsg_open( encoder, {field_id}U );"]
    for j, (sn, sf) in enumerate(f.fields.items(), 1):
        out += encode_scalar( sf, j, f"{acc}.{sn}", ind, omit_default=True )
    out += [f"{ind}fd_pb_submsg_close( encoder );"]
    return out

def encode_field( f: Field, field_id: int, name: str, acc: str, ind: str ) -> List[str]:
    """Emit encode lines for one struct field of any supported type."""
    if f.chtype in (ClickHouseType.Bytes, ClickHouseType.String):
        return [f"{ind}if( {acc}_len ) fd_pb_push_bytes ( encoder, {field_id}U, {acc}, {acc}_len );"]
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
            "  FD_TEST( circq->cursor_push_seq );",
            "  fd_pb_push_uint64( encoder, 1U, circq->cursor_push_seq-1UL );",
            "  fd_pb_push_uint64( encoder, 2U, event_id );",
            "  fd_pb_push_uint64( encoder, 3U, link_seq );",
            "  fd_pb_push_uint64( encoder, 4U, (ulong)timestamp_nanos );",
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
        lines += [
            "  fd_pb_submsg_open( encoder, 5U ); /* Event */",
            f"  fd_pb_submsg_open( encoder, {s.id}U ); /* {to_pascal_case(s.name)} */",
        ]
        # Encode each field.  proto3 omits scalar fields at their default
        # (0/false) - skipped here (a conformant reader reconstructs the
        # default).  Fixed-byte fields are always emitted (a 32-byte hash is
        # meaningful content, not the empty `bytes` default).
        for i, (name, f) in enumerate(s.fields.items(), 1):
            lines += encode_field( f, i, name, f"msg->{name}", "  " )
        lines += [
            "  fd_pb_submsg_close( encoder );",
            "  fd_pb_submsg_close( encoder );",
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
        lines += [
            f"  case {s.id}UL:",
            f"    FD_TEST( ev_sz==sizeof(fd_event_{s.name}_t) );",
            f"    fd_event_{s.name}_serialize( circq, client, timestamp_nanos, link_seq, (fd_event_{s.name}_t const *)ev );",
            "    break;",
        ]
    lines += [
        '  default: FD_LOG_ERR(( "unexpected event type %lu", type ));',
        "  }",
        "}",
        "",
    ]
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
    proto_path.write_text(generate_protobuf(schemas))

    print(f"Protobuf generated successfully from {len(schemas)} schemas")

    gen_dir = Path(__file__).parent / "generated"
    gen_dir.mkdir(exist_ok=True)
    (gen_dir / "fd_event_gen.h").write_text(generate_c_header(schemas))
    (gen_dir / "fd_event_gen.c").write_text(generate_c_source(schemas))
    eligible = [s.name for s in schemas if schema_is_supported(s)]
    skipped  = [s.name for s in schemas if not schema_is_supported(s)]
    print(f"C structs/serializers generated for fixed-length schemas: {eligible}")
    print(f"  (skipped variable-length schemas: {skipped})")

    if not args.skip_check:
        check_breaking_changes(schema_dir)

if __name__ == "__main__":
    main()
