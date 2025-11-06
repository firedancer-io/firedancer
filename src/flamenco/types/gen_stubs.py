#!/usr/bin/env python3
"""
C Code Generator for Solana/Firedancer Type System

This script generates C header and implementation files for serialization/deserialization
of Solana blockchain data structures. It reads type definitions from a JSON configuration
file and generates optimized C code for binary encoding/decoding, memory management,
and type reflection.

Usage: python3 gen_stubs.py <header_file> <implementation_file> <reflection_file>
"""

import json
import sys

# Load type definitions from JSON configuration file
with open('fd_types.json', 'r') as json_file:
    json_object = json.load(json_file)

# Open output files for writing generated C code
header = open(sys.argv[1], "w")      # Header file (.h)
body = open(sys.argv[2], "w")        # Implementation file (.c)
reflect = open(sys.argv[3], "w")     # Reflection file

# Extract configuration from JSON
namespace = json_object["namespace"]  # Namespace prefix for generated functions
entries = json_object["entries"]     # List of type definitions

# Generate file headers with auto-generation notice
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=header)
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=body)
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=reflect)

# Generate header file include guards
print("#ifndef HEADER_" + json_object["name"].upper(), file=header)
print("#define HEADER_" + json_object["name"].upper(), file=header)
print("", file=header)

# Include any extra headers specified in the JSON config
for extra in json_object["extra_header"]:
    print(extra, file=header)
print("", file=header)

# Generate implementation file includes and compiler directives
print(f'#include "{sys.argv[1]}"', file=body)

# Disable specific GCC warnings for generated code
print('#pragma GCC diagnostic ignored "-Wunused-parameter"', file=body)
print('#pragma GCC diagnostic ignored "-Wunused-variable"', file=body)
print('#pragma GCC diagnostic ignored "-Wunused-function"', file=body)
print('#if defined(__GNUC__) && (__GNUC__ >= 9)', file=body)
print('#pragma GCC diagnostic ignored "-Waddress-of-packed-member"', file=body)
print('#endif', file=body)

# Include custom type definitions
print('#define SOURCE_fd_src_flamenco_types_fd_types_c', file=body)
print('#include "fd_types_custom.h"', file=body)

# Sets to track types that need special preamble/postamble handling
preambletypes = set()
postambletypes = set()

# Map from primitive types to their corresponding bincode function names
# This allows the code generator to emit the correct function calls for each type
simpletypes = dict()
for t,t2 in [("char","int8"),
             ("uchar","uint8"),
             ("double","double"),
             ("short","int16"),
             ("ushort","uint16"),
             ("int","int32"),
             ("uint","uint32"),
             ("long","int64"),
             ("ulong","uint64")]:
    simpletypes[t] = t2

# Map from type name to encoded byte size for fixed-size types
# Used for memory allocation and size calculations
fixedsizetypes = dict()
for t,t2 in [("bool",1),
             ("char",1),
             ("uchar",1),
             ("short",2),
             ("ushort",2),
             ("int",4),
             ("uint",4),
             ("long",8),
             ("ulong",8),
             ("double",8),
             ("uint128",16),
             ("pubkey",32),
             ("hash",32),
             ("uchar[32]",32),
             ("signature",64),
             ("uchar[128]",128),
             ("uchar[2048]",2048),]:
    fixedsizetypes[t] = t2

# Set of types that do not contain nested local pointers
# These types can be serialized directly without special offset handling
flattypes = {
  "bool",
  "char",
  "uchar",
  "short",
  "ushort",
  "int",
  "uint",
  "long",
  "ulong",
  "double",
  "uint128",
  "pubkey",
  "hash",
  "uchar[32]",
  "signature",
  "uchar[128]",
  "uchar[2048]",
  "flamenco_txn" # custom type
}

# Types that are fixed size and valid for all possible bit patterns
# These types can be used in fuzzing without special validation
# (e.g. ulong is in here, but bool is not because not all bit patterns are valid bools)
fuzzytypes = {
    "char", "uchar",
    "short", "ushort",
    "int", "uint",
    "long", "ulong",
    "double",
    "uint128",
    "pubkey",
    "hash",
    "uchar[32]",
    "signature",
    "uchar[128]",
    "uchar[2048]",
}

# Base class for all type nodes in the type system
class TypeNode:
    """
    Base class for all type definitions in the generated C code.

    Each type node represents a data structure that can be:
    - Serialized/deserialized using bincode format
    - Allocated and freed in memory
    - Walked for reflection/debugging
    - Sized for memory planning

    Attributes:
        name: The name of this type
        produce_global: Whether to generate "global" versions (using offsets vs pointers)
        encoders: Encoder configuration (if any)
        arch_index: Architecture-specific index for optimization
    """
    def __init__(self, json, **kwargs):
        self.produce_global = False
        if json is not None:
            self.name = json["name"]
            self.produce_global = bool(json["global"]) if "global" in json else None
        elif 'name' in kwargs:
            self.name = kwargs['name']
        else:
            raise ValueError(f"invalid arguments {kwargs} provided to TypeNode!")
        self.encoders = None
        self.arch_index = 0  # Index for architecture-specific optimizations

    def isFixedSize(self):
        """Return True if this type has a fixed size in bytes."""
        return False

    def fixedSize(self):
        """Return the fixed size in bytes, or None if variable size."""
        return

    def isFuzzy(self):
        """Return True if this type is safe for fuzzing (all bit patterns valid)."""
        return False

    def isFlat(self):
        """Return True if this type contains no nested pointers."""
        return False

    def emitOffsetJoin(self, type_name):
        """Generate helper functions for joining global types with offsets."""
        pass

    def subTypes(self):
        """Return iterator over nested types contained in this type."""
        return iter(())

    def subMembers(self):
        """Return iterator over member fields of this type."""
        return iter(())
# Class representing primitive/basic types (int, char, etc.)
class PrimitiveMember(TypeNode):
    """
    Represents primitive data types like integers, chars, booleans, etc.

    These are the fundamental building blocks that map directly to C primitive types.
    Handles special cases like:
    - Variable-length integers (varint encoding)
    - String types (char*)
    - Fixed-size arrays (uchar[32], etc.)

    Attributes:
        type: The primitive type name (e.g., "ulong", "char*")
        varint: Whether to use variable-length integer encoding
        decode: Whether this field should be decoded
        encode: Whether this field should be encoded
        walk: Whether this field should be included in walking/reflection
    """
    def __init__(self, container, json):
        super().__init__(json)
        self.type = json["type"]
        self.varint = ("modifier" in json and json["modifier"] == "varint")
        self.decode = ("decode" not in json or json["decode"])
        self.encode = ("encode" not in json or json["encode"])
        self.walk = ("walk" not in json or json["walk"])

    def emitPreamble(self):
        """Generate any preamble code needed before type definition."""
        pass

    def emitPostamble(self):
        """Generate any postamble code needed after type definition."""
        pass

    def emitNew(self, indent=''):
        """Generate constructor/initialization code for this primitive type."""
        pass

    def isFlat(self):
        """Return True if this primitive type contains no pointers (except char*)."""
        return self.type != "char*"

    # Map from primitive type names to functions that emit C struct member declarations
    emitMemberMap = {
        "char" :      lambda n: print(f'  char {n};',      file=header),
        "char*" :     lambda n: print(f'  char* {n};',     file=header),
        "char[32]" :  lambda n: print(f'  char {n}[32];',  file=header),
        "double" :    lambda n: print(f'  double {n};',    file=header),
        "long" :      lambda n: print(f'  long {n};',      file=header),
        "uint" :      lambda n: print(f'  uint {n};',      file=header),
        "uint128" :   lambda n: print(f'  uint128 {n};',   file=header),
        "bool" :      lambda n: print(f'  uchar {n};',     file=header),  # bool stored as uchar
        "uchar" :     lambda n: print(f'  uchar {n};',     file=header),
        "uchar[32]" : lambda n: print(f'  uchar {n}[32];', file=header),
        "uchar[128]" :lambda n: print(f'  uchar {n}[128];', file=header),
        "uchar[2048]":lambda n: print(f'  uchar {n}[2048];', file=header),
        "ulong" :     lambda n: print(f'  ulong {n};',     file=header),
        "ushort" :    lambda n: print(f'  ushort {n};',    file=header)
    }

    def emitMember(self):
        PrimitiveMember.emitMemberMap[self.type](self.name)

    def emitMemberGlobal(self):
        PrimitiveMember.emitMemberMap[self.type](self.name)

    def isFixedSize(self):
        if self.varint:
            return False
        if self.encode != self.decode:
            return False
        return self.type in fixedsizetypes

    def fixedSize(self):
        if not self.encode:
            return 0
        return fixedsizetypes[self.type]

    def isFuzzy(self):
        if self.varint:
            return False
        return self.type in fuzzytypes

    def string_decode_footprint(n, varint, indent):
        """
        Generate code to calculate memory footprint needed for decoding a string.

        Strings are encoded as: [length: u64][data: bytes]
        We need extra space for null termination in C.
        """
        print(f'{indent}  ulong slen;', file=body)
        print(f'{indent}  err = fd_bincode_uint64_decode( &slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'{indent}  err = fd_bincode_bytes_decode_footprint( slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'{indent}  *total_sz += slen + 1; // Need an extra byte for null termination', file=body)

    def ushort_decode_footprint(n, varint, indent):
        """Generate code to calculate footprint for decoding unsigned short (16-bit)."""
        if varint:
            print(f'{indent}  do {{ ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); }} while(0);', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint16_decode_footprint( ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    def ulong_decode_footprint(n, varint, indent):
        """Generate code to calculate footprint for decoding unsigned long (64-bit)."""
        if varint:
            print(f'{indent}  err = fd_bincode_varint_decode_footprint( ctx );', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint64_decode_footprint( ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    emitDecodeFootprintMap = {
        "char" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint8_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "char*" :     lambda n, varint, indent: PrimitiveMember.string_decode_footprint(n, varint, indent),
        "char[32]" :  lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 32, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "double" :    lambda n, varint, indent: print(f'{indent}  err = fd_bincode_double_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "long" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint64_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint32_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint128" :   lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint128_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "bool" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bool_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar" :     lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint8_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[32]" : lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 32, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[128]" :lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 128, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[2048]":lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 2048, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "ulong" :     lambda n, varint, indent: PrimitiveMember.ulong_decode_footprint(n, varint, indent),
        "ushort" :    lambda n, varint, indent: PrimitiveMember.ushort_decode_footprint(n, varint, indent),
    }

    def emitDecodeFootprint(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeFootprintMap[self.type](self.name, self.varint, indent)

    def string_decode_unsafe(n, varint, indent):
        print(f'{indent}  ulong slen;', file=body)
        print(f'{indent}  fd_bincode_uint64_decode_unsafe( &slen, ctx );', file=body)
        print(f'{indent}  self->{n} = *alloc_mem;', file=body)
        print(f'{indent}  fd_bincode_bytes_decode_unsafe( (uchar *)self->{n}, slen, ctx );', file=body)
        print(f"{indent}  self->{n}[slen] = '\\0';", file=body)
        print(f'{indent}  *alloc_mem = (uchar *)(*alloc_mem) + (slen + 1); // extra byte for null termination', file=body)

    def ushort_decode_unsafe(n, varint, indent):
        if varint:
            print(f'{indent}  fd_bincode_compact_u16_decode_unsafe( &self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  fd_bincode_uint16_decode_unsafe( &self->{n}, ctx );', file=body),

    def ulong_decode_unsafe(n, varint, indent):
        if varint:
            print(f'{indent}  fd_bincode_varint_decode_unsafe( &self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  fd_bincode_uint64_decode_unsafe( &self->{n}, ctx );', file=body),

    emitDecodeMap = {
        "char" :      lambda n, varint, indent: print(f'{indent}  fd_bincode_uint8_decode_unsafe( (uchar *) &self->{n}, ctx );', file=body),
        "char*" :     lambda n, varint, indent: PrimitiveMember.string_decode_unsafe(n, varint, indent),
        "char[32]" :  lambda n, varint, indent: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "double" :    lambda n, varint, indent: print(f'{indent}  fd_bincode_double_decode_unsafe( &self->{n}, ctx );', file=body),
        "long" :      lambda n, varint, indent: print(f'{indent}  fd_bincode_uint64_decode_unsafe( (ulong *) &self->{n}, ctx );', file=body),
        "uint" :      lambda n, varint, indent: print(f'{indent}  fd_bincode_uint32_decode_unsafe( &self->{n}, ctx );', file=body),
        "uint128" :   lambda n, varint, indent: print(f'{indent}  fd_bincode_uint128_decode_unsafe( &self->{n}, ctx );', file=body),
        "bool" :      lambda n, varint, indent: print(f'{indent}  fd_bincode_bool_decode_unsafe( &self->{n}, ctx );', file=body),
        "uchar" :     lambda n, varint, indent: print(f'{indent}  fd_bincode_uint8_decode_unsafe( &self->{n}, ctx );', file=body),
        "uchar[32]" : lambda n, varint, indent: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "uchar[128]" :lambda n, varint, indent: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "uchar[2048]":lambda n, varint, indent: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "ulong" :     lambda n, varint, indent: PrimitiveMember.ulong_decode_unsafe(n, varint, indent),
        "ushort" :    lambda n, varint, indent: PrimitiveMember.ushort_decode_unsafe(n, varint, indent),
    }

    def emitDecodeInner(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, self.varint, indent)

    def emitDecodeInnerGlobal(self, indent=''):
        # FIXME: char * is currently incorrect
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, self.varint, indent)

    def string_encode(n, varint, indent):
        print(f'{indent}  ulong slen = strlen( (char *) self->{n} );', file=body)
        print(f'{indent}  err = fd_bincode_uint64_encode( slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'{indent}  err = fd_bincode_bytes_encode( (uchar *) self->{n}, slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def ushort_encode(n, varint, indent):
        if varint:
            print(f'{indent}  err = fd_bincode_compact_u16_encode( &self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint16_encode( self->{n}, ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def ulong_encode(n, varint, indent):
        if varint:
            print(f'{indent}  err = fd_bincode_varint_encode( self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint64_encode( self->{n}, ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    emitEncodeMap = {
        "char" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint8_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "char*" :     lambda n, varint, indent: PrimitiveMember.string_encode(n, varint, indent),
        "char[32]" :  lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_encode( &self->{n}[0], sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "double" :    lambda n, varint, indent: print(f'{indent}  err = fd_bincode_double_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "long" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint64_encode( (ulong)self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint32_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint128" :   lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint128_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "bool" :      lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bool_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar" :     lambda n, varint, indent: print(f'{indent}  err = fd_bincode_uint8_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[32]" : lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_encode( self->{n}, sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[128]" : lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_encode( self->{n}, sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[2048]" : lambda n, varint, indent: print(f'{indent}  err = fd_bincode_bytes_encode( self->{n}, sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "ulong" :     lambda n, varint, indent: PrimitiveMember.ulong_encode(n, varint, indent),
        "ushort" :    lambda n, varint, indent: PrimitiveMember.ushort_encode(n, varint, indent),
    }

    def emitEncode(self, indent=''):
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, self.varint, indent)

    def emitEncodeGlobal(self, indent=''):
        # FIXME: char * is currently incorrect
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, self.varint, indent)

    emitSizeMap = {
        "char" :      lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(char);', file=body),
        "char*" :     lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(ulong) + strlen(self->{inner}{n});', file=body),
        "char[32]" :  lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(char) * 32;', file=body),
        "double" :    lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(double);', file=body),
        "long" :      lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(long);', file=body),
        "uint" :      lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(uint);', file=body),
        "uint128" :   lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(uint128);', file=body),
        "bool" :      lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(char);', file=body),
        "uchar" :     lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(char);', file=body),
        "uchar[32]" : lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(char) * 32;', file=body),
        "uchar[128]" :lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(char) * 128;', file=body),
        "uchar[2048]":lambda n, varint, inner, indent: print(f'{indent}  size += sizeof(char) * 2048;', file=body),
        "ulong" :     lambda n, varint, inner, indent: print(f'{indent}  size += { ("fd_bincode_varint_size( self->" + n + " );") if varint else "sizeof(ulong);" }', file=body),
        "ushort" :    lambda n, varint, inner, indent: print(f'{indent}  size += { ("fd_bincode_compact_u16_size( &self->" + n + " );") if varint else "sizeof(ushort);" }', file=body),
    }

    def emitSize(self, inner, indent=''):
        if self.encode:
            PrimitiveMember.emitSizeMap[self.type](self.name, self.varint, inner, indent)

    def emitSizeGlobal(self, inner, indent=''):
        # FIXME: char * is currently incorrect
        if self.encode:
            PrimitiveMember.emitSizeMap[self.type](self.name, self.varint, inner, indent)

    emitWalkMap = {
        "char" :      lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR, "char", level, {1 if varint else 0} );',  file=body),
        "char*" :     lambda n, varint, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_CSTR, "char*", level, {1 if varint else 0}  );', file=body),
        "double" :    lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE, "double", level, {1 if varint else 0}  );', file=body),
        "long" :      lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SLONG, "long", level, {1 if varint else 0}  );', file=body),
        "uint" :      lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT, "uint", level, {1 if varint else 0}  );', file=body),
        "uint128" :   lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level, {1 if varint else 0}  );', file=body),
        "bool" :      lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_BOOL, "bool", level, {1 if varint else 0}  );', file=body),
        "uchar" :     lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, {1 if varint else 0}  );', file=body),
        "uchar[32]" : lambda n, varint, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level, {1 if varint else 0}  );', file=body),
        "uchar[128]" :lambda n, varint, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH1024, "uchar[128]", level, {1 if varint else 0}  );', file=body),
        "uchar[2048]":lambda n, varint, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH16384, "uchar[2048]", level, {1 if varint else 0}  );', file=body),
        "ulong" :     lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_ULONG, "ulong", level, {1 if varint else 0}  );', file=body),
        "ushort" :    lambda n, varint, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_USHORT, "ushort", level, {1 if varint else 0}  );', file=body)
    }

    def emitWalk(self, inner, indent=''):
        if self.walk:
            PrimitiveMember.emitWalkMap[self.type](self.name, self.varint, inner)

# This is a member which IS a struct, NOT a member OF a struct
class StructMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.type = json["type"]
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def isFlat(self):
        return self.type in flattypes

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self, indent=''):
        print(f'{indent}  {namespace}_{self.type}_t {self.name};', file=header)

    def emitMemberGlobal(self, indent=''):
        if self.type in flattypes:
            print(f'{indent}  {namespace}_{self.type}_t {self.name};', file=header)
        else:
            print(f'{indent}  {namespace}_{self.type}_global_t {self.name};', file=header)

    def isFixedSize(self):
        return self.type in fixedsizetypes

    def fixedSize(self):
        return fixedsizetypes[self.type]

    def isFuzzy(self):
        return self.type in fuzzytypes

    def emitNew(self, indent=''):
        print(f'{indent}  {namespace}_{self.type}_new( &self->{self.name} );', file=body)

    def emitDecodeFootprint(self, indent=''):
        print(f'{indent}  err = {namespace}_{self.type}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitDecodeInner(self, indent=''):
        print(f'{indent}  {namespace}_{self.type}_decode_inner( &self->{self.name}, alloc_mem, ctx );', file=body)

    def emitDecodeInnerGlobal(self, indent=''):
        if self.type in flattypes:
            print(f'{indent}  {namespace}_{self.type}_decode_inner( &self->{self.name}, alloc_mem, ctx );', file=body)
        else:
            print(f'{indent}  {namespace}_{self.type}_decode_inner_global( &self->{self.name}, alloc_mem, ctx );', file=body)

    def emitEncode(self, indent=''):
        print(f'{indent}  err = {namespace}_{self.type}_encode( &self->{self.name}, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitEncodeGlobal(self, indent=''):
        if self.type in flattypes:
            print(f'{indent}  err = {namespace}_{self.type}_encode( &self->{self.name}, ctx );', file=body)
            print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)
        else:
            print(f'{indent}  err = {namespace}_{self.type}_encode_global( &self->{self.name}, ctx );', file=body)
            print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitSize(self, inner, indent=''):
        print(f'{indent}  size += {namespace}_{self.type}_size( &self->{inner}{self.name} );', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        if self.type in flattypes:
            print(f'{indent}  size += {namespace}_{self.type}_size( &self->{inner}{self.name} );', file=body)
        else:
            print(f'{indent}  size += {namespace}_{self.type}_size_global( &self->{inner}{self.name} );', file=body)

    def emitWalk(self, inner, indent=''):
        print(f'{indent}  {namespace}_{self.type}_walk( w, &self->{inner}{self.name}, fun, "{self.name}", level, 0 );', file=body)

# Class representing dynamic arrays/vectors
class VectorMember(TypeNode):
    """
    Represents a dynamic array (vector) of elements.

    Vectors are encoded as: [length][element1][element2]...[elementN]

    Supports:
    - Compact encoding (uses 16-bit length instead of 64-bit)
    - Different element types (primitives or complex types)
    - Memory management for both regular and global variants

    Attributes:
        element: Type of elements stored in the vector
        compact: Whether to use compact (16-bit) length encoding
        ignore_underflow: Whether to ignore underflow errors during decoding
    """
    def __init__(self, container, json, **kwargs):
        if (json is not None):
            super().__init__(json)
            self.element = json["element"]
            self.compact = ("modifier" in json and json["modifier"] == "compact")
            self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)
        elif(json is None and 'name' in kwargs):
            super().__init__(json, name=kwargs['name'])
            if 'element' in kwargs:
                self.element = kwargs['element']
            else:
                raise ValueError(f"missing element argument in {kwargs}")
            self.compact = False
            self.ignore_underflow = False

    def isFlat(self):
        return False

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=header)
        else:
            print(f'  ulong {self.name}_len;', file=header)
        if self.element in simpletypes:
            print(f'  {self.element}* {self.name};', file=header)
        else:
            print(f'  {namespace}_{self.element}_t * {self.name};', file=header)

    def emitMemberGlobal(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=header)
        else:
            print(f'  ulong {self.name}_len;', file=header)
        print(f'  ulong {self.name}_offset;', file=header)

    def emitOffsetJoin(self, type_name):
        ret_type = None
        if self.element in simpletypes:
            ret_type = self.element
        elif self.element in flattypes:
            ret_type = f'{namespace}_{self.element}_t'
        else:
            ret_type = f'{namespace}_{self.element}_global_t'

        print(f'FD_FN_UNUSED static {ret_type} * {type_name}_{self.name}_join( {type_name}_global_t const * struct_mem ) {{ // vector', file=header)
        print(f'  return struct_mem->{self.name}_offset ? ({ret_type} *)fd_type_pun( (uchar *)struct_mem + struct_mem->{self.name}_offset ) : NULL;', file=header)
        print(f'}}', file=header)
        print(f'FD_FN_UNUSED static void {type_name}_{self.name}_update( {type_name}_global_t * struct_mem, {ret_type} * vec ) {{', file=header)
        print(f'  struct_mem->{self.name}_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;', file=header)
        print(f'}}', file=header)


    def emitNew(self, indent=''):
        pass

    def emitDestroy(self, indent=''):
        """Generate cleanup code for vector member - sets pointer to NULL and length to 0."""
        print(f'{indent}  self->{self.name} = NULL;', file=body)
        print(f'{indent}  self->{self.name}_len = 0;', file=body)

    def emitDecodeFootprint(self, indent=''):
        if self.compact:
            print(f'{indent}  ushort {self.name}_len;', file=body)
            print(f'{indent}  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'{indent}  ulong {self.name}_len;', file=body)
            print(f'{indent}  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'{indent}  if( {self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'

        if self.element == "uchar":
            print(f'{indent}    *total_sz += 8UL + {self.name}_len;', file=body)
            print(f'{indent}    err = fd_bincode_bytes_decode_footprint( {self.name}_len, ctx );', file=body)
            print(f'{indent}    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

        else:
            if self.element in simpletypes:
                  print(f'{indent}    *total_sz += 8UL + sizeof({self.element})*{self.name}_len;', file=body)
            else:
                  print(f'    *total_sz += {el.upper()}_ALIGN + sizeof({el}_t)*{self.name}_len;', file=body)

            print(f'{indent}    for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)

            if self.element in simpletypes:
                print(f'{indent}      err = fd_bincode_{simpletypes[self.element]}_decode_footprint( ctx );', file=body)
            else:
                print(f'{indent}      err = {namespace}_{self.element}_decode_footprint_inner( ctx, total_sz );', file=body)

            print(f'{indent}      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
            print(f'{indent}    }}', file=body)

        print(f'{indent}  }}', file=body)

    def emitDecodeInner(self, indent=''):
        if self.compact:
            print(f'{indent}  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'{indent}  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'{indent}  if( self->{self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'

        if self.element == "uchar":
            print(f'{indent}    self->{self.name} = *alloc_mem;', file=body)
            print(f'{indent}    fd_bincode_bytes_decode_unsafe( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            print(f'{indent}    *alloc_mem = (uchar *)(*alloc_mem) + self->{self.name}_len;', file=body)
        else:
            if self.element in simpletypes:
                print(f'{indent}    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );', file=body)
                print(f'{indent}    self->{self.name} = *alloc_mem;', file=body)
                print(f'{indent}    *alloc_mem = (uchar *)(*alloc_mem) + sizeof({self.element})*self->{self.name}_len;', file=body)
            else:
                print(f'    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), {el.upper()}_ALIGN );', file=body)
                print(f'    self->{self.name} = *alloc_mem;', file=body)
                print(f'    *alloc_mem = (uchar *)(*alloc_mem) + sizeof({el}_t)*self->{self.name}_len;', file=body)

            print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)

            if self.element in simpletypes:
                print(f'{indent}      fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name} + i, ctx );', file=body)
            else:
                print(f'{indent}      {namespace}_{self.element}_new( self->{self.name} + i );', file=body)
                print(f'{indent}      {namespace}_{self.element}_decode_inner( self->{self.name} + i, alloc_mem, ctx );', file=body)

            print(f'{indent}    }}', file=body)

        print(f'{indent}  }} else', file=body)
        print(f'{indent}    self->{self.name} = NULL;', file=body)

    def emitDecodeInnerGlobal(self, indent=''):
        if self.compact:
            print(f'{indent}  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'{indent}  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'{indent}  if( self->{self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'

        if self.element == "uchar":
            print(f'{indent}    self->{self.name}_offset = (ulong)*alloc_mem - (ulong)struct_mem;', file=body)
            print(f'{indent}    fd_bincode_bytes_decode_unsafe( *alloc_mem, self->{self.name}_len, ctx );', file=body)
            print(f'{indent}    *alloc_mem = (uchar *)(*alloc_mem) + self->{self.name}_len;', file=body)
        else:
            if self.element in simpletypes:
                print(f'{indent}    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );', file=body)
                print(f'{indent}    self->{self.name}_offset = (ulong)*alloc_mem - (ulong)struct_mem;', file=body)
                print(f'{indent}    uchar * cur_mem = (uchar *)(*alloc_mem);', file=body)
                print(f'{indent}    *alloc_mem = (uchar *)(*alloc_mem) + sizeof({self.element})*self->{self.name}_len;', file=body)
            else:
                print(f'    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), {el.upper()}_ALIGN );', file=body)
                print(f'    self->{self.name}_offset = (ulong)*alloc_mem - (ulong)struct_mem;', file=body)
                print(f'    uchar * cur_mem = (uchar *)(*alloc_mem);', file=body)
                print(f'    *alloc_mem = (uchar *)(*alloc_mem) + sizeof({el}_t)*self->{self.name}_len;', file=body)

            print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
            if self.element in simpletypes:
                print(f'{indent}      fd_bincode_{simpletypes[self.element]}_decode_unsafe( ({self.element}*)(cur_mem + sizeof({self.element}) * i), ctx );', file=body)
            else:
                print(f'      {namespace}_{self.element}_new( ({namespace}_{self.element}_t *)fd_type_pun(cur_mem + sizeof({el}_t) * i) );', file=body)
                if self.element in flattypes:
                    print(f'      {namespace}_{self.element}_decode_inner( cur_mem + sizeof({el}_t) * i, alloc_mem, ctx );', file=body)
                else:
                    print(f'      {namespace}_{self.element}_decode_inner_global( cur_mem + sizeof({el}_t) * i, alloc_mem, ctx );', file=body)

            print(f'{indent}    }}', file=body)

        print(f'{indent}  }} else {{', file=body)
        print(f'{indent}    self->{self.name}_offset = 0UL;', file=body)
        print(f'{indent}  }}', file=body)

    def emitEncode(self, indent=''):
        if self.compact:
            print(f'{indent}  err = fd_bincode_compact_u16_encode( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'{indent}  err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'{indent}  if( self->{self.name}_len ) {{', file=body)

        if self.element == "uchar":
            print(f'{indent}    err = fd_bincode_bytes_encode( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            print(f'{indent}    if( FD_UNLIKELY( err ) ) return err;', file=body)

        else:
            print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)

            if self.element in simpletypes:
                print(f'{indent}      err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}[i], ctx );', file=body)
            else:
                print(f'{indent}      err = {namespace}_{self.element}_encode( self->{self.name} + i, ctx );', file=body)
                print(f'{indent}      if( FD_UNLIKELY( err ) ) return err;', file=body)

            print(f'{indent}    }}', file=body)

        print(f'{indent}  }}', file=body)

    def emitEncodeGlobal(self, indent=''):
        if self.compact:
            print(f'{indent}  err = fd_bincode_compact_u16_encode( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'{indent}  err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'{indent}  if( self->{self.name}_len ) {{', file=body)
        print(f'{indent}    uchar * {self.name}_laddr = (uchar*)self + self->{self.name}_offset;', file=body)

        if self.element == "uchar":
            print(f'{indent}    err = fd_bincode_bytes_encode( {self.name}_laddr, self->{self.name}_len, ctx );', file=body)
            print(f'{indent}    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print(f'{indent}  }}', file=body)
            return

        if self.element in simpletypes:
            print(f'{indent}    {self.element} * {self.name} = ({self.element} *){self.name}_laddr;', file=body)
        elif self.element in flattypes:
            print(f'{indent}    {namespace}_{self.element}_t * {self.name} = ({namespace}_{self.element}_t *){self.name}_laddr;', file=body)
        else:
            print(f'{indent}    {namespace}_{self.element}_global_t * {self.name} = ({namespace}_{self.element}_global_t *){self.name}_laddr;', file=body)

        print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)

        if self.element in simpletypes:
            print(f'{indent}      err = fd_bincode_{simpletypes[self.element]}_encode( {self.name}[i], ctx );', file=body)
            print(f'{indent}      if( FD_UNLIKELY( err ) ) return err;', file=body)
        elif self.element in flattypes:
            print(f'{indent}      err = {namespace}_{self.element}_encode( &{self.name}[i], ctx );', file=body)
            print(f'{indent}      if( FD_UNLIKELY( err ) ) return err;', file=body)
        else:
            print(f'{indent}      err = {namespace}_{self.element}_encode_global( &{self.name}[i], ctx );', file=body)
            print(f'{indent}      if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'{indent}    }}', file=body)
        print(f'{indent}  }}', file=body)

    def emitSize(self, inner, indent=''):
        print(f'{indent}  do {{', file=body)
        if self.compact:
            print(f'{indent}    ushort tmp = (ushort)self->{self.name}_len;', file=body)
            print(f'{indent}    size += fd_bincode_compact_u16_size( &tmp );', file=body)
        else:
            print(f'{indent}    size += sizeof(ulong);', file=body)
        if self.element == "uchar":
            print(f'{indent}    size += self->{self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'{indent}    size += self->{self.name}_len * sizeof({self.element});', file=body)
        else:
            print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ )', file=body)
            print(f'{indent}      size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)
        print(f'{indent}  }} while(0);', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        print(f'{indent}  do {{', file=body)
        if self.compact:
            print(f'{indent}    ushort tmp = (ushort)self->{self.name}_len;', file=body)
            print(f'{indent}    size += fd_bincode_compact_u16_size( &tmp );', file=body)
        else:
            print(f'{indent}    size += sizeof(ulong);', file=body)

        ret_type = None
        if self.element in simpletypes:
            ret_type = self.element
        elif self.element in flattypes:
            ret_type = f'{namespace}_{self.element}_t'
        else:
            ret_type = f'{namespace}_{self.element}_global_t'

        print(f'    {ret_type} * {self.name} = self->{self.name}_offset ? ({ret_type} *)fd_type_pun( (uchar *)self + self->{self.name}_offset ) : NULL;', file=body)

        if self.element == "uchar":
            print(f'{indent}    size += self->{self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'{indent}    size += self->{self.name}_len * sizeof({self.element});', file=body)
        elif self.element in flattypes:
            print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ )', file=body)
            print(f'{indent}      size += {namespace}_{self.element}_size( {self.name} + i );', file=body)
        else:
            print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ )', file=body)
            print(f'{indent}      size += {namespace}_{self.element}_size_global( {self.name} + i );', file=body)
        print(f'{indent}  }} while(0);', file=body)


    emitWalkMap = {
        "double" :  lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_DOUBLE,  "double",  level, 0 );', file=body),
        "long" :    lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_LONG,    "long",    level, 0 );', file=body),
        "uint" :    lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_UINT,    "uint",    level, 0 );', file=body),
        "uint128" : lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level, 0 );', file=body),
        "ulong" :   lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level, 0 );', file=body),
        "ushort" :  lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_USHORT,  "ushort",  level, 0 );', file=body),
        "uchar" :   lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );', file=body),
    }

    def emitWalk(self, inner, indent=''):
        # The `serialize` function in Rust's `short_vec` (analogous to our `walk()` implementation) handles serializing
        # the vector's length independently, rather than relying on the Serializer (i.e., the `walk` function callback)
        # to do it. To remain consistent, we have to replicate this behavior here.
        # Reference: https://docs.rs/solana-short-vec/latest/src/solana_short_vec/lib.rs.html#166-185
        # Additionally, does this imply that `short_vec` encodes lengths twice? No, because it uses the `serialize_tuple`
        # callback (which, in Bincode's implementation, does not encode the sequence length) rather than `serialize_seq`.
        # Reference: https://docs.rs/bincode/latest/src/bincode/features/serde/ser.rs.html#226-228 (see the `serialize_seq` implementation above for comparison)
        if self.compact:
            print(f'{indent}  fun( w, &self->{self.name}_len, "{self.name}_len", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1 );', file=body)

        print(f'{indent}  if( self->{self.name}_len ) {{', file=body)
        print(f'{indent}    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );', file=body)
        print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; i++ )', file=body)

        if self.element in VectorMember.emitWalkMap:
            body.write("    ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'{indent}      {namespace}_{self.element}_walk(w, self->{self.name} + i, fun, "{self.element}", level, 0 );', file=body)

        print(f'{indent}    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );', file=body)
        print(f'{indent}  }}', file=body)

# A BitVector is a [Option<Vector<some type>>, len]
# TODO: it would be ideal to use an OptionMember that contains a VectorMember,
# but we can't do this yet. Hence, BitVectorMember re-implements the
# OptionMember implementation with the element set to VectorMember
class BitVectorMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.vector_element = json["element"]
        self.vector_member = VectorMember(container, None, name=f"{self.name}_bitvec", element=self.vector_element)

    def isFlat(self):
        return False

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'  uchar has_{self.name};', file=header)
        self.vector_member.emitMember()
        print(f'  ulong {self.name}_len;', file=header)

    def emitMemberGlobal(self):
        print(f'  uchar has_{self.name};', file=header)
        self.vector_member.emitMemberGlobal()
        print(f'  ulong {self.name}_len;', file=header)

    def emitNew(self, indent=''):
        pass

    def emitDestroy(self, indent=''):
        self.vector_member.emitDestroy()
        print(f'  self->has_{self.name} = 0;', file=body)
        print(f'  self->{self.name}_len = 0;', file=body)

    def emitDecodeFootprint(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    ulong inner_len = 0UL;', file=body)
        print('    err = fd_bincode_bool_decode( &o, ctx );', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('    if( o ) {', file=body)
        self.vector_member.emitDecodeFootprint('    ')
        print('      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'      inner_len = {self.vector_member.name}_len;', file=body)
        print('      if( inner_len==0 ) return FD_BINCODE_ERR_ENCODING;', file=body)
        print('    }', file=body)
        print('    ulong len;', file=body)
        print('    err = fd_bincode_uint64_decode( &len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'    if( len > inner_len * sizeof({self.vector_element}) * 8UL ) return FD_BINCODE_ERR_ENCODING;', file=body)
        print('  }', file=body)

    def emitDecodeInner(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    fd_bincode_bool_decode_unsafe( &o, ctx );', file=body)
        print(f'    self->has_{self.name} = !!o;', file=body)
        print('    if( o ) {', file=body)
        self.vector_member.emitDecodeInner('    ')
        print('    } else {', file=body)
        print(f'      self->{self.vector_member.name} = NULL;', file=body)
        print('    }', file=body)
        print(f'    fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    fd_bincode_bool_decode_unsafe( &o, ctx );', file=body)
        print(f'    self->has_{self.name} = !!o;', file=body)
        print('    if( o ) {', file=body)
        self.vector_member.emitDecodeInnerGlobal('    ')
        print('    }', file=body)
        print(f'    fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print('  }', file=body)

    def emitEncode(self):
        print(f'  err = fd_bincode_bool_encode( self->has_{self.name}, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'  if( self->has_{self.name} ) {{', file=body)
        self.vector_member.emitEncode('  ')
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)
        print(f'  err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitEncodeGlobal(self):
        print(f'  err = fd_bincode_bool_encode( self->has_{self.name}, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'  if( self->has_{self.name} ) {{', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
        self.vector_member.emitEncodeGlobal('  ')
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)
        print(f'  err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitSize(self, inner):
        print('  size += sizeof(char);', file=body)
        print(f'  if( self->has_{self.name} ) {{', file=body)
        self.vector_member.emitSize('', '  ')
        print('  }', file=body)
        print('  size += sizeof(ulong);', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        print(f'{indent}  do {{', file=body)
        print(f'{indent}    size += sizeof(char);', file=body)
        print(f'{indent}    if( self->has_{self.name} ) {{', file=body)
        self.vector_member.emitSizeGlobal('', '  ')
        print(f'{indent}    }}', file=body)
        print(f'{indent}  }} while(0);', file=body)

    def emitWalk(self, inner, indent=''):
        print(f'  if( !self->has_{self.name} ) {{', file=body)
        print(f'    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_NULL, "{self.vector_element}", level, 0 );', file=body)
        print('  } else {', file=body)
        self.vector_member.emitWalk('', '  ')
        print('  }', file=body)
        print(f'  fun( w, &self->{self.name}_len, "{self.name}_len", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );', file=body)

# Class representing fixed-size circular buffer arrays
class StaticVectorMember(TypeNode):
    """
    Represents a fixed-size array that acts as a circular buffer.

    Unlike regular vectors, static vectors have a fixed maximum size but variable
    length. They use offset-based indexing to implement circular buffer behavior.

    Key features:
    - Fixed maximum size at compile time
    - Variable length at runtime (up to max size)
    - Circular buffer indexing with offset
    - Optimized indexing for power-of-2 sizes (uses bitwise AND vs modulo)

    Attributes:
        element: Type of elements stored in the array
        size: Maximum number of elements (None if not specified)
        ignore_underflow: Whether to ignore underflow errors during decoding
    """
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.size = (json["size"] if "size" in json else None)
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def isFixedSize(self):
        return self.element in fixedsizetypes

    def fixedSize(self):
        return 8 + self.size * fixedsizetypes[self.element]

    def isFlat(self):
          return self.element in flattypes

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'  ulong {self.name}_len;', file=header)
        print(f'  ulong {self.name}_size;', file=header)
        print(f'  ulong {self.name}_offset;', file=header)

        if self.element in simpletypes:
            print(f'  {self.element} {self.name}[{self.size}];', file=header)
        else:
            print(f'  {namespace}_{self.element}_t {self.name}[{self.size}];', file=header)

    def emitMemberGlobal(self):
        print(f'  ulong {self.name}_len;', file=header)
        print(f'  ulong {self.name}_size;', file=header)
        print(f'  ulong {self.name}_offset;', file=header)

        if self.element in simpletypes:
            print(f'  {self.element} {self.name}[{self.size}];', file=header)
        elif self.element in flattypes:
            print(f'  {namespace}_{self.element}_t {self.name}[{self.size}];', file=header)
        else:
            print(f'  {namespace}_{self.element}_global_t {self.name}[{self.size}];', file=header)

    def emitNew(self, indent=''):
        size = self.size
        print(f'  self->{self.name}_size = {self.size};', file=body)
        if self.element in simpletypes:
            pass
        else:
            print(f'  for( ulong i=0; i<{size}; i++ )', file=body)
            print(f'    {namespace}_{self.element}_new( self->{self.name} + i );', file=body)

    def emitDecodeFootprint(self):
        print(f'  ulong {self.name}_len;', file=body)
        print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  if( {self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'
        el = el.upper()

        if self.element == "uchar":
            print(f'    err = fd_bincode_bytes_decode_footprint( {self.name}_len, ctx );', file=body)
            print(f'    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

        else:
            print(f'    for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)

            if self.element in simpletypes:
                print(f'      err = fd_bincode_{simpletypes[self.element]}_decode_footprint( ctx );', file=body)
            else:
                print(f'      err = {namespace}_{self.element}_decode_footprint_inner( ctx, total_sz );', file=body)

            print(f'      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
            print('    }', file=body)

        print('  }', file=body)

    def emitDecodeInner(self):
        print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'  self->{self.name}_size = {self.size};', file=body)
        print(f'  self->{self.name}_offset = 0;', file=body)

        if self.element == "uchar":
            print(f'  fd_bincode_bytes_decode_unsafe( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            return

        print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name} + i, ctx );', file=body)
        else:
            print(f'    {namespace}_{self.element}_decode_inner( self->{self.name} + i, alloc_mem, ctx );', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'  self->{self.name}_size = {self.size};', file=body)
        print(f'  self->{self.name}_offset = 0;', file=body)

        if self.element == "uchar":
            print(f'  fd_bincode_bytes_decode_unsafe( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            return

        print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name} + i, ctx );', file=body)
        elif self.element in flattypes:
            print(f'    {namespace}_{self.element}_decode_inner( self->{self.name} + i, alloc_mem, ctx );', file=body)
        else:
            print(f'    {namespace}_{self.element}_decode_inner_global( self->{self.name} + i, alloc_mem, ctx );', file=body)
        print('  }', file=body)

    def emitEncode(self):
        print(f'  err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  if( FD_UNLIKELY( 0 == self->{self.name}_len ) ) return FD_BINCODE_SUCCESS;', file=body)

        if self.element == "uchar":
            #print(f'  err = fd_bincode_bytes_encode( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            print(f' TODO: implement this windowed properly', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            return

        print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
        if self.size is not None and (self.size & (self.size - 1)) == 0:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) & ({self.size} - 1);', file=body)
        else:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) % self->{self.name}_size;', file=body)
        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}[idx], ctx );', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_encode( self->{self.name} + idx, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitEncodeGlobal(self):
        print(f'  err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  if( FD_UNLIKELY( 0 == self->{self.name}_len ) ) return FD_BINCODE_SUCCESS;', file=body)

        if self.element == "uchar":
            #print(f'  err = fd_bincode_bytes_encode( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            print(f' TODO: implement this windowed properly', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            return

        print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
        if self.size is not None and (self.size & (self.size - 1)) == 0:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) & ({self.size} - 1);', file=body)
        else:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) % self->{self.name}_size;', file=body)
        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}[idx], ctx );', file=body)
        elif self.element in flattypes:
            print(f'    err = {namespace}_{self.element}_encode( self->{self.name} + idx, ctx );', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_encode_global( self->{self.name} + idx, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        print('  size += sizeof(ulong);', file=body)
        if self.element == "uchar":
            print(f'  size += self->{self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'  size += self->{self.name}_len * sizeof({self.element});', file=body)
        else:
            print(f'  for( ulong i=0; i<self->{self.name}_len; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        print('  size += sizeof(ulong);', file=body)
        if self.element == "uchar":
            print(f'  size += self->{self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'  size += self->{self.name}_len * sizeof({self.element});', file=body)
        elif self.element in flattypes:
            print(f'  for( ulong i=0; i<self->{self.name}_len; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)
        else:
            print(f'  for( ulong i=0; i<self->{self.name}_len; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size_global( self->{self.name} + i );', file=body)

    emitWalkMap = {
        "double" :  lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_DOUBLE,  "double",  level, 0 );', file=body),
        "long" :    lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_LONG,    "long",    level, 0 );', file=body),
        "uint" :    lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_UINT,    "uint",    level, 0 );', file=body),
        "uint128" : lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level, 0 );', file=body),
        "ulong" :   lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level, 0 );', file=body),
        "ushort" :  lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_USHORT,  "ushort",  level, 0 );', file=body)
    }

    def emitWalk(self, inner, indent=''):
        if self.element == "uchar":
            print(f'  TODO: IMPLEMENT', file=body),
            return

        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR, "{self.element}[]", level++, 0 );', file=body)
        print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
        if self.size is not None and (self.size & (self.size - 1)) == 0:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) & ({self.size} - 1);', file=body)
        else:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) % self->{self.name}_size;', file=body)
        if self.element in VectorMember.emitWalkMap:
            body.write("  ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'    {namespace}_{self.element}_walk( w, self->{self.name} + idx, fun, "{self.element}", level, 0 );', file=body)
        print('  }', file=body)
        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.element}[]", level--, 0 );', file=body)

class StringMember(VectorMember):
    def __init__(self, container, json):
        json["element"] = "uchar"
        super().__init__(container, json)
        self.compact = False
        self.ignore_underflow = False

    def isFlat(self):
        return False

    def emitDecodeFootprint(self):
        print(f'  ulong {self.name}_len;', file=body)
        print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  *total_sz += {self.name}_len;', file=body)
        print(f'  if( {self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'
        el = el.upper()

        print(f'    err = fd_bincode_bytes_decode_footprint( {self.name}_len, ctx );', file=body)
        print(f'    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'    err = !fd_utf8_verify( (char const *) ctx->data - {self.name}_len, {self.name}_len );', file=body)
        print(f'    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

        print('  }', file=body)

class DequeMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.min = json.get("min", None)
        self.max = json.get("max", None)
        self.growth = (json["growth"] if "growth" in json else None)

    def isFlat(self):
        return False

    def elem_type(self):
        if self.element in simpletypes:
            return self.element
        else:
            return f'{namespace}_{self.element}_t'

    def elem_type_global(self):
        if self.element in simpletypes:
            return self.element
        else:
            return f'{namespace}_{self.element}_global_t'

    def prefix(self):
        return f'deq_{self.elem_type()}'

    def prefix_global(self):
        return f'deq_{self.elem_type_global()}'

    def emitPreamble(self):
        dp = self.prefix()
        if dp in preambletypes:
            return
        preambletypes.add(dp)
        element_type = self.elem_type()
        print("#define DEQUE_NAME " + dp, file=header)
        print("#define DEQUE_T " + element_type, file=header)
        print('#include "../../util/tmpl/fd_deque_dynamic.c"', file=header)
        print("#undef DEQUE_NAME", file=header)
        print("#undef DEQUE_T", file=header)
        print("#undef DEQUE_MAX", file=header)
        print(f'static inline {element_type} *', file=header)
        print(f'{dp}_join_new( void * * alloc_mem, ulong max ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {dp}_align() );', file=header)
        print(f'  void * deque_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {dp}_footprint( max );', file=header)
        print(f'  return {dp}_join( {dp}_new( deque_mem, max ) );', file=header)
        print("}", file=header)
        print("", file=header)
        dp_global = self.prefix_global()

        if self.element in flattypes:
            return
        if dp_global in preambletypes:
            return
        element_type_global = self.elem_type_global()
        print("#define DEQUE_NAME " + dp_global, file=header)
        print("#define DEQUE_T " + element_type_global, file=header)
        print('#include "../../util/tmpl/fd_deque_dynamic.c"', file=header)
        print("#undef DEQUE_NAME", file=header)
        print("#undef DEQUE_T", file=header)
        print("#undef DEQUE_MAX", file=header)
        print(f'static inline {element_type_global} *', file=header)
        print(f'{dp_global}_join_new( void * * alloc_mem, ulong max ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {dp_global}_align() );', file=header)
        print(f'  void * deque_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {dp_global}_footprint( max );', file=header)
        print(f'  return {dp_global}_join( {dp_global}_new( deque_mem, max ) );', file=header)
        print("}", file=header)

    def emitPostamble(self):
        pass

    def emitMember(self):
        bound_tag = ""
        if self.min:
            bound_tag = f" (min cnt {self.min})"
        if self.max:
            bound_tag += f" (max cnt {self.max})"
        print(f'  {self.elem_type()} * {self.name}; /* fd_deque_dynamic{bound_tag} */', file=header)

    def emitMemberGlobal(self):
        if self.min:
            bound_tag = f" (min cnt {self.min})"
        elif self.max:
            bound_tag = f" (max cnt {self.max})"
        else:
            bound_tag = ""
        print(f'  ulong {self.name}_offset; /* fd_deque_dynamic{bound_tag} */', file=header)

    def emitOffsetJoin(self, type_name):
        ret_type = None
        if self.element in simpletypes:
            ret_type = self.element
        elif self.element in flattypes:
            ret_type = f'{namespace}_{self.element}_t'
        else:
            ret_type = f'{namespace}_{self.element}_global_t'

        prefix = self.prefix() if self.element in flattypes else self.prefix_global()

        print(f'static FD_FN_UNUSED {ret_type} * {type_name}_{self.name}_join( {type_name}_global_t * type ) {{ // deque', file=header)
        print(f'  return type->{self.name}_offset ? ({ret_type} *){prefix}_join( fd_type_pun( (uchar *)type + type->{self.name}_offset ) ) : NULL;', file=header)
        print(f'}}', file=header)

    def emitNew(self, indent=''):
        pass

    def emitDecodeFootprint(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY( err ) ) return err;', file=body)

        if self.max:
            print(f'  if( FD_UNLIKELY( {self.name}_len > {self.max} ) ) return FD_BINCODE_ERR_ENCODING;', file=body)
        if self.min:
            print(f'  ulong {self.name}_max = fd_ulong_max( {self.name}_len, {self.min} );', file=body)
            print(f'  *total_sz += {self.prefix()}_align() + {self.prefix()}_footprint( {self.name}_max );', file=body)
        else:
            print(f'  ulong {self.name}_max = {self.name}_len == 0 ? 1 : {self.name}_len;', file=body)
            print(f'  *total_sz += {self.prefix()}_align() + {self.prefix()}_footprint( {self.name}_max ) ;', file=body)

        if self.element in fuzzytypes:
            fixedsize = fixedsizetypes[self.element]
            print(f'  ulong {self.name}_sz;', file=body)
            print(f'  if( FD_UNLIKELY( __builtin_umull_overflow( {self.name}_len, {fixedsize}, &{self.name}_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;', file=body)
            print(f'  err = fd_bincode_bytes_decode_footprint( {self.name}_sz, ctx );', file=body)
            print(f'  if( FD_UNLIKELY( err ) ) return err;', file=body)
        else:
            print(f'  for( ulong i = 0; i < {self.name}_len; ++i ) {{', file=body)

            if self.element in simpletypes:
                print(f'    err = fd_bincode_{simpletypes[self.element]}_decode_footprint( ctx );', file=body)
            else:
                print(f'    err = {namespace}_{self.element}_decode_footprint_inner( ctx, total_sz );', file=body)
            print(f'    if( FD_UNLIKELY( err ) ) return err;', file=body)

            print('  }', file=body)

    def emitDecodeInner(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe( &{self.name}_len, ctx );', file=body)

        if self.min:
            print(f'  ulong {self.name}_max = fd_ulong_max( {self.name}_len, {self.min} );', file=body)
            print(f'  self->{self.name} = {self.prefix()}_join_new( alloc_mem, {self.name}_max );', file=body)
        else:
            print(f'  self->{self.name} = {self.prefix()}_join_new( alloc_mem, {self.name}_len );', file=body)

        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {self.elem_type()} * elem = {self.prefix()}_push_tail_nocopy( self->{self.name} );', file=body);

        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe( elem, ctx );', file=body)
        else:
            print(f'    {namespace}_{self.element}_new( elem );', file=body)
            print(f'    {namespace}_{self.element}_decode_inner( elem, alloc_mem, ctx );', file=body)

        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe( &{self.name}_len, ctx );', file=body)

        prefix = self.prefix() if self.element in flattypes else self.prefix_global()
        elem_type = self.elem_type() if self.element in flattypes else self.elem_type_global()

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {prefix}_align() );', file=body)

        deque_type = "error"
        if self.element in simpletypes:
            deque_type = f"{self.element}"
        elif self.element in flattypes:
            deque_type = f"{namespace}_{self.element}_t"
        else:
            deque_type = f"{namespace}_{self.element}_global_t"

        if self.min:
            print(f'  ulong {self.name}_max = fd_ulong_max( {self.name}_len, {self.min} );', file=body)
            print(f'  {deque_type} * {self.name} = {prefix}_join_new( alloc_mem, {self.name}_max );', file=body)
        else:
            print(f'  {deque_type} * {self.name} = {prefix}_join_new( alloc_mem, {self.name}_len );', file=body)

        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {elem_type} * elem = {prefix}_push_tail_nocopy( {self.name} );', file=body)

        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe( elem, ctx );', file=body)
        else:
            # TODO: The Global type should have its own _new() call, but
            # functionally it's the same as the non-global _new().
            print(f'    {namespace}_{self.element}_new( ({namespace}_{self.element}_t*)fd_type_pun( elem ) );', file=body)
            if self.element in flattypes:
                print(f'    {namespace}_{self.element}_decode_inner( elem, alloc_mem, ctx );', file=body)
            else:
                print(f'    {namespace}_{self.element}_decode_inner_global( elem, alloc_mem, ctx );', file=body)
        print('  }', file=body)
        leave = f'{namespace}_{self.element}_leave' if self.element in flattypes else f'{namespace}_{self.element}_global_leave'
        print(f'  self->{self.name}_offset = (ulong){prefix}_leave( {self.name} ) - (ulong)struct_mem;', file=body)


    def emitEncode(self):
        print(f'  if( self->{self.name} ) {{', file=body)

        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){self.prefix()}_cnt( self->{self.name} );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt( self->{self.name} );', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'    for( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
        print(f'      {self.elem_type()} const * ele = {self.prefix()}_iter_ele_const( self->{self.name}, iter );', file=body)

        if self.element in simpletypes:
            print(f'      err = fd_bincode_{simpletypes[self.element]}_encode( ele[0], ctx );', file=body)
        else:
            print(f'      err = {namespace}_{self.element}_encode( ele, ctx );', file=body)
            print('      if( FD_UNLIKELY( err ) ) return err;', file=body)

        print('    }', file=body)

        print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitEncodeGlobal(self):
        print(f'  if( self->{self.name}_offset ) {{', file=body)

        print(f'  uchar * {self.name}_laddr = (uchar*)self + self->{self.name}_offset;', file=body)
        prefix = self.prefix() if self.element in flattypes else self.prefix_global()
        elem_type = self.elem_type() if self.element in flattypes else self.elem_type_global()
        print(f'   {elem_type} * {self.name} = {prefix}_join( {self.name}_laddr );', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){prefix}_cnt( {self.name} );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = {prefix}_cnt( {self.name} );', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'    for( {prefix}_iter_t iter = {prefix}_iter_init( {self.name} ); !{prefix}_iter_done( {self.name}, iter ); iter = {prefix}_iter_next( {self.name}, iter ) ) {{', file=body)
        print(f'      {elem_type} const * ele = {prefix}_iter_ele_const( {self.name}, iter );', file=body)

        if self.element in simpletypes:
            print(f'      err = fd_bincode_{simpletypes[self.element]}_encode( ele[0], ctx );', file=body)
        elif self.element in flattypes:
            print(f'      err = {namespace}_{self.element}_encode( ele, ctx );', file=body)
            print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
        else:
            print(f'      err = {namespace}_{self.element}_encode_global( ele, ctx );', file=body)
            print('      if( FD_UNLIKELY( err ) ) return err;', file=body)

        print('    }', file=body)

        print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        print(f'  if( self->{self.name} ) {{', file=body)

        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){self.prefix()}_cnt( self->{self.name} );', file=body)
            print(f'    size += fd_bincode_compact_u16_size( &{self.name}_len );', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)

        if self.element == "uchar":
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += {self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += {self.name}_len * sizeof({self.element});', file=body)
        else:
            print(f'    for( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );', file=body)
            print(f'      size += {namespace}_{self.element}_size( ele );', file=body)
            print('    }', file=body)

        print('  } else {', file=body)
        if self.compact:
            print('    size += 1;', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        print('  }', file=body)

    def emitSizeGlobal(self, inner):
        print(f'  if( self->{self.name}_offset!=0 ) {{', file=body)

        ret_type = None
        if self.element in simpletypes:
            ret_type = self.element
        elif self.element in flattypes:
            ret_type = f'{namespace}_{self.element}_t'
        else:
            ret_type = f'{namespace}_{self.element}_global_t'
        prefix = self.prefix() if self.element in flattypes else self.prefix_global()

        print(f'    {ret_type} * {self.name} = ({ret_type} *){prefix}_join( fd_type_pun( (uchar *)self + self->{self.name}_offset ) );', file=body)

        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){self.prefix()}_cnt( {self.name} );', file=body)
            print(f'    size += fd_bincode_compact_u16_size( &{self.name}_len );', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)

        if self.element == "uchar":
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt({self.name});', file=body)
            print(f'    size += {self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt({self.name});', file=body)
            print(f'    size += {self.name}_len * sizeof({self.element});', file=body)
        elif self.element in flattypes:
            print(f'    for( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( {self.name} ); !{self.prefix()}_iter_done( {self.name}, iter ); iter = {self.prefix()}_iter_next( {self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( {self.name}, iter );', file=body)
            print(f'      size += {namespace}_{self.element}_size( ele );', file=body)
            print('    }', file=body)
        else:
            print(f'    for( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( {self.name} ); !{self.prefix()}_iter_done( {self.name}, iter ); iter = {self.prefix()}_iter_next( {self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type_global()} * ele = {self.prefix()}_iter_ele( {self.name}, iter );', file=body)
            print(f'      size += {namespace}_{self.element}_size_global( ele );', file=body)
            print('    }', file=body)

        print('  } else {', file=body)
        if self.compact:
            print('    size += 1;', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        print('  }', file=body)


    def emitWalk(self, inner):
        print(
            f'''
  /* Walk deque */
  fun( w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_ARR, "{self.name}", level++, 0 );
  if( self->{self.name} ) {{
    for( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} );
         !{self.prefix()}_iter_done( self->{self.name}, iter );
         iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{
      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );''',
            file=body
        )

        if self.element == "uchar":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );', file=body),
        elif self.element == "ulong":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level, 0 );', file=body),
        elif self.element == "uint":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level, 0 );', file=body),
        else:
            print(f'      {namespace}_{self.element}_walk(w, ele, fun, "{self.name}", level, 0 );', file=body)

        print(f'''    }}
  }}
  fun( w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.name}", level--, 0 );
  /* Done walking deque */
''', file=body)


class MapMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.key = json["key"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.minalloc = (int(json["minalloc"]) if "minalloc" in json else 0)

    def elem_type(self):
        if self.element in simpletypes:
            return self.element
        else:
            return f'{namespace}_{self.element}_t'

    def elem_type_global(self):
        if self.element in simpletypes:
            return self.element
        else:
            return f'{namespace}_{self.element}_global_t'

    def emitPreamble(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        if mapname in preambletypes:
            return
        preambletypes.add(mapname)
        nodename = element_type + "_mapnode"
        print(f"typedef struct {nodename} {nodename}_t;", file=header)
        print(f"#define REDBLK_T {nodename}_t", file=header)
        print(f"#define REDBLK_NAME {mapname}", file=header)
        print(f"#define REDBLK_IMPL_STYLE 1", file=header)
        print(f'#include "../../util/tmpl/fd_redblack.c"', file=header)
        print(f"struct {nodename} {{", file=header)
        print(f"    {element_type} elem;", file=header)
        print(f"    ulong redblack_parent;", file=header)
        print(f"    ulong redblack_left;", file=header)
        print(f"    ulong redblack_right;", file=header)
        print(f"    int redblack_color;", file=header)
        print("};", file=header)
        print(f'static inline {nodename}_t *', file=header)
        print(f'{mapname}_join_new( void * * alloc_mem, ulong len ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {mapname}_align() );', file=header)
        print(f'  void * map_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {mapname}_footprint( len );', file=header)
        print(f'  return {mapname}_join( {mapname}_new( map_mem, len ) );', file=header)
        print("}", file=header)
        if not self.produce_global or self.element in flattypes:
            return
        element_type = self.elem_type_global()
        mapname = element_type + "_map"
        if mapname in preambletypes:
            return
        preambletypes.add(mapname)
        nodename = element_type + "_mapnode"
        print(f"typedef struct {nodename} {nodename}_t;", file=header)
        print(f"#define REDBLK_T {nodename}_t", file=header)
        print(f"#define REDBLK_NAME {mapname}", file=header)
        print(f"#define REDBLK_IMPL_STYLE 1", file=header)
        print(f'#include "../../util/tmpl/fd_redblack.c"', file=header)
        print(f"struct {nodename} {{", file=header)
        print(f"    {element_type} elem;", file=header)
        print(f"    ulong redblack_parent;", file=header)
        print(f"    ulong redblack_left;", file=header)
        print(f"    ulong redblack_right;", file=header)
        print(f"    int redblack_color;", file=header)
        print("};", file=header)
        print(f'static inline {nodename}_t *', file=header)
        print(f'{mapname}_join_new( void * * alloc_mem, ulong len ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == len ) ) len = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {mapname}_align() );', file=header)
        print(f'  void * map_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {mapname}_footprint( len );', file=header)
        print(f'  return {mapname}_join( {mapname}_new( map_mem, len ) );', file=header)
        print("}", file=header)


    def emitPostamble(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        if mapname in postambletypes:
            return
        postambletypes.add(mapname)
        nodename = element_type + "_mapnode_t"
        print(f'#define REDBLK_T {nodename}', file=body)
        print(f'#define REDBLK_NAME {mapname}', file=body)
        print(f'#define REDBLK_IMPL_STYLE 2', file=body)
        print(f'#include "../../util/tmpl/fd_redblack.c"', file=body)
        print(f'long {mapname}_compare( {nodename} * left, {nodename} * right ) {{', file=body)
        key = self.key
        if (key == "pubkey" or key == "account" or key == "key"):
            print(f'  return memcmp( left->elem.{key}.uc, right->elem.{key}.uc, sizeof(right->elem.{key}) );', file=body)
        else:
            print(f'  return (long)( left->elem.{key} - right->elem.{key} );', file=body)
        print("}", file=body)
        if self.element in flattypes:
            return
        if not self.produce_global or self.element in flattypes:
            return
        element_type = self.elem_type_global()
        mapname = element_type + "_map"
        if mapname in postambletypes:
            return
        postambletypes.add(mapname)
        nodename = element_type + "_mapnode_t"
        print(f'#define REDBLK_T {nodename}', file=body)
        print(f'#define REDBLK_NAME {mapname}', file=body)
        print(f'#define REDBLK_IMPL_STYLE 2', file=body)
        print(f'#include "../../util/tmpl/fd_redblack.c"', file=body)
        print(f'long {mapname}_compare( {nodename} * left, {nodename} * right ) {{', file=body)
        key = self.key
        if (key == "pubkey" or key == "account" or key == "key"):
            print(f'  return memcmp( left->elem.{key}.uc, right->elem.{key}.uc, sizeof(right->elem.{key}) );', file=body)
        else:
            print(f'  return (long)( left->elem.{key} - right->elem.{key} );', file=body)
        print("}", file=body)


    def emitMember(self):
        element_type = self.elem_type()
        print(f'  {element_type}_mapnode_t * {self.name}_pool;', file=header)
        print(f'  {element_type}_mapnode_t * {self.name}_root;', file=header)

    def emitMemberGlobal(self):
        element_type = self.elem_type()
        print(f'  ulong {self.name}_pool_offset;', file=header)
        print(f'  ulong {self.name}_root_offset;', file=header)

    def emitOffsetJoin(self, type_name):
        element_type = self.elem_type() if self.element in flattypes else self.elem_type_global()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'static FD_FN_UNUSED {nodename} * {type_name}_{self.name}_pool_join( {type_name}_global_t const * type ) {{', file=header)
        print(f'  if( FD_UNLIKELY( !type ) ) return NULL;', file=header)
        print(f'  return !!type->{self.name}_pool_offset ? ({nodename} *){mapname}_join( fd_type_pun( (uchar *)type + type->{self.name}_pool_offset ) ) : NULL;', file=header)
        print(f'}}', file=header)

        print(f'static FD_FN_UNUSED {nodename} * {type_name}_{self.name}_root_join( {type_name}_global_t const * type ) {{', file=header)
        print(f'  if( FD_UNLIKELY( !type ) ) return NULL;', file=header)
        print(f'  return !!type->{self.name}_root_offset ? ({nodename} *)fd_type_pun( (uchar *)type + type->{self.name}_root_offset ) : NULL;', file=header)
        print(f'}}', file=header)

        print(f'static FD_FN_UNUSED void {type_name}_{self.name}_pool_update( {type_name}_global_t * type, {nodename} * pool ) {{', file=header)
        print(f'  type->{self.name}_pool_offset = !!pool ? (ulong){mapname}_leave( pool ) - (ulong)type : 0UL;', file=header)
        print(f'}}', file=header)

        print(f'static FD_FN_UNUSED void {type_name}_{self.name}_root_update( {type_name}_global_t * type, {nodename} * root ) {{', file=header)
        print(f'  type->{self.name}_root_offset = !!root ? (ulong)root - (ulong)type : 0UL;', file=header)
        print(f'}}', file=header)

    def emitNew(self, indent=''):
        pass

    def emitDecodeFootprint(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        if self.compact:
            print(f'  ushort {self.name}_len = 0;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len = 0UL;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)

        if self.minalloc > 0:
            print(f'  ulong {self.name}_cnt = fd_ulong_max( {self.name}_len, {self.minalloc} );', file=body)
        else:
            print(f'  ulong {self.name}_cnt = !!{self.name}_len ? {self.name}_len : 1;', file=body)
        print(f'  *total_sz += {mapname}_align() + {mapname}_footprint( {self.name}_cnt );', file=body)

        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    err = {namespace}_{self.element}_decode_footprint_inner( ctx, total_sz );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeInner(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe( &{self.name}_len, ctx );', file=body)
        if self.minalloc > 0:
            print(f'  self->{self.name}_pool = {mapname}_join_new( alloc_mem, fd_ulong_max( {self.name}_len, {self.minalloc} ) );', file=body)
        else:
            print(f'  self->{self.name}_pool = {mapname}_join_new( alloc_mem, {self.name}_len );', file=body)
        print(f'  self->{self.name}_root = NULL;', file=body)
        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {nodename} * node = {mapname}_acquire( self->{self.name}_pool );', file=body)
        print(f'    {namespace}_{self.element}_new( &node->elem );', file=body)
        print(f'    {namespace}_{self.element}_decode_inner( &node->elem, alloc_mem, ctx );', file=body)
        print(f'    {nodename} * out = NULL;;', file=body)
        print(f'    {mapname}_insert_or_replace( self->{self.name}_pool, &self->{self.name}_root, node, &out );', file=body)
        print(f'    if( out != NULL ) {{', file=body)
        print(f'      {mapname}_release( self->{self.name}_pool, out );', file=body)
        print(f'    }}', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        element_type = self.elem_type() if self.element in flattypes else self.elem_type_global()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe( &{self.name}_len, ctx );', file=body)

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {mapname}_align() );', file=body)

        if self.minalloc > 0:
            print(f'  {nodename} * {self.name}_pool = {mapname}_join_new( alloc_mem, fd_ulong_max( {self.name}_len, {self.minalloc} ) );', file=body)
        else:
            print(f'  {nodename} * {self.name}_pool = {mapname}_join_new( alloc_mem, {self.name}_len );', file=body)
        print(f'  {nodename} * {self.name}_root = NULL;', file=body)
        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {nodename} * node = {mapname}_acquire( {self.name}_pool );', file=body)
        print(f'    {namespace}_{self.element}_new( ({namespace}_{self.element}_t *)fd_type_pun(&node->elem) );', file=body)
        if self.element in flattypes:
            print(f'    {namespace}_{self.element}_decode_inner( &node->elem, alloc_mem, ctx );', file=body)
        else:
            print(f'    {namespace}_{self.element}_decode_inner_global( &node->elem, alloc_mem, ctx );', file=body)
        print(f'    {mapname}_insert( {self.name}_pool, &{self.name}_root, node );', file=body)
        print(f'  }}', file=body)

        print(f'  self->{self.name}_pool_offset = (ulong){mapname}_leave( {self.name}_pool ) - (ulong)struct_mem;', file=body)
        print(f'  self->{self.name}_root_offset = (ulong){self.name}_root - (ulong)struct_mem;', file=body)

    def emitEncode(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  if( self->{self.name}_root ) {{', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){mapname}_size( self->{self.name}_pool, self->{self.name}_root );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = {mapname}_size( self->{self.name}_pool, self->{self.name}_root );', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'    for( {nodename} * n = {mapname}_minimum( self->{self.name}_pool, self->{self.name}_root ); n; n = {mapname}_successor( self->{self.name}_pool, n ) ) {{', file=body);
        print(f'      err = {namespace}_{self.element}_encode( &n->elem, ctx );', file=body)
        print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('    }', file=body)
        print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitEncodeGlobal(self):
        element_type = self.elem_type() if self.element in flattypes else self.elem_type_global()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"
        print(f'  {nodename} * {self.name}_root = {mapname}_join( (uchar *)self + self->{self.name}_root_offset );', file=body)
        print(f'  {nodename} * {self.name}_pool = {mapname}_join( (uchar *)self + self->{self.name}_pool_offset );', file=body)

        print(f'  if( {self.name}_root ) {{', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){mapname}_size( {self.name}_pool, {self.name}_root );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = {mapname}_size( {self.name}_pool, {self.name}_root );', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'    for( {nodename} * n = {mapname}_minimum( {self.name}_pool, {self.name}_root ); n; n = {mapname}_successor( {self.name}_pool, n ) ) {{', file=body);
        if self.element in flattypes:
            print(f'      err = {namespace}_{self.element}_encode( &n->elem, ctx );', file=body)
        else:
            print(f'      err = {namespace}_{self.element}_encode_global( &n->elem, ctx );', file=body)
        print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('    }', file=body)
        print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'    ulong {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  if( self->{self.name}_root ) {{', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){mapname}_size( self->{self.name}_pool, self->{self.name}_root );', file=body)
            print(f'    size += fd_bincode_compact_u16_size( &{self.name}_len );', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        print(f'    ulong max = {mapname}_max( self->{self.name}_pool );', file=body)
        print(f'    size += {mapname}_footprint( max );', file=body)
        print(f'    for( {nodename} * n = {mapname}_minimum( self->{self.name}_pool, self->{self.name}_root ); n; n = {mapname}_successor( self->{self.name}_pool, n ) ) {{', file=body);
        print(f'      size += {namespace}_{self.element}_size( &n->elem ) - sizeof({self.elem_type()});', file=body)
        print('    }', file=body)
        print('  } else {', file=body)
        if self.compact:
            print('    size += 1;', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        print('  }', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        element_type = self.elem_type() if self.element in flattypes else self.elem_type_global()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  {nodename} * {self.name}_pool = !!self->{self.name}_pool_offset ? ({nodename} *){mapname}_join( fd_type_pun( (uchar *)self + self->{self.name}_pool_offset ) ) : NULL;', file=body)
        print(f'  {nodename} * {self.name}_root = !!self->{self.name}_root_offset ? ({nodename} *)fd_type_pun( (uchar *)self + self->{self.name}_root_offset ) : NULL;', file=body)
        print(f'  if( {self.name}_root ) {{', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){mapname}_size( {self.name}_pool, {self.name}_root );', file=body)
            print(f'    size += fd_bincode_compact_u16_size( &{self.name}_len );', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        print(f'    ulong max = {mapname}_max( {self.name}_pool );', file=body)
        print(f'    size += {mapname}_footprint( max );', file=body)
        print(f'    for( {nodename} * n = {mapname}_minimum( {self.name}_pool, {self.name}_root ); n; n = {mapname}_successor( {self.name}_pool, n ) ) {{', file=body);
        if self.element in flattypes:
            print(f'      size += {namespace}_{self.element}_size( &n->elem ) - sizeof({self.elem_type()});', file=body)
        else:
            print(f'      size += {namespace}_{self.element}_size_global( &n->elem ) - sizeof({self.elem_type()});', file=body)
        print('    }', file=body)
        print('  } else {', file=body)
        if self.compact:
            print('    size += 1;', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        print('  }', file=body)

    def emitWalk(self, inner):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"
        print(f'  if( self->{self.name}_root ) {{', file=body)
        print(f'    for( {nodename} * n = {mapname}_minimum(self->{self.name}_pool, self->{self.name}_root ); n; n = {mapname}_successor( self->{self.name}_pool, n ) ) {{', file=body);

        if self.element == "uchar":
            print('      fun(w, &n->elem, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );', file=body),
        elif self.element == "ulong":
            print('      fun(w, &n->elem, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level, 0 );', file=body),
        elif self.element == "uint":
            print('      fun(w, &n->elem, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level, 0 );', file=body),
        else:
            print(f'      {namespace}_{self.element}_walk(w, &n->elem, fun, "{self.name}", level, 0 );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)


# FIXME: The partition member is currently implement in a very hacky manner
# and does not properly support global types where the partition has members
# which are local pointers. The partition is currently only used for
# fd_stake_reward_t which contains no pointers.
class PartitionMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.dlist_t = json["dlist_t"]
        self.dlist_n = json["dlist_n"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.dlist_max = (int(json["dlist_max"]) if "dlist_max" in json else 0)

    def emitPreamble(self):
        pool_name = self.dlist_n + "_pool"
        dlist_name = self.dlist_n + "_dlist"

        print(f"#define POOL_NAME {pool_name}", file=header)
        print(f"#define POOL_T {self.dlist_t}", file=header)
        print(f"#define POOL_NEXT parent", file=header)
        print(f"#include \"../../util/tmpl/fd_pool.c\"", file=header)
        print(f'static inline {self.dlist_t} *', file=header)
        print(f'{pool_name}_join_new( void * * alloc_mem, ulong num ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {pool_name}_align() );', file=header)
        print(f'  void * pool_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {pool_name}_footprint( num );', file=header)
        print(f'  return {pool_name}_join( {pool_name}_new( pool_mem, num ) );', file=header)
        print("}", file=header)
        print(f"#define DLIST_NAME {dlist_name}", file=header)
        print(f"#define DLIST_ELE_T {self.dlist_t}", file=header)
        print(f'#include "../../util/tmpl/fd_dlist.c"', file=header)
        print(f'static inline {dlist_name}_t *', file=header)
        print(f'{dlist_name}_join_new( void * * alloc_mem, ulong num ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {dlist_name}_align() );', file=header)
        print(f'  void * dlist_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {dlist_name}_footprint();', file=header)
        print(f'  return {dlist_name}_join( {dlist_name}_new( dlist_mem ) );', file=header)
        print("}", file=header)

    def emitPostamble(self):
        pass

    def emitMember(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=header)
        else:
            print(f'  ulong {self.name}_len;', file=header)
        print(f'  ulong {self.name}_lengths[{self.dlist_max}];', file=header)
        print(f'  {self.dlist_n}_dlist_t * {self.name};', file=header)
        print(f'  {self.dlist_t} * pool;', file=header)

    def emitMemberGlobal(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=header)
        else:
            print(f'  ulong {self.name}_len;', file=header)
        print(f'  ulong {self.name}_lengths[{self.dlist_max}];', file=header)
        print(f'  ulong {self.name}_offset;', file=header)
        print(f'  ulong pool_offset;', file=header)

    def emitNew(self, indent=''):
        pass

    def emitDecodeFootprint(self):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  ulong total_count = 0UL;', file=body)
        print(f'  ulong {self.name}_lengths[{self.dlist_max}];', file=body)
        print(f'  for( ulong i=0; i<{self.dlist_max}; i++ ) {{', file=body)
        print(f'    err = fd_bincode_uint64_decode( {self.name}_lengths + i, ctx );', file=body)
        print(f'    total_count+={self.name}_lengths[ i ];', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('  }', file=body)

        print(f'  *total_sz += {pool_name}_align() + {pool_name}_footprint( total_count );', file=body)
        print(f'  *total_sz += {dlist_name}_align() + {dlist_name}_footprint()*{self.name}_len;', file=body)

        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    err = {dlist_t.rstrip("_t")}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'    if( FD_UNLIKELY ( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeInner(self):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"

        if self.compact:
            print(f'  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'  ulong total_count = 0UL;', file=body)
        print(f'  for( ulong i=0; i < {self.dlist_max}; i++ ) {{', file=body)
        print(f'    fd_bincode_uint64_decode_unsafe( self->{self.name}_lengths + i, ctx );', file=body)
        print(f'    total_count += self->{self.name}_lengths[ i ];', file=body)
        print('  }', file=body)

        print(f'  self->pool = {pool_name}_join_new( alloc_mem, total_count );', file=body)
        print(f'  self->{self.name} = {dlist_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)

        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
        print(f'    {dlist_name}_new( &self->{self.name}[ i ] );', file=body)
        print(f'    for( ulong j=0; j < self->{self.name}_lengths[ i ]; j++ ) {{', file=body)
        print(f'      {dlist_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'      {dlist_t.rstrip("_t")}_new( ele );', file=body)
        print(f'      {dlist_t.rstrip("_t")}_decode_inner( ele, alloc_mem, ctx );', file=body)
        print(f'      {dlist_name}_ele_push_tail( &self->{self.name}[ i ], ele, self->pool );', file=body)
        print('    }', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"

        if self.compact:
            print(f'  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'  ulong total_count = 0UL;', file=body)
        print(f'  for( ulong i=0; i < {self.dlist_max}; i++ ) {{', file=body)
        print(f'    fd_bincode_uint64_decode_unsafe( self->{self.name}_lengths + i, ctx );', file=body)
        print(f'    total_count += self->{self.name}_lengths[ i ];', file=body)
        print('  }', file=body)

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {pool_name}_align() );', file=body)
        print(f'  {self.dlist_t} * pool = {pool_name}_join_new( alloc_mem, total_count );', file=body)

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {dlist_name}_align() );', file=body)
        print(f'  {self.dlist_n}_dlist_t * {self.name} = {dlist_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)
        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
        print(f'    {dlist_name}_new( &{self.name}[ i ] );', file=body)
        print(f'    for( ulong j=0; j < self->{self.name}_lengths[ i ]; j++ ) {{', file=body)
        print(f'      {dlist_t} * ele = {pool_name}_ele_acquire( pool );', file=body)
        print(f'      {dlist_t.rstrip("_t")}_new( ele );', file=body)
        print(f'      {dlist_t.rstrip("_t")}_decode_inner( ele, alloc_mem, ctx );', file=body)
        print(f'      {dlist_name}_ele_push_tail( &{self.name}[ i ], ele, pool );', file=body)
        print('    }', file=body)
        print('  }', file=body)
        print(f'  self->pool_offset  = (ulong){pool_name}_leave( pool ) - (ulong)struct_mem;', file=body)
        print(f'  self->{self.name}_offset = (ulong){dlist_name}_leave( {self.name} ) - (ulong)struct_mem;', file=body)


    def emitEncode(self):
        name = self.name
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t

        print(f'  if( self->{name} ) {{', file=body)
        if self.compact:
            print(f'    err = fd_bincode_compact_u16_encode( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'    err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)

        print(f'    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'    for( ulong i=0; i < {self.dlist_max}; i++ ) {{', file=body)
        print(f'      err = fd_bincode_uint64_encode( self->{self.name}_lengths[ i ], ctx );', file=body)
        print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('    }', file=body)

        print(f'    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
        print(f'      for( {dlist_name}_iter_t iter = {dlist_name}_iter_fwd_init( &self->{self.name}[ i ], self->pool );', file=body)
        print(f'           !{dlist_name}_iter_done( iter, &self->{self.name}[ i ], self->pool );', file=body);
        print(f'           iter = {dlist_name}_iter_fwd_next( iter, &self->{self.name}[ i ], self->pool ) ) {{', file=body);
        print(f'        {dlist_t} * ele = {dlist_name}_iter_ele( iter, &self->{self.name}[ i ], self->pool );', file=body)
        print(f'        err = {dlist_t.rstrip("_t")}_encode( ele, ctx );', file=body)
        print('        if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('      }', file=body)
        print('    }', file=body)
        print('  } else {', file=body)

        if self.compact:
            print(f'    err = fd_bincode_compact_u16_encode( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'    err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitEncodeGlobal(self):
        pass


    def emitSize(self, inner):
        name = self.name
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool = self.dlist_n + "_pool"

        if self.compact:
            print(f'  ushort {name}_len = (ushort){pool}_used( self->pool );', file=body)
            print(f'  size += fd_bincode_compact_u16_size( &{name}_len );', file=body)
        else:
            print('  size += sizeof(ulong);', file=body)
        print(f'  size += {self.dlist_max} * sizeof(ulong);', file=body)

        print(f'  if( self->{name} ) {{', file=body)
        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)

        print(f'      for( {dlist_name}_iter_t iter = {dlist_name}_iter_fwd_init( &self->{self.name}[ i ], self->pool );', file=body)
        print(f'           !{dlist_name}_iter_done( iter, &self->{self.name}[ i ], self->pool );', file=body);
        print(f'           iter = {dlist_name}_iter_fwd_next( iter, &self->{self.name}[ i ], self->pool ) ) {{', file=body);
        print(f'        {dlist_t} * ele = {dlist_name}_iter_ele( iter, &self->{self.name}[ i ], self->pool );', file=body)
        print(f'        size += {dlist_t.rstrip("_t")}_size( ele );', file=body)
        print(f'      }}', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)

    def emitSizeGlobal(self, inner):
        print(f'  FD_LOG_CRIT(( "FIXME: not implemented" ));', file=body)

    def emitWalk(self, inner):
        name = self.name
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t

        print(f'  if( self->{name} ) {{', file=body)
        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)

        print(f'      for( {dlist_name}_iter_t iter = {dlist_name}_iter_fwd_init( &self->{self.name}[ i ], self->pool );', file=body)
        print(f'             !{dlist_name}_iter_done( iter, &self->{self.name}[ i ], self->pool );', file=body);
        print(f'             iter = {dlist_name}_iter_fwd_next( iter, &self->{self.name}[ i ], self->pool ) ) {{', file=body);
        print(f'          {dlist_t} * ele = {dlist_name}_iter_ele( iter, &self->{self.name}[ i ], self->pool );', file=body)

        if dlist_t == "uchar":
            print('        fun( w, ele, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );', file=body),
        elif dlist_t == "ulong":
            print('        fun( w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level, 0 );', file=body),
        elif dlist_t == "uint":
            print('        fun( w, ele, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level, 0 );', file=body),
        else:
            print(f'        {dlist_t.rstrip("_t")}_walk( w, ele, fun, "{dlist_t}", level, 0 );', file=body)
        print(f'      }}', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)


# FIXME: The treap member is currently implement in a very hacky manner
# and does not properly support global types where the treap has members
# which are local pointers. The treap is currently only used for
# fd_vote_authorized_voter_t which contains no pointers.
class TreapMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.treap_t = json["treap_t"]
        self.treap_query_t = json["treap_query_t"]
        self.treap_cmp = json["treap_cmp"]
        self.treap_lt = json["treap_lt"]
        self.min = int(json["min"])
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.treap_prio = (json["treap_prio"] if "treap_prio" in json else None)
        self.treap_optimize = (json["optimize"] if "optimize" in json else None)
        self.rev = json.get("rev", False)
        self.upsert = json.get("upsert", False)
        self.min_name = f"{self.name.upper()}_MIN"

    def emitPreamble(self):
        name = self.name
        treap_name = name + '_treap'
        treap_t = self.treap_t
        if treap_t in preambletypes:
            return
        preambletypes.add(treap_t)
        treap_query_t = self.treap_query_t
        treap_cmp = self.treap_cmp
        treap_lt = self.treap_lt
        pool = name + '_pool'
        print(f"#define {self.min_name} {self.min}", file=header)
        print(f"#define POOL_NAME {pool}", file=header)
        print(f"#define POOL_T {treap_t}", file=header)
        print(f"#define POOL_NEXT parent", file=header)
        print("#include \"../../util/tmpl/fd_pool.c\"", file=header)
        print(f'static inline {treap_t} *', file=header)
        print(f'{pool}_join_new( void * * alloc_mem, ulong num ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {pool}_align() );', file=header)
        print(f'  void * pool_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {pool}_footprint( num );', file=header)
        print(f'  return {pool}_join( {pool}_new( pool_mem, num ) );', file=header)
        print("}", file=header)
        print(f"#define TREAP_NAME {treap_name}", file=header)
        print(f"#define TREAP_T {treap_t}", file=header)
        print(f"#define TREAP_QUERY_T {treap_query_t}", file=header)
        print(f"#define TREAP_CMP(q,e) {treap_cmp}", file=header)
        print(f"#define TREAP_LT(e0,e1) {treap_lt}", file=header)
        if self.treap_optimize is not None:
            print(f"#define TREAP_OPTIMIZE_ITERATION 1", file=header)
        if self.treap_prio is not None:
            print(f"#define TREAP_PRIO {self.treap_prio}", file=header)
        print("#include \"../../util/tmpl/fd_treap.c\"", file=header)
        print(f'static inline {treap_name}_t *', file=header)
        print(f'{treap_name}_join_new( void * * alloc_mem, ulong num ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {treap_name}_align() );', file=header)
        print(f'  void * treap_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {treap_name}_footprint( num );', file=header)
        print(f'  return {treap_name}_join( {treap_name}_new( treap_mem, num ) );', file=header)
        print("}", file=header)

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'  {self.treap_t} * pool;', file=header)
        print(f'  {self.name}_treap_t * treap;', file=header)

    def emitMemberGlobal(self):
        print(f'  ulong pool_offset;', file=header)
        print(f'  ulong treap_offset;', file=header)

    def emitNew(self, indent=''):
        pass

    def emitDecodeFootprint(self):
        treap_name = self.name + '_treap'
        pool_name = self.name + '_pool'
        treap_t = self.treap_t

        if self.compact:
            print(f'  ushort {treap_name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{treap_name}_len, ctx );', file=body)
        else:
            print(f'  ulong {treap_name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{treap_name}_len, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'  ulong {treap_name}_max = fd_ulong_max( fd_ulong_max( {treap_name}_len, {self.min_name} ), 1UL );', file=body)
        print(f'  *total_sz += {pool_name}_align() + {pool_name}_footprint( {treap_name}_max );', file=body)
        print(f'  *total_sz += {treap_name}_align() + {treap_name}_footprint( {treap_name}_max );', file=body)

        print(f'  for( ulong i=0; i < {treap_name}_len; i++ ) {{', file=body)
        print(f'    err = {treap_t.rstrip("_t")}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'    if( FD_UNLIKELY ( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeInner(self):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool_name = self.name + '_pool'

        if self.compact:
            print(f'  ushort {treap_name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe( &{treap_name}_len, ctx );', file=body)
        else:
            print(f'  ulong {treap_name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe( &{treap_name}_len, ctx );', file=body)

        print(f'  ulong {treap_name}_max = fd_ulong_max( {treap_name}_len, {self.min_name} );', file=body)
        print(f'  self->pool = {pool_name}_join_new( alloc_mem, {treap_name}_max );', file=body)
        print(f'  self->treap = {treap_name}_join_new( alloc_mem, {treap_name}_max );', file=body)
        print(f'  for( ulong i=0; i < {treap_name}_len; i++ ) {{', file=body)
        print(f'    {treap_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'    {treap_t.rstrip("_t")}_new( ele );', file=body)
        print(f'    {treap_t.rstrip("_t")}_decode_inner( ele, alloc_mem, ctx );', file=body)

        if self.upsert:
            print(f'    {treap_t} * repeated_entry = {treap_name}_ele_query( self->treap, ele->epoch, self->pool );', file=body)
            print(f'    if( repeated_entry ) {{', file=body)
            print(f'        {treap_name}_ele_remove( self->treap, repeated_entry, self->pool ); // Remove the element before inserting it back to avoid duplication', file=body)
            print(f'        {pool_name}_ele_release( self->pool, repeated_entry );', file=body)
            print(f'    }}', file=body)

        print(f'    {treap_name}_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool_name = self.name + '_pool'

        if self.compact:
            print(f'  ushort {treap_name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe( &{treap_name}_len, ctx );', file=body)
        else:
            print(f'  ulong {treap_name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe( &{treap_name}_len, ctx );', file=body)

        print(f'  ulong {treap_name}_max = fd_ulong_max( {treap_name}_len, {self.min_name} );', file=body)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {pool_name}_align() );', file=body)
        print(f'  {treap_t} * pool = {pool_name}_join_new( alloc_mem, {treap_name}_max );', file=body)

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {treap_name}_align() );', file=body)
        print(f'  {treap_name}_t * treap = {treap_name}_join_new( alloc_mem, {treap_name}_max );', file=body)
        print(f'  for( ulong i=0; i < {treap_name}_len; i++ ) {{', file=body)
        print(f'    {treap_t} * ele = {pool_name}_ele_acquire( pool );', file=body)
        print(f'    {treap_t.rstrip("_t")}_new( ele );', file=body)
        print(f'    {treap_t.rstrip("_t")}_decode_inner( ele, alloc_mem, ctx );', file=body)

        if self.upsert:
            print(f'    {treap_t} * repeated_entry = {treap_name}_ele_query( treap, ele->epoch, pool );', file=body)
            print(f'    if( repeated_entry ) {{', file=body)
            print(f'        {treap_name}_ele_remove( treap, repeated_entry, pool ); // Remove the element before inserting it back to avoid duplication', file=body)
            print(f'        {pool_name}_ele_release( pool, repeated_entry );', file=body)
            print(f'    }}', file=body)

        print(f'    {treap_name}_ele_insert( treap, ele, pool ); /* this cannot fail */', file=body)
        print('  }', file=body)
        print(f'  self->pool_offset  = (ulong){pool_name}_leave( pool ) - (ulong)struct_mem;', file=body)
        print(f'  self->treap_offset = (ulong){treap_name}_leave( treap ) - (ulong)struct_mem;', file=body)

    def emitEncode(self):
        name = self.name
        treap_name = name + '_treap'
        treap_t = self.treap_t

        print(f'  if( self->treap ) {{', file=body)
        if self.compact:
            print(f'    ushort {name}_len = {treap_name}_ele_cnt( self->treap );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{name}_len, ctx );', file=body)
        else:
            print(f'    ulong {name}_len = {treap_name}_ele_cnt( self->treap );', file=body)
            print(f'    err = fd_bincode_uint64_encode( {name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)

        if self.rev:
            print(f'    for( {treap_name}_rev_iter_t iter = {treap_name}_rev_iter_init( self->treap, self->pool );', file=body)
            print(f'         !{treap_name}_rev_iter_done( iter );', file=body);
            print(f'         iter = {treap_name}_rev_iter_next( iter, self->pool ) ) {{', file=body);
            print(f'      {treap_t} * ele = {treap_name}_rev_iter_ele( iter, self->pool );', file=body)
            print(f'      err = {treap_t.rstrip("_t")}_encode( ele, ctx );', file=body)
            print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('    }', file=body)
            print('  } else {', file=body)
        else:
            print(f'    for( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body)
            print(f'         !{treap_name}_fwd_iter_done( iter );', file=body);
            print(f'         iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
            print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)
            print(f'      err = {treap_t.rstrip("_t")}_encode( ele, ctx );', file=body)
            print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('    }', file=body)
            print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{name}_len, ctx );', file=body)
        else:
            print(f'    ulong {name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode( {name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitEncodeGlobal(self):
        name = self.name
        treap_name = name + '_treap'
        treap_t = self.treap_t
        pool_name = self.name + '_pool'


        print(f'  {treap_t} * pool = {pool_name}_join( (uchar*)self + self->pool_offset );', file=body)
        print(f'  {treap_name}_t * treap = {treap_name}_join( (uchar*)self + self->treap_offset );', file=body)
        print(f'  if( treap ) {{', file=body)
        if self.compact:
            print(f'    ushort {name}_len = {treap_name}_ele_cnt( treap );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{name}_len, ctx );', file=body)
        else:
            print(f'    ulong {name}_len = {treap_name}_ele_cnt( treap );', file=body)
            print(f'    err = fd_bincode_uint64_encode( {name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)

        if self.rev:
            print(f'    for( {treap_name}_rev_iter_t iter = {treap_name}_rev_iter_init( treap, pool );', file=body)
            print(f'         !{treap_name}_rev_iter_done( iter );', file=body)
            print(f'         iter = {treap_name}_rev_iter_next( iter, pool ) ) {{', file=body)
            print(f'      {treap_t} * ele = {treap_name}_rev_iter_ele( iter, pool );', file=body)
            print(f'      err = {treap_t.rstrip("_t")}_encode( ele, ctx );', file=body)
            print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('    }', file=body)
            print('  } else {', file=body)
        else:
            print(f'    for( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( treap, pool );', file=body)
            print(f'         !{treap_name}_fwd_iter_done( iter );', file=body)
            print(f'         iter = {treap_name}_fwd_iter_next( iter, pool ) ) {{', file=body)
            print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, pool );', file=body)
            print(f'      err = {treap_t.rstrip("_t")}_encode( ele, ctx );', file=body)
            print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('    }', file=body)
            print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{name}_len, ctx );', file=body)
        else:
            print(f'    ulong {name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode( {name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)


    def emitSize(self, inner):
        name = self.name
        treap_name = name + '_treap'
        treap_t = self.treap_t
        pool = name + '_pool'

        if self.compact:
            print(f'  ushort {name}_len = (ushort){pool}_used( self->pool );', file=body)
            print(f'  size += fd_bincode_compact_u16_size( &{name}_len );', file=body)
        else:
            print('  size += sizeof(ulong);', file=body)
        print(f'  if( self->treap ) {{', file=body)
        print(f'    for( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body)
        print(f'         !{treap_name}_fwd_iter_done( iter );', file=body);
        print(f'         iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
        print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)
        print(f'      size += {treap_t.rstrip("_t")}_size( ele );', file=body)
        print('    }', file=body)
        print('  }', file=body)

    def emitWalk(self, inner):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t

        print(f'  if( self->treap ) {{', file=body)
        print(f'    for( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body)
        print(f'         !{treap_name}_fwd_iter_done( iter );', file=body);
        print(f'         iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
        print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)

        if treap_t == "uchar":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );', file=body),
        elif treap_t == "ulong":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level, 0 );', file=body),
        elif treap_t == "uint":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level, 0 );', file=body),
        else:
            print(f'      {treap_t.rstrip("_t")}_walk( w, ele, fun, "{treap_t}", level, 0 );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)


    def emitSizeGlobal(self, inner):
        print(f'  FD_LOG_CRIT(( "FIXME: Not implemented" ));', file=body)

# FIXME: The dlist member is currently implement in a very hacky manner
# and does not properly support global types where the dlist has members
# which are local pointers. The dlist is currently only used for
# fd_stake_reward_t which contains no pointers.
class DlistMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.dlist_t = json["dlist_t"]
        self.dlist_n = json["dlist_n"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")

    def emitPreamble(self):
        pool_name = self.dlist_n + "_pool"
        dlist_name = self.dlist_n + "_dlist"

        print(f"#define POOL_NAME {pool_name}", file=header)
        print(f"#define POOL_T {self.dlist_t}", file=header)
        print(f"#define POOL_NEXT parent", file=header)
        print(f"#include \"../../util/tmpl/fd_pool.c\"", file=header)
        print(f'static inline {self.dlist_t} *', file=header)
        print(f'{pool_name}_join_new( void * * alloc_mem, ulong num ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {pool_name}_align() );', file=header)
        print(f'  void * pool_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {pool_name}_footprint( num );', file=header)
        print(f'  return {pool_name}_join( {pool_name}_new( pool_mem, num ) );', file=header)
        print("}", file=header)
        print(f"#define DLIST_NAME {dlist_name}", file=header)
        print(f"#define DLIST_ELE_T {self.dlist_t}", file=header)
        print(f'#include "../../util/tmpl/fd_dlist.c"', file=header)
        print(f'static inline {dlist_name}_t *', file=header)
        print(f'{dlist_name}_join_new( void * * alloc_mem, ulong num ) {{', file=header)
        print(f'  if( FD_UNLIKELY( 0 == num ) ) num = 1; // prevent underflow', file=header)
        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {dlist_name}_align() );', file=header)
        print(f'  void * dlist_mem = *alloc_mem;', file=header)
        print(f'  *alloc_mem = (uchar *)*alloc_mem + {dlist_name}_footprint();', file=header)
        print(f'  return {dlist_name}_join( {dlist_name}_new( dlist_mem ) );', file=header)
        print("}", file=header)

    def emitPostamble(self):
        pass

    def emitMember(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=header)
        else:
            print(f'  ulong {self.name}_len;', file=header)
        print(f'  {self.dlist_n}_dlist_t * {self.name};', file=header)
        print(f'  {self.dlist_t} * pool;', file=header)

    def emitMemberGlobal(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=header)
        else:
            print(f'  ulong {self.name}_len;', file=header)
        print(f'  ulong pool_offset;', file=header)
        print(f'  ulong dlist_offset;', file=header)

    def emitNew(self, indent=''):
        pass

    def emitDecodeFootprint(self):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'  *total_sz += {pool_name}_align() + {pool_name}_footprint( {self.name}_len );', file=body)
        print(f'  *total_sz += {dlist_name}_align() + {dlist_name}_footprint()*{self.name}_len;', file=body)

        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    err = {dlist_t.rstrip("_t")}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'    if( FD_UNLIKELY ( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeInner(self):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"

        if self.compact:
            print(f'  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)

        print(f'  self->pool = {pool_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)
        print(f'  self->{self.name} = {dlist_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)
        print(f'  {dlist_name}_new( self->{self.name} );', file=body)
        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
        print(f'    {dlist_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'    {dlist_t.rstrip("_t")}_new( ele );', file=body)
        print(f'    {dlist_t.rstrip("_t")}_decode_inner( ele, alloc_mem, ctx );', file=body)
        print(f'    {dlist_name}_ele_push_tail( self->{self.name}, ele, self->pool );', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"

        if self.compact:
            print(f'  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {pool_name}_align() );', file=body)
        print(f'  {self.dlist_t} * pool = {pool_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {dlist_name}_align() );', file=body)
        print(f'  {self.dlist_n}_dlist_t * {self.name} = {dlist_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)
        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
        print(f'    {dlist_t} * ele = {pool_name}_ele_acquire( pool );', file=body)
        print(f'    {dlist_t.rstrip("_t")}_new( ele );', file=body)
        print(f'    {dlist_t.rstrip("_t")}_decode_inner( ele, alloc_mem, ctx );', file=body)
        print(f'    {dlist_name}_ele_push_tail( {self.name}, ele, pool );', file=body)
        print('  }', file=body)
        print(f'  self->pool_offset = (ulong){pool_name}_leave( pool ) - (ulong)struct_mem;', file=body)
        print(f'  self->dlist_offset = (ulong){dlist_name}_leave( {self.name} ) - (ulong)struct_mem;', file=body)

    def emitEncode(self):
        name = self.name
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t

        print(f'  if( self->{name} ) {{', file=body)
        if self.compact:
            print(f'    err = fd_bincode_compact_u16_encode( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'    err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)

        print(f'    if( FD_UNLIKELY( err ) ) return err;', file=body)

        print(f'    for( {dlist_name}_iter_t iter = {dlist_name}_iter_fwd_init( self->{self.name}, self->pool );', file=body)
        print(f'         !{dlist_name}_iter_done( iter, self->{self.name}, self->pool );', file=body);
        print(f'         iter = {dlist_name}_iter_fwd_next( iter, self->{self.name}, self->pool ) ) {{', file=body);
        print(f'      {dlist_t} * ele = {dlist_name}_iter_ele( iter, self->{self.name}, self->pool );', file=body)
        print(f'      err = {dlist_t.rstrip("_t")}_encode( ele, ctx );', file=body)
        print('      if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('    }', file=body)
        print('  } else {', file=body)

        if self.compact:
            print(f'    err = fd_bincode_compact_u16_encode( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'    err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitEncodeGlobal(self):
        pass

    def emitSize(self, inner):
        name = self.name
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool = self.dlist_n + "_pool"

        if self.compact:
            print(f'  ushort {name}_len = (ushort){pool}_used( self->pool );', file=body)
            print(f'  size += fd_bincode_compact_u16_size( &{name}_len );', file=body)
        else:
            print('  size += sizeof(ulong);', file=body)

        print(f'  if( self->{name} ) {{', file=body)

        print(f'    for( {dlist_name}_iter_t iter = {dlist_name}_iter_fwd_init( self->{self.name}, self->pool );', file=body)
        print(f'         !{dlist_name}_iter_done( iter, self->{self.name}, self->pool );', file=body);
        print(f'         iter = {dlist_name}_iter_fwd_next( iter, self->{self.name}, self->pool ) ) {{', file=body);
        print(f'      {dlist_t} * ele = {dlist_name}_iter_ele( iter, self->{self.name}, self->pool );', file=body)
        print(f'      size += {dlist_t.rstrip("_t")}_size( ele );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        print(f'  FD_LOG_CRIT(( "FIXME: not implemented" ));', file=body)

    def emitWalk(self, inner):
        name = self.name
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t

        print(f'  if( self->{name} ) {{', file=body)

        print(f'    for( {dlist_name}_iter_t iter = {dlist_name}_iter_fwd_init( self->{self.name}, self->pool );', file=body)
        print(f'           !{dlist_name}_iter_done( iter, self->{self.name}, self->pool );', file=body);
        print(f'           iter = {dlist_name}_iter_fwd_next( iter, self->{self.name}, self->pool ) ) {{', file=body);
        print(f'        {dlist_t} * ele = {dlist_name}_iter_ele( iter, self->{self.name}, self->pool );', file=body)

        if dlist_t == "uchar":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );', file=body),
        elif dlist_t == "ulong":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level, 0 );', file=body),
        elif dlist_t == "uint":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level, 0 );', file=body),
        else:
            print(f'      {dlist_t.rstrip("_t")}_walk( w, ele, fun, "{dlist_t}", level, 0 );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)


# Class representing optional/nullable types (Rust Option<T> equivalent)
class OptionMember(TypeNode):
    """
    Represents an optional value that may or may not be present.

    Options are encoded as: [present: bool][value if present]

    Supports two storage modes:
    - Flat: Value stored inline with a boolean flag (for small types)
    - Pointer: Value stored via pointer, NULL if not present (for large types)

    Attributes:
        element: Type of the optional value
        flat: Whether to store value inline (True) or via pointer (False)
        ignore_underflow: Whether to ignore underflow errors during decoding
    """
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.flat = json.get("flat", False)
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        if self.flat:
            if self.element in simpletypes:
                print(f'  {self.element} {self.name};', file=header)
            else:
                print(f'  {namespace}_{self.element}_t {self.name};', file=header)
            print(f'  uchar has_{self.name};', file=header)
        else:
            if self.element in simpletypes:
                print(f'  {self.element}* {self.name};', file=header)
            else:
                print(f'  {namespace}_{self.element}_t * {self.name};', file=header)

    def emitMemberGlobal(self):
        if self.flat:
            if self.element in simpletypes:
                print(f'  {self.element} {self.name};', file=header)
            elif self.element in flattypes:
                print(f'  {namespace}_{self.element}_t {self.name};', file=header)
            else:
                print(f'  {namespace}_{self.element}_global_t {self.name};', file=header)
            print(f'  uchar has_{self.name};', file=header)
        else:
            print(f'  ulong {self.name}_offset;', file=header)

    def emitOffsetJoin(self, type_name):
        if self.flat:
            return

        ret_type = None
        if self.element in simpletypes:
            ret_type = self.element
        elif self.element in flattypes:
            ret_type = f'{namespace}_{self.element}_t'
        else:
            ret_type = f'{namespace}_{self.element}_global_t'

        print(f'FD_FN_UNUSED static {ret_type} * {type_name}_{self.name}_join( {type_name}_global_t const * struct_mem ) {{', file=header)
        print(f'  return struct_mem->{self.name}_offset ? ({ret_type} *)fd_type_pun( (uchar *)struct_mem + struct_mem->{self.name}_offset ) : NULL;', file=header)
        print(f'}}', file=header)

    def emitNew(self, indent=''):
        pass

    def emitDecodeFootprint(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    err = fd_bincode_bool_decode( &o, ctx );', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('    if( o ) {', file=body)
        if not self.flat:
          if self.element in simpletypes:
              print(f'    *total_sz += 8UL + sizeof({self.element});', file=body)
          else:
              el = f'{namespace}_{self.element}'
              print(f'    *total_sz += {el.upper()}_ALIGN + sizeof({el}_t);', file=body)
        if self.element in simpletypes:
            print(f'      err = fd_bincode_{simpletypes[self.element]}_decode_footprint( ctx );', file=body)
        else:
            print(f'      err = {namespace}_{self.element}_decode_footprint_inner( ctx, total_sz );', file=body)
        print('      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('    }', file=body)
        print('  }', file=body)

    def emitDecodeInner(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    fd_bincode_bool_decode_unsafe( &o, ctx );', file=body)
        if self.flat:
            print(f'    self->has_{self.name} = !!o;', file=body)
            print('    if( o ) {', file=body)
            if self.element in simpletypes:
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( &self->{self.name}, ctx );', file=body)
            else:
                el = f'{namespace}_{self.element}'
                el = el.upper()
                print(f'      {namespace}_{self.element}_new( &self->{self.name} );', file=body)
                print(f'      {namespace}_{self.element}_decode_inner( &self->{self.name}, alloc_mem, ctx );', file=body)
            print('    }', file=body)
        else:
            print('    if( o ) {', file=body)
            if self.element in simpletypes:
                print(f'      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, 8UL );', file=body)
                print(f'      self->{self.name} = *alloc_mem;', file=body)
                print(f'      *alloc_mem = (uchar *)*alloc_mem + sizeof({self.element});', file=body)
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name}, ctx );', file=body)
            else:
                el = f'{namespace}_{self.element}'
                print(f'      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {el.upper()}_ALIGN );', file=body)
                print(f'      self->{self.name} = *alloc_mem;', file=body)
                print(f'      *alloc_mem = (uchar *)*alloc_mem + sizeof({el}_t);', file=body)
                print(f'      {namespace}_{self.element}_new( self->{self.name} );', file=body)
                print(f'      {namespace}_{self.element}_decode_inner( self->{self.name}, alloc_mem, ctx );', file=body)
            print('    } else {', file=body)
            print(f'      self->{self.name} = NULL;', file=body)
            print('    }', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    fd_bincode_bool_decode_unsafe( &o, ctx );', file=body)
        if self.flat:
            print(f'    self->has_{self.name} = !!o;', file=body)
            print('    if( o ) {', file=body)
            if self.element in simpletypes:
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( &self->{self.name}, ctx );', file=body)
            else:
                el = f'{namespace}_{self.element}'
                el = el.upper()
                print(f'      {namespace}_{self.element}_new( ({namespace}_{self.element}_t *)fd_type_pun(&self->{self.name}) );', file=body)
                if self.element in flattypes:
                    print(f'      {namespace}_{self.element}_decode_inner( &self->{self.name}, alloc_mem, ctx );', file=body)
                else:
                    print(f'      {namespace}_{self.element}_decode_inner_global( &self->{self.name}, alloc_mem, ctx );', file=body)
            print('    }', file=body)
        else:
            print('    if( o ) {', file=body)
            if self.element in simpletypes:
                print(f'      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, 8UL );', file=body)
                print(f'      self->{self.name}_offset = (ulong)*alloc_mem - (ulong)struct_mem;', file=body)
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( *alloc_mem, ctx );', file=body)
                print(f'      *alloc_mem = (uchar *)*alloc_mem + sizeof({self.element});', file=body)
            else:
                el = f'{namespace}_{self.element}'
                print(f'      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {el.upper()}_ALIGN );', file=body)
                print(f'      self->{self.name}_offset = (ulong)*alloc_mem - (ulong)struct_mem;', file=body)
                print(f'      {namespace}_{self.element}_new( *alloc_mem );', file=body)
                print(f'      *alloc_mem = (uchar *)*alloc_mem + sizeof({el}_t);', file=body)
                if self.element in flattypes:
                    print(f'      {namespace}_{self.element}_decode_inner( (uchar*)self + self->{self.name}_offset, alloc_mem, ctx );', file=body)
                else:
                    print(f'      {namespace}_{self.element}_decode_inner_global( (uchar*)self + self->{self.name}_offset, alloc_mem, ctx );', file=body)
            print('    } else {', file=body)
            print(f'      self->{self.name}_offset = 0UL;', file=body)
            print('    }', file=body)
        print('  }', file=body)

    def emitEncode(self):
        if self.flat:
            print(f'  err = fd_bincode_bool_encode( self->has_{self.name}, ctx );', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            print(f'  if( self->has_{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}, ctx );', file=body)
            else:
                print(f'    err = {namespace}_{self.element}_encode( &self->{self.name}, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  }', file=body)
        else:
            print(f'  if( self->{self.name} != NULL ) {{', file=body)
            print('    err = fd_bincode_bool_encode( 1, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            if self.element in simpletypes:
                print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}[0], ctx );', file=body)
            else:
                print(f'    err = {namespace}_{self.element}_encode( self->{self.name}, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  } else {', file=body)
            print('    err = fd_bincode_bool_encode( 0, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  }', file=body)

    def emitEncodeGlobal(self):
        if self.flat:
            print(f'  err = fd_bincode_bool_encode( self->has_{self.name}, ctx );', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            print(f'  if( self->has_{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}, ctx );', file=body)
            elif self.element in flattypes:
                print(f'    err = {namespace}_{self.element}_encode( &self->{self.name}, ctx );', file=body)
            else:
                print(f'    err = {namespace}_{self.element}_encode_global( &self->{self.name}, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  }', file=body)
        else:
            print(f'  if( self->{self.name}_offset ) {{', file=body)
            print('    err = fd_bincode_bool_encode( 1, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            if self.element in simpletypes:
                print(f'    {self.element} * {self.name} = (void *)((uchar*)self + self->{self.name}_offset);', file=body)
                print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( {self.name}[0], ctx );', file=body)
            elif self.element in flattypes:
                print(f'    {namespace}_{self.element}_t * {self.name} = (void *)((uchar*)self + self->{self.name}_offset);', file=body)
                print(f'    err = {namespace}_{self.element}_encode( {self.name}, ctx );', file=body)
            else:
                print(f'    {namespace}_{self.element}_global_t * {self.name} = (void *)((uchar*)self + self->{self.name}_offset);', file=body)
                print(f'    err = {namespace}_{self.element}_encode_global( {self.name}, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  } else {', file=body)
            print('    err = fd_bincode_bool_encode( 0, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  }', file=body)

    def emitSize(self, inner):
        print('  size += sizeof(char);', file=body)
        if self.flat:
            print(f'  if( self->has_{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    size += sizeof({self.element});', file=body)
            else:
                print(f'    size += {namespace}_{self.element}_size( &self->{self.name} );', file=body)
            print('  }', file=body)
        else:
            print(f'  if( NULL != self->{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    size += sizeof({self.element});', file=body)
            else:
                print(f'    size += {namespace}_{self.element}_size( self->{self.name} );', file=body)
            print('  }', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        print('  size += sizeof(char);', file=body)
        if self.flat:
            print(f'  if( self->has_{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    size += sizeof({self.element});', file=body)
            else:
                print(f'    size += {namespace}_{self.element}_size( &self->{self.name} );', file=body)
            print('  }', file=body)
        else:
            ret_type = None
            if self.element in simpletypes:
                ret_type = self.element
            elif self.element in flattypes:
                ret_type = f'{namespace}_{self.element}_t'
            else:
                ret_type = f'{namespace}_{self.element}_global_t'

            print(f'  {ret_type} * {self.name} = ({ret_type} *)fd_type_pun( (uchar *)self + self->{self.name}_offset );', file=body)

            print(f'  if( NULL != {self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    size += sizeof({self.element});', file=body)
            elif self.element in flattypes:
                print(f'    size += {namespace}_{self.element}_size( {self.name} );', file=body)
            else:
                print(f'    size += {namespace}_{self.element}_size_global( {self.name} );', file=body)
            print('  }', file=body)

    emitWalkMap = {
        "bool" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_BOOL, "char", level, 0 );', file=body),
        "char" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR, "char", level, 0 );', file=body),
        "double" :    lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0 );', file=body),
        "long" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );', file=body),
        "uint" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT, "uint", level, 0 );', file=body),
        "uint128" :   lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level, 0 );', file=body),
        "uchar" :     lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );', file=body),
        "uchar[32]" : lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level, 0 );', file=body),
        "uchar[128]" :lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH1024, "uchar[128]", level, 0 );', file=body),
        "uchar[2048]":lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH16384, "uchar[2048]", level, 0 );', file=body),
        "ulong" :     lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );', file=body),
        "ushort" :    lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0 );', file=body),
    }

    def emitWalk(self, inner):
        if self.flat:
            print(f'  if( !self->has_{self.name} ) {{', file=body)
            print(f'    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_NULL, "{self.element}", level, 0 );', file=body)
            print( '  } else {', file=body)
            if self.element in OptionMember.emitWalkMap:
                OptionMember.emitWalkMap[self.element](self.name, '&')
            else:
                print(f'    {namespace}_{self.element}_walk( w, &self->{self.name}, fun, "{self.name}", level, 0 );', file=body)
            print( '  }', file=body)
        else:
            print(f'  if( !self->{self.name} ) {{', file=body)
            print(f'    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_NULL, "{self.element}", level, 0 );', file=body)
            print( '  } else {', file=body)
            if self.element in OptionMember.emitWalkMap:
                OptionMember.emitWalkMap[self.element](self.name, '')
            else:
                print(f'    {namespace}_{self.element}_walk( w, self->{self.name}, fun, "{self.name}", level, 0 );', file=body)
            print( '  }', file=body)

class ArrayMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.length = int(json["length"])

    def isFlat(self):
        return self.element in flattypes

    def isFixedSize(self):
        return self.element in fixedsizetypes

    def fixedSize(self):
        return self.length * fixedsizetypes[self.element]

    def isFuzzy(self):
        return self.element in fuzzytypes

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        if self.element in simpletypes:
            print(f'  {self.element} {self.name}[{self.length}];', file=header)
        else:
            print(f'  {namespace}_{self.element}_t {self.name}[{self.length}];', file=header)

    def emitMemberGlobal(self):
      if self.element in simpletypes:
          print(f'  {self.element} {self.name}[{self.length}];', file=header)
      elif self.element in flattypes:
          print(f'  {namespace}_{self.element}_t {self.name}[{self.length}];', file=header)
      else:
          print(f'  {namespace}_{self.element}_global_t {self.name}[{self.length}];', file=header)
    def emitNew(self, indent=''):
        length = self.length
        if self.element in simpletypes:
            pass
        else:
            print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
            print(f'    {namespace}_{self.element}_new( self->{self.name} + i );', file=body)

    def emitDecodeFootprint(self):
        length = self.length

        if self.element == "uchar":
            print(f'  err = fd_bincode_bytes_decode_footprint( {length}, ctx );', file=body)
            print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
            return

        print(f'  for( ulong i=0; i<{length}; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_decode_footprint( ctx );', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_decode_footprint_inner( ctx, total_sz );', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeInner(self):
        length = self.length

        if self.element == "uchar":
            print(f'  fd_bincode_bytes_decode_unsafe( self->{self.name}, {length}, ctx );', file=body)
            return

        print(f'  for( ulong i=0; i<{length}; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name} + i, ctx );', file=body)
        else:
            print(f'    {namespace}_{self.element}_decode_inner( self->{self.name} + i, alloc_mem, ctx );', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        length = self.length

        if self.element == "uchar":
            print(f'  fd_bincode_bytes_decode_unsafe( self->{self.name}, {length}, ctx );', file=body)
            return

        print(f'  for( ulong i=0; i<{length}; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name} + i, ctx );', file=body)
        else:
            if self.element in flattypes:
                print(f'    {namespace}_{self.element}_decode_inner( self->{self.name} + i, alloc_mem, ctx );', file=body)
            else:
                print(f'    {namespace}_{self.element}_decode_inner_global( self->{self.name} + i, alloc_mem, ctx );', file=body)
        print('  }', file=body)

    def emitEncode(self):
        length = self.length

        if self.element == "uchar":
            print(f'  err = fd_bincode_bytes_encode( self->{self.name}, {length}, ctx );', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            return

        print(f'  for( ulong i=0; i<{length}; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}[i], ctx );', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_encode( self->{self.name} + i, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitEncodeGlobal(self):
        length = self.length

        if self.element == "uchar":
            print(f'  err = fd_bincode_bytes_encode( self->{self.name}, {length}, ctx );', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            return

        print(f'  for( ulong i=0; i<{length}; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}[i], ctx );', file=body)
        elif self.element in flattypes:
            print(f'    err = {namespace}_{self.element}_encode( self->{self.name} + i, ctx );', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_encode_global( self->{self.name} + i, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        length = self.length

        if self.element == "uchar":
            print(f'  size += {length};', file=body)
        elif self.element in simpletypes:
            print(f'  size += {length} * sizeof({self.element});', file=body)
        else:
            print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)

    def emitSizeGlobal(self, inner, indent=''):
        length = self.length

        if self.element == "uchar":
            print(f'  size += {length};', file=body)
        elif self.element in simpletypes:
            print(f'  size += {length} * sizeof({self.element});', file=body)
        elif self.element in flattypes:
            print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)
        else:
            print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size_global( self->{self.name} + i );', file=body)

    def emitWalk(self, inner):
        length = self.length

        if self.element == "uchar":
            print(f'  fun(w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_UCHAR, "{self.element}", level, 0 );', file=body),
            return

        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR, "{self.element}[]", level++, 0 );', file=body)
        print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
        if self.element in VectorMember.emitWalkMap:
            body.write("  ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'    {namespace}_{self.element}_walk( w, self->{self.name} + i, fun, "{self.element}", level, 0 );', file=body)
        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.element}[]", level--, 0 );', file=body)

memberTypeMap = {
    "static_vector" : StaticVectorMember,
    "vector" :        VectorMember,
    "string" :        StringMember,
    "deque" :         DequeMember,
    "dlist" :         DlistMember,
    "partition" :     PartitionMember,
    "array" :         ArrayMember,
    "option" :        OptionMember,
    "map" :           MapMember,
    "treap" :         TreapMember,
    "bitvec" :        BitVectorMember
}

def parseMember(namespace, json):
    type = str(json["type"])
    if type in memberTypeMap:
        c = memberTypeMap[type]
    elif type in PrimitiveMember.emitMemberMap:
        json["type"] = type
        c = PrimitiveMember
    else:
        c = StructMember
    return c(namespace, json)


class OpaqueType(TypeNode):
    def __init__(self, json):
        super().__init__(json)
        self.fullname = f'{namespace}_{json["name"]}'
        self.walktype = (json["walktype"] if "walktype" in json else None)
        self.size = (int(json["size"]) if "size" in json else None)
        self.emitprotos = (bool(json["emitprotos"]) if "emitprotos" in json else True)
        # All opaque types are flattypes
        flattypes.add( self.name)

    def emitHeader(self):
        pass

    def isFlat(self):
        return True

    def isFixedSize(self):
        return self.size is not None

    def fixedSize(self):
        return self.size

    def emitPrototypes(self):
        if not self.emitprotos:
            return
        n = self.fullname
        print(f"static inline void {n}_new( {n}_t * self ) {{ (void)self; }}", file=header)
        print(f"int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
        print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char * name, uint level, uint varint );", file=header)
        print(f"static inline ulong {n}_size( {n}_t const * self ) {{ (void)self; return sizeof({n}_t); }}", file=header)
        print(f'static inline ulong {n}_align( void ) {{ return alignof({n}_t); }}', file=header)
        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print("", file=header)

    def emitImpls(self):
        if not self.emitprotos:
            return
        n = self.fullname
        print(f'int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        print(f'  return fd_bincode_bytes_encode( (uchar const *)self, sizeof({n}_t), ctx );', file=body)
        print("}", file=body)

        if self.walktype is not None:
            print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {{", file=body)
            print(f'  fun( w, (uchar const *)self, name, {self.walktype}, name, level, varint );', file=body)
            print("}", file=body)

        print(f'static int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print(f'  if( ctx->data>=ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
        print(f'  return fd_bincode_bytes_decode_footprint( sizeof({n}_t), ctx );', file=body)
        print(f'}}', file=body)

        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print(f'  *total_sz += sizeof({n}_t);', file=body)
        print(f'  void const * start_data = ctx->data;', file=body)
        print(f'  int err = {n}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'  if( ctx->data>ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
        print(f'  ctx->data = start_data;', file=body)
        print(f'  return err;', file=body)
        print(f'}}', file=body)

        print(f'static void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  fd_bincode_bytes_decode_unsafe( struct_mem, sizeof({n}_t), ctx );', file=body)
        print(f'  return;', file=body)
        print(f'}}', file=body)

        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  fd_bincode_bytes_decode_unsafe( mem, sizeof({n}_t), ctx );', file=body)
        print(f'  return mem;', file=body)
        print(f'}}', file=body)

        print("", file=body)

    def emitPostamble(self):
        pass


# FIXME horrible code
def extract_sub_type(member):
    if isinstance(member, str):
        return None
    if isinstance(member, PrimitiveMember):
        return None
    if isinstance(member, OpaqueType):
        return None
    if isinstance(member, BitVectorMember):
        return None
    if hasattr(member, "element"):
        return type_map[member.element] if member.element in type_map else None
    if hasattr(member, "type"):
        return type_map[member.type] if member.type in type_map else None
    if hasattr(member, "dlist_t"):
        return type_map[member.dlist_t] if member.dlist_t in type_map else None
    raise ValueError(f"Unknown type {member} in extract_sub_type")

def extract_member_type(member):
    if isinstance(member, str):
        return None
    if isinstance(member, PrimitiveMember):
        return None
    if isinstance(member, OpaqueType):
        return None
    if isinstance(member, BitVectorMember):
        return None
    if hasattr(member, "element"):
        return member
    if hasattr(member, "type"):
        return member
    if hasattr(member, "dlist_t"):
        return member
    raise ValueError(f"Unknown type {member} in extract_member_type")

# Class representing C struct types
class StructType(TypeNode):
    """
    Represents a C struct with multiple named fields.

    Generates complete C struct definitions with:
    - Member declarations
    - Constructor/destructor functions
    - Encode/decode functions for serialization
    - Size calculation functions
    - Walk functions for reflection
    - Both regular and "global" variants (using offsets vs pointers)

    Attributes:
        fullname: Full qualified name with namespace prefix
        fields: List of member fields in this struct
        comment: Optional comment/documentation for the struct
        encoders: Encoder configuration (if any)
        custom_decode_inner: Whether to use custom decode implementation
        normalizer: Optional normalizer function name
        validator: Optional validator function name
        attribute: C attribute string (alignment, packed, etc.)
        alignment: Alignment requirement in bytes
    """
    def __init__(self, json):
        super().__init__(json)
        self.fullname = f'{namespace}_{json["name"]}'
        self.fields = []
        index = 0
        # Parse all non-removed fields
        for f in json["fields"]:
            if not (bool(f["removed"]) if "removed" in f else False):
                m = parseMember(self.fullname, f)
                self.fields.append(m)
                m.arch_index = (int(f["tag"]) if "tag" in f else index)
            index = index + 1

        # Extract optional configuration
        self.comment = (json["comment"] if "comment" in json else None)
        self.encoders = (json["encoders"] if "encoders" in json else None)
        self.custom_decode_inner = (json["custom_decode_inner"] if "custom_decode_inner" in json else False)
        self.normalizer = (json["normalizer"] if "normalizer" in json else None)
        self.validator = (json["validator"] if "validator" in json else None)

        # Handle alignment and packing attributes
        if "alignment" in json:
            self.attribute = f'__attribute__((aligned({json["alignment"]}UL))) '
            self.alignment = json["alignment"]
        elif "packed" in json and json["packed"]:
            self.attribute = f'__attribute__((packed)) '
            self.alignment = 8
        else:
            self.attribute = f''
            self.alignment = 0

    def isFixedSize(self):
        for f in self.fields:
            if not f.isFixedSize():
                return False
            if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                return False
        return True

    def isFlat(self):
        for f in self.fields:
            if not f.isFlat():
                return False
        return True

    def fixedSize(self):
        size = 0
        for f in self.fields:
            size += f.fixedSize()
        return size

    def isFuzzy(self):
        for f in self.fields:
            if not f.isFuzzy():
                return False
        return True

    def subTypes(self):
        for f in self.fields:
            sub_type = extract_sub_type(f)
            if sub_type is not None:
                yield sub_type

    def subMembers(self):
        for f in self.fields:
            sub_member = extract_member_type(f)
            if sub_member is not None:
                yield sub_member

    def emitHeader(self):
        for f in self.fields:
            f.emitPreamble()

        if self.comment is not None and self.comment != "":
            print(f'/* {self.comment} */', file=header)

        if self.isFixedSize():
            print(f'/* Encoded Size: Fixed ({self.fixedSize()} bytes) */', file=header)
        else:
            print(f'/* Encoded Size: Dynamic */', file=header)

        n = self.fullname
        # Struct type
        print(f'struct {self.attribute}{n} {{', file=header)
        for f in self.fields:
            f.emitMember()
        print("};", file=header)
        print(f'typedef struct {n} {n}_t;', file=header)

        if int(self.alignment) > 0:
            print(f"#define {n.upper()}_ALIGN ({self.alignment}UL)", file=header)
        else:
            print(f"#define {n.upper()}_ALIGN alignof({n}_t)", file=header)
        print("", file=header)

        # Global type
        if self.produce_global and not self.isFlat():
            print(f'struct {self.attribute}{n}_global {{', file=header)
            for f in self.fields:
                f.emitMemberGlobal()
            print("};", file=header)
            print(f'typedef struct {n}_global {n}_global_t;', file=header)

            if int(self.alignment) > 0:
                print(f"#define {n.upper()}_GLOBAL_ALIGN ({self.alignment}UL)", file=header)
            else:
                print(f"#define {n.upper()}_GLOBAL_ALIGN alignof({n}_global_t)", file=header)
            print("", file=header)

            for f in self.fields:
                f.emitOffsetJoin(n)

    def emitPrototypes(self):
        n = self.fullname
        if self.isFixedSize() and self.isFuzzy():
            print(f"static inline void {n}_new( {n}_t * self ) {{ fd_memset( self, 0, sizeof({n}_t) ); }}", file=header)
        else:
            print(f"void {n}_new( {n}_t * self );", file=header)
        print(f"int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
        print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );", file=header)
        if self.isFixedSize():
            print(f'static inline ulong {n}_size( {n}_t const * self ) {{ (void)self; return {self.fixedSize()}UL; }}', file=header)
        else:
            print(f"ulong {n}_size( {n}_t const * self );", file=header)
        print(f'static inline ulong {n}_align( void ) {{ return {n.upper()}_ALIGN; }}', file=header)
        if self.isFixedSize() and self.isFuzzy():
            print(f'static inline int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=header)
            print(f'  *total_sz += sizeof({n}_t);', file=header)
            print(f'  if( (ulong)ctx->data + {self.fixedSize()}UL > (ulong)ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=header)
            print(f'  return 0;', file=header)
            print(f'}}', file=header)
        else:
            print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        if self.produce_global and not self.isFlat():
            print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
            print(f"int {n}_encode_global( {n}_global_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
            print(f'ulong {n}_size_global( {n}_global_t const * self );', file=header)
        print("", file=header)

    def emitEncodes(self):
        n = self.fullname
        self.emitEncode(n)
        if self.produce_global and not self.isFlat():
            self.emitEncodeGlobal(n)

    def emitEncode(self, n):
        print(f'int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        print('  int err;', file=body)
        for f in self.fields:
            if hasattr(f, 'encode') and not f.encode:
                continue
            f.emitEncode()
        print('  return FD_BINCODE_SUCCESS;', file=body)
        print("}", file=body)

    def emitEncodeGlobal(self, n):
        n = self.fullname
        print(f'int {n}_encode_global( {n}_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        print('  int err;', file=body)
        for f in self.fields:
            if hasattr(f, 'encode') and not f.encode:
                continue
            f.emitEncodeGlobal()
        print('  return FD_BINCODE_SUCCESS;', file=body)
        print("}", file=body)

    def emitImpls(self):
        n = self.fullname

        if self.encoders is not False:
            self.emitEncodes()

        if self.encoders is not False:
            if self.isFixedSize() and self.isFuzzy():
                print(f'static inline int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
                sz = self.fixedSize()
                print(f'  if( (ulong)ctx->data + {self.fixedSize()}UL > (ulong)ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
                if self.validator is not None:
                    print(f'  int err = {self.validator}( ctx );', file=body)
                    print(f'  if( FD_UNLIKELY( err != FD_BINCODE_SUCCESS ) )', file=body)
                    print(f'    return err;', file=body)
                print(f'  ctx->data = (void *)( (ulong)ctx->data + {self.fixedSize()}UL );', file=body)
                print(f'  return 0;', file=body)
                print(f'}}', file=body)
            else:
                print(f'static int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
                print(f'  if( ctx->data>=ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
                print(f'  int err = 0;', file=body)
                if self.validator is not None:
                    print(f'  err = {self.validator}( ctx );', file=body)
                    print(f'  if( FD_UNLIKELY( err != FD_BINCODE_SUCCESS ) )', file=body)
                    print(f'    return err;', file=body)
                for f in self.fields:
                    if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                        print('  if( ctx->data == ctx->dataend ) return FD_BINCODE_SUCCESS;', file=body)
                    f.emitDecodeFootprint()
                print(f'  return 0;', file=body)
                print(f'}}', file=body)

                print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
                print(f'  *total_sz += sizeof({n}_t);', file=body)
                print(f'  void const * start_data = ctx->data;', file=body)
                print(f'  int err = {n}_decode_footprint_inner( ctx, total_sz );', file=body)
                print(f'  if( ctx->data>ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
                print(f'  ctx->data = start_data;', file=body)
                print(f'  return err;', file=body)
                print(f'}}', file=body)
            if not self.custom_decode_inner:
                print(f'static void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
                print(f'  {n}_t * self = ({n}_t *)struct_mem;', file=body)
                for f in self.fields:
                    if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                        print('  if( ctx->data == ctx->dataend ) return;', file=body)
                    f.emitDecodeInner()
                if self.normalizer is not None:
                    print(f'  {self.normalizer}( self );', file=body)
                print(f'}}', file=body)

            print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_t * self = ({n}_t *)mem;', file=body)
            print(f'  {n}_new( self );', file=body)
            print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_t);', file=body)
            print(f'  void * * alloc_mem = &alloc_region;', file=body)
            print(f'  {n}_decode_inner( mem, alloc_mem, ctx );', file=body)
            print(f'  return self;', file=body)
            print(f'}}', file=body)

            if self.produce_global and not self.isFlat():
                if not self.custom_decode_inner:
                    print(f'static void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
                    print(f'  {n}_global_t * self = ({n}_global_t *)struct_mem;', file=body)
                    for f in self.fields:
                        if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                            print('  if( ctx->data == ctx->dataend ) return;', file=body)
                        f.emitDecodeInnerGlobal()
                    print(f'}}', file=body)

                print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
                print(f'  {n}_global_t * self = ({n}_global_t *)mem;', file=body)
                print(f'  {n}_new( ({n}_t *)self );', file=body)
                print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_global_t);', file=body)
                print(f'  void * * alloc_mem = &alloc_region;', file=body)
                print(f'  {n}_decode_inner_global( mem, alloc_mem, ctx );', file=body)
                print(f'  return self;', file=body)
                print(f'}}', file=body)

        if self.isFixedSize() and self.isFuzzy():
            pass
        else:
            print(f'void {n}_new({n}_t * self) {{', file=body)
            print(f'  fd_memset( self, 0, sizeof({n}_t) );', file=body)
            for f in self.fields:
                f.emitNew()
            print("}", file=body)

        print(f'void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {{', file=body)
        print(f'  (void) varint;', file=body)
        print(f'  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "{n}", level++, 0 );', file=body)
        for f in self.fields:
            f.emitWalk('')
        print(f'  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "{n}", level--, 0 );', file=body)
        print("}", file=body)

        if not self.isFixedSize():
            print(f'ulong {n}_size( {n}_t const * self ) {{', file=body)
            print('  ulong size = 0;', file=body)
            for f in self.fields:
                f.emitSize('')
            print('  return size;', file=body)
            print("}", file=body)
            print("", file=body)

        if self.produce_global and not self.isFlat():
            print(f'ulong {n}_size_global( {n}_global_t const * self ) {{', file=body)
            print('  ulong size = 0;', file=body)
            for f in self.fields:
                f.emitSizeGlobal('')
            print('  return size;', file=body)
            print("}", file=body)
            print("", file=body)

    def emitPostamble(self):
        for f in self.fields:
            f.emitPostamble()


class EnumType(TypeNode):
    def __init__(self, json):
        super().__init__(json)
        self.name = json["name"]
        self.fullname = f'{namespace}_{json["name"]}'
        self.zerocopy = (bool(json["zerocopy"]) if "zerocopy" in json else False)
        self.variants = []
        for f in json["variants"]:
            if 'type' in f:
                self.variants.append(parseMember(self.fullname, f))
            else:
                self.variants.append(str(f['name']))
        self.comment = (json["comment"] if "comment" in json else None)
        if "alignment" in json:
            self.attribute = f'__attribute__((aligned({json["alignment"]}UL))) '
            self.alignment = json["alignment"]
        elif "packed" in json and json["packed"]:
            self.attribute = f'__attribute__((packed)) '
            self.alignment = 8
        else:
            self.attribute = ''
            self.alignment = 0
        self.compact = (json["compact"] if "compact" in json else False)

        # Current supported repr types for enum are uint and ulong
        self.repr = (json["repr"] if "repr" in json else "uint")
        self.repr_codec_stem = "uint32"
        self.repr_max_val = "UINT_MAX"

        if self.repr == "ulong":
            self.repr_codec_stem = "uint64"
            self.repr_max_val = "ULONG_MAX"

    def subTypes(self):
        for v in self.variants:
            sub_type = extract_sub_type(v)
            if sub_type is not None:
                yield sub_type

    def subMembers(self):
        for v in self.variants:
            if not isinstance(v, str):
                yield v

    def isFlat(self):
        for v in self.variants:
            if not isinstance(v, str):
                if not v.isFlat():
                    return False
        return True

    def isFixedSize(self):
        all_simple = True
        for v in self.variants:
            if not isinstance(v, str):
                all_simple = False
                break
        if all_simple:
            return True

    def fixedSize(self):
        return 4

    def isFuzzy(self):
        return False

    def emitHeader(self):
        for v in self.variants:
            if not isinstance(v, str):
                v.emitPreamble()

        n = self.fullname

        # Enum type
        if not self.isFixedSize():
            print(f'union {self.attribute}{n}_inner {{', file=header)
            empty = True
            for v in self.variants:
                if not isinstance(v, str):
                    empty = False
                    v.emitMember()
            if empty:
                print('  uchar nonempty; /* Hack to support enums with no inner structures */', file=header)
            print("};", file=header)
            print(f"typedef union {n}_inner {n}_inner_t;\n", file=header)

            if self.produce_global and not self.isFlat():
                print(f'union {self.attribute}{n}_inner_global {{', file=header)
                empty = True
                for v in self.variants:
                    if not isinstance(v, str):
                        empty = False
                        v.emitMemberGlobal()
                if empty:
                    print('  uchar nonempty; /* Hack to support enums with no inner structures */', file=header)
                print("};", file=header)
                print(f"typedef union {n}_inner_global {n}_inner_global_t;\n", file=header)

        if self.comment is not None:
            print(f'/* {self.comment} */', file=header)

        print(f"struct {self.attribute}{n} {{", file=header)
        print(f'  {self.repr} discriminant;', file=header)
        if not self.isFixedSize():
            print(f'  {n}_inner_t inner;', file=header)
        print("};", file=header)
        print(f"typedef struct {n} {n}_t;", file=header)
        if self.alignment > 0:
            print(f"#define {n.upper()}_ALIGN ({self.alignment}UL)", file=header)
        else:
            print(f"#define {n.upper()}_ALIGN alignof({n}_t)", file=header)

        if self.produce_global and not self.isFlat():
            print(f"struct {self.attribute}{n}_global {{", file=header)
            print(f'  {self.repr} discriminant;', file=header)
            print(f'  {n}_inner_global_t inner;', file=header)
            print("};", file=header)
            print(f"typedef struct {n}_global {n}_global_t;", file=header)

            if self.alignment > 0:
                print(f"#define {n.upper()}_GLOBAL_ALIGN ({self.alignment}UL)", file=header)
            else:
                print(f"#define {n.upper()}_GLOBAL_ALIGN alignof({n}_global_t)", file=header)
        print("", file=header)

    def emitPrototypes(self):
        n = self.fullname
        if self.isFixedSize():
            print(f"static inline void {n}_new_disc( {n}_t * self, {self.repr} discriminant ) {{ self->discriminant = discriminant; }}", file=header)
            print(f"static inline void {n}_new( {n}_t * self ) {{ self->discriminant = ({self.repr})ULONG_MAX; }}", file=header)
        else:
            print(f"void {n}_new_disc( {n}_t * self, {self.repr} discriminant );", file=header)
            print(f"void {n}_new( {n}_t * self );", file=header)
        print(f"int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
        print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint );", file=header)
        print(f"ulong {n}_size( {n}_t const * self );", file=header)
        print(f'static inline ulong {n}_align( void ) {{ return {n.upper()}_ALIGN; }}', file=header)
        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        if self.produce_global and not self.isFlat():
            print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
            print(f"int {n}_encode_global( {n}_global_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
            print(f'ulong {n}_size_global( {n}_global_t const * self );', file=header)
        print("", file=header)

        for i, v in enumerate(self.variants):
            name = (v if isinstance(v, str) else v.name)
            print(f'FD_FN_PURE uchar {n}_is_{name}( {n}_t const * self );', file=header)

        print("enum {", file=header)
        for i, v in enumerate(self.variants):
            name = (v if isinstance(v, str) else v.name)
            print(f'{n}_enum_{name} = {i},', file=header)
        print("};", file=header)

    def emitImpls(self):
        n = self.fullname
        indent = '  '

        for i, v in enumerate(self.variants):
            name = (v if isinstance(v, str) else v.name)
            print(f'FD_FN_PURE uchar {n}_is_{name}({n}_t const * self) {{', file=body)
            print(f'  return self->discriminant == {i};', file=body)
            print("}", file=body)

        if not self.isFixedSize():
            print(f'void {n}_inner_new( {n}_inner_t * self, {self.repr} discriminant );', file=body)

        print(f'int {n}_inner_decode_footprint( {self.repr} discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print('  int err;', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitDecodeFootprint(indent)
            print('    return FD_BINCODE_SUCCESS;', file=body)
            print('  }', file=body)
        print('  default: return FD_BINCODE_ERR_ENCODING;', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'static int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print(f'  if( ctx->data>=ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
        if self.compact:
            print('  ushort discriminant = 0;', file=body)
            print('  int err = fd_bincode_compact_u16_decode( &discriminant, ctx );', file=body)
        else:
            print(f'  {self.repr} discriminant = 0;', file=body)
            print(f'  int err = fd_bincode_{self.repr_codec_stem}_decode( &discriminant, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'  return {n}_inner_decode_footprint( discriminant, ctx, total_sz );', file=body)
        print("}", file=body)

        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print(f'  *total_sz += sizeof({n}_t);', file=body)
        print(f'  void const * start_data = ctx->data;', file=body)
        print(f'  int err =  {n}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'  if( ctx->data>ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
        print(f'  ctx->data = start_data;', file=body)
        print(f'  return err;', file=body)
        print("}", file=body)

        if not self.isFixedSize():
            print(f'static void {n}_inner_decode_inner( {n}_inner_t * self, void * * alloc_mem, {self.repr} discriminant, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print('  switch (discriminant) {', file=body)
            for i, v in enumerate(self.variants):
                print(f'  case {i}: {{', file=body)
                if not isinstance(v, str):
                    v.emitDecodeInner(indent)
                print('    break;', file=body)
                print('  }', file=body)
            print('  }', file=body)
            print("}", file=body)


            if self.produce_global and not self.isFlat():
                print(f'static void {n}_inner_decode_inner_global( {n}_inner_global_t * self, void * * alloc_mem, {self.repr} discriminant, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
                print('  switch (discriminant) {', file=body)
                for i, v in enumerate(self.variants):
                    print(f'  case {i}: {{', file=body)
                    if not isinstance(v, str):
                        v.emitDecodeInnerGlobal(indent)
                    print('    break;', file=body)
                    print('  }', file=body)
                print('  }', file=body)
                print("}", file=body)

        print(f'static void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  {n}_t * self = ({n}_t *)struct_mem;', file=body)
        if self.compact:
            print('  ushort tmp = 0;', file=body)
            print('  fd_bincode_compact_u16_decode_unsafe( &tmp, ctx );', file=body)
            print('  self->discriminant = tmp;', file=body)
        else:
            print(f'  fd_bincode_{self.repr_codec_stem}_decode_unsafe( &self->discriminant, ctx );', file=body)
        if not self.isFixedSize():
            print(f'  {n}_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );', file=body)
        print(f'}}', file=body)

        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  {n}_t * self = ({n}_t *)mem;', file=body)
        print(f'  {n}_new( self );', file=body)
        print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_t);', file=body)
        print(f'  void * * alloc_mem = &alloc_region;', file=body)
        print(f'  {n}_decode_inner( mem, alloc_mem, ctx );', file=body)
        print(f'  return self;', file=body)
        print(f'}}', file=body)

        if self.produce_global and not self.isFlat():
            print(f'static int {n}_inner_encode_global( {n}_inner_global_t const * self, {self.repr} discriminant, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
            first = True
            for i, v in enumerate(self.variants):
                if not isinstance(v, str):
                    if first:
                        print('  int err;', file=body)
                        print('  switch (discriminant) {', file=body)
                        first = False
                    print(f'  case {i}: {{', file=body)
                    v.emitEncodeGlobal(indent)
                    print('    break;', file=body)
                    print('  }', file=body)
            if not first:
                print('  }', file=body)
            print('  return FD_BINCODE_SUCCESS;', file=body)
            print("}", file=body)

            print(f'int {n}_encode_global( {n}_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
            if self.compact:
                print('  ushort discriminant = (ushort) self->discriminant;', file=body)
                print('  int err = fd_bincode_compact_u16_encode( &discriminant, ctx );', file=body)
            else:
                print(f'  int err = fd_bincode_{self.repr_codec_stem}_encode( self->discriminant, ctx );', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            print(f'  return {n}_inner_encode_global( &self->inner, self->discriminant, ctx );', file=body)
            print("}", file=body)
            print("", file=body)

            print(f'static void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_global_t * self = ({n}_global_t *)struct_mem;', file=body)
            if self.compact:
                print('  ushort tmp = 0;', file=body)
                print('  fd_bincode_compact_u16_decode_unsafe( &tmp, ctx );', file=body)
                print('  self->discriminant = tmp;', file=body)
            else:
                print(f'  fd_bincode_{self.repr_codec_stem}_decode_unsafe( &self->discriminant, ctx );', file=body)
            if not self.isFixedSize():
                print(f'  {n}_inner_decode_inner_global( &self->inner, alloc_mem, self->discriminant, ctx );', file=body)
            print(f'}}', file=body)

            print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_t * self = ({n}_t *)mem;', file=body)
            print(f'  {n}_new( self );', file=body)
            print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_t);', file=body)
            print(f'  void * * alloc_mem = &alloc_region;', file=body)
            print(f'  {n}_decode_inner_global( mem, alloc_mem, ctx );', file=body)
            print(f'  return self;', file=body)
            print(f'}}', file=body)

        if not self.isFixedSize():
            print(f'void {n}_inner_new( {n}_inner_t * self, {self.repr} discriminant ) {{', file=body)
            print('  switch( discriminant ) {', file=body)
            for i, v in enumerate(self.variants):
                print(f'  case {i}: {{', file=body)
                if not isinstance(v, str):
                    v.emitNew(indent)
                print('    break;', file=body)
                print('  }', file=body)
            print('  default: break; // FD_LOG_ERR(( "unhandled type"));', file=body)
            print('  }', file=body)
            print("}", file=body)

            print(f'void {n}_new_disc( {n}_t * self, {self.repr} discriminant ) {{', file=body)
            print('  self->discriminant = discriminant;', file=body)
            print(f'  {n}_inner_new( &self->inner, self->discriminant );', file=body)
            print("}", file=body)

            print(f'void {n}_new( {n}_t * self ) {{', file=body)
            print(f'  fd_memset( self, 0, sizeof({n}_t) );', file=body)
            print(f'  {n}_new_disc( self, {self.repr_max_val} );', file=body) # Invalid by default
            print("}", file=body)

        print("", file=body)

        print(f'void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {{', file=body)
        print(f'  (void) varint;', file=body)
        print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "{n}", level++, 0);', file=body)
        print('  switch( self->discriminant ) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                print(f'    fun( w, self, "{v.name}", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );', file=body)
                v.emitWalk("inner.", indent)
            else:
                print(f'    fun( w, self, "{v}", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );', file=body)
            print('    break;', file=body)
            print('  }', file=body)
        print('  }', file=body)
        print(f'  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "{n}", level--, 0 );', file=body)
        print("}", file=body)

        print(f'ulong {n}_size( {n}_t const * self ) {{', file=body)
        print('  ulong size = 0;', file=body)
        print(f'  size += sizeof({self.repr});', file=body)
        print('  switch (self->discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            if not isinstance(v, str):
                print(f'  case {i}: {{', file=body)
                v.emitSize('inner.', indent)
                print('    break;', file=body)
                print('  }', file=body)
        print('  }', file=body)
        print('  return size;', file=body)
        print("}", file=body)
        print("", file=body)

        if self.produce_global and not self.isFlat():
            print(f'ulong {n}_size_global( {n}_global_t const * self ) {{', file=body)
            print('  ulong size = 0;', file=body)
            print(f'  size += sizeof({self.repr});', file=body)
            print('  switch (self->discriminant) {', file=body)
            for i, v in enumerate(self.variants):
                if not isinstance(v, str):
                    print(f'  case {i}: {{', file=body)
                    v.emitSizeGlobal('inner.', indent)
                    print('    break;', file=body)
                    print('  }', file=body)
            print('  }', file=body)
            print('  return size;', file=body)
            print("}", file=body)
            print("", file=body)

        if not self.isFixedSize():
            print(f'int {n}_inner_encode( {n}_inner_t const * self, {self.repr} discriminant, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
            first = True
            for i, v in enumerate(self.variants):
                if not isinstance(v, str):
                    if first:
                        print('  int err;', file=body)
                        print('  switch (discriminant) {', file=body)
                        first = False
                    print(f'  case {i}: {{', file=body)
                    v.emitEncode(indent)
                    print('    break;', file=body)
                    print('  }', file=body)
            if not first:
                print('  }', file=body)
            print('  return FD_BINCODE_SUCCESS;', file=body)
            print("}", file=body)

        print(f'int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        if self.compact:
            print('  ushort discriminant = (ushort) self->discriminant;', file=body)
            print('  int err = fd_bincode_compact_u16_encode( &discriminant, ctx );', file=body)
        else:
            print(f'  int err = fd_bincode_{self.repr_codec_stem}_encode( self->discriminant, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
        if not self.isFixedSize():
            print(f'  return {n}_inner_encode( &self->inner, self->discriminant, ctx );', file=body)
        else:
            print('  return err;', file=body)
        print("}", file=body)
        print("", file=body)

        indent = ''

    def emitPostamble(self):
        for v in self.variants:
            if not isinstance(v, str):
                v.emitPostamble()

# Global type mapping for cross-references
type_map = {}

# Main function that orchestrates the code generation process
def main():
    """
    Main code generation function.

    This function processes all type definitions from the JSON configuration and
    generates the complete C code in multiple phases:

    1. Parse and create all type objects
    2. Propagate global attributes through type dependencies
    3. Build lookup tables for type properties
    4. Generate headers, prototypes, implementations, and reflection data

    The multi-pass approach ensures all types are properly declared before
    any code that references them is generated.
    """

    # Parse all type definitions from JSON
    alltypes = []
    for entry in entries:
        if entry['type'] == 'opaque':
            alltypes.append(OpaqueType(entry))
        if entry['type'] == 'struct':
            alltypes.append(StructType(entry))
        if entry['type'] == 'enum':
            alltypes.append(EnumType(entry))

    # Build type mapping and identify global types
    propagate = set()
    global type_map
    for t in alltypes:
        if t.produce_global:
            propagate.add(t)
        type_map[t.name] = t

    # Propagate 'global' attribute recursively through dependencies
    # We need to propagate the 'global' attribute recursively through
    # all the types specified in fd_types.json to be global. We need
    # to mark all of the submembers AND subtypes of these global types
    # as global.
    while len(propagate) > 0:
        t = propagate.pop()
        for sub in t.subTypes():
            sub.produce_global = True
            propagate.add(sub)
        for sub in t.subMembers():
            sub.produce_global = True

    # Build lookup tables for type properties
    nametypes = {}
    for t in alltypes:
        if hasattr(t, 'fullname'):
            nametypes[t.fullname] = t

    # Update global type property sets
    global fixedsizetypes
    global fuzzytypes
    global flattypes
    for typeinfo in alltypes:
        if typeinfo.isFixedSize():
            fixedsizetypes[typeinfo.name] = typeinfo.fixedSize()
        if typeinfo.isFlat():
            flattypes.add(typeinfo.name)
        if typeinfo.isFuzzy():
            fuzzytypes.add(typeinfo.name)

    # Generate struct/union/enum declarations
    for t in alltypes:
        t.emitHeader()

    # Generate function prototypes
    print("", file=header)
    print("FD_PROTOTYPES_BEGIN", file=header)
    print("", file=header)

    for t in alltypes:
        t.emitPrototypes()

    print("FD_PROTOTYPES_END", file=header)
    print("", file=header)
    print("#endif // HEADER_" + json_object["name"].upper(), file=header)

    # Generate function implementations
    for t in alltypes:
        t.emitImpls()

    # Generate cleanup/postamble code
    for t in alltypes:
        t.emitPostamble()

    type_name_count = len(nametypes)
    print('#include "fd_types.h"', file=reflect)
    print('#include "fd_types_custom.h"', file=reflect)
    print('#include "fd_types_reflect_private.h"', file=reflect)
    print('#pragma GCC diagnostic ignored "-Wpedantic"', file=reflect)
    print(f'ulong fd_types_vt_list_cnt = {type_name_count};', file=reflect)
    print("fd_types_vt_t const fd_types_vt_list[] = {", file=reflect)
    for key,val in nametypes.items():
        print('  {', file=reflect, end='')
        print(f' .name=\"{key}\",', file=reflect, end='')
        print(f' .name_len={len(key)},', file=reflect, end='')
        print(f' .align={key.upper()}_ALIGN,', file=reflect, end='')
        print(f' .new_=(void *){key}_new,', file=reflect, end='')
        print(f' .decode=(void *){key}_decode,', file=reflect, end='')
        print(f' .size=(void *){key}_size,', file=reflect, end='')
        print(f' .walk=(void *){key}_walk,', file=reflect, end='')
        print(f' .decode_footprint=(void *){key}_decode_footprint,', file=reflect, end='')
        print(f' .encode=(void *){key}_encode', file=reflect, end='')
        print('  },', file=reflect)
    print("  { .name=NULL }", file=reflect)
    print("};", file=reflect)

    print('#include "fd_types_custom.c"', file=body)

if __name__ == "__main__":
    main()
