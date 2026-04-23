#!/usr/bin/env python3
"""
C Code Generator for Solana/Firedancer Type System

This script generates C header and implementation files for serialization/deserialization
of Solana blockchain data structures. It reads type definitions from a JSON configuration
file and generates optimized C code for binary encoding/decoding, and memory management.

Usage: python3 gen_stubs.py <header_file> <implementation_file>
"""

import json
import sys

# Load type definitions from JSON configuration file
with open('fd_types.json', 'r') as json_file:
    json_object = json.load(json_file)

# Open output files for writing generated C code
header = open(sys.argv[1], "w")      # Header file (.h)
body = open(sys.argv[2], "w")        # Implementation file (.c)

# Extract configuration from JSON
namespace = json_object["namespace"]  # Namespace prefix for generated functions
entries = json_object["entries"]     # List of type definitions

# Generate file headers with auto-generation notice
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=header)
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=body)

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
             ("hash",32)]:
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
  "hash"
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
}

# Base class for all type nodes in the type system
class TypeNode:
    """
    Base class for all type definitions in the generated C code.

    Each type node represents a data structure that can be:
    - Serialized/deserialized using bincode format
    - Allocated and freed in memory
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
            self.produce_seek_end = bool(json["seek_end"]) if "seek_end" in json else False
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

    Attributes:
        type: The primitive type name (e.g., "ulong")
        decode: Whether this field should be decoded
        encode: Whether this field should be encoded
    """
    def __init__(self, container, json):
        super().__init__(json)
        self.type = json["type"]
        self.decode = ("decode" not in json or json["decode"])
        self.encode = ("encode" not in json or json["encode"])

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
        return True

    # Map from primitive type names to functions that emit C struct member declarations
    emitMemberMap = {
        "char" :      lambda n: print(f'  char {n};',      file=header),
        "double" :    lambda n: print(f'  double {n};',    file=header),
        "long" :      lambda n: print(f'  long {n};',      file=header),
        "uint" :      lambda n: print(f'  uint {n};',      file=header),
        "uint128" :   lambda n: print(f'  fd_w_u128_t {n};',   file=header),
        "bool" :      lambda n: print(f'  uchar {n};',     file=header),  # bool stored as uchar
        "uchar" :     lambda n: print(f'  uchar {n};',     file=header),
        "ulong" :     lambda n: print(f'  ulong {n};',     file=header),
        "ushort" :    lambda n: print(f'  ushort {n};',    file=header)
    }

    def emitMember(self):
        PrimitiveMember.emitMemberMap[self.type](self.name)

    def emitMemberGlobal(self):
        PrimitiveMember.emitMemberMap[self.type](self.name)

    def isFixedSize(self):
        if self.encode != self.decode:
            return False
        return self.type in fixedsizetypes

    def fixedSize(self):
        if not self.encode:
            return 0
        return fixedsizetypes[self.type]

    def isFuzzy(self):
        return self.type in fuzzytypes

    emitDecodeFootprintMap = {
        "char" :      lambda indent: print(f'{indent}  err = fd_bincode_uint8_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "double" :    lambda indent: print(f'{indent}  err = fd_bincode_double_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "long" :      lambda indent: print(f'{indent}  err = fd_bincode_uint64_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint" :      lambda indent: print(f'{indent}  err = fd_bincode_uint32_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint128" :   lambda indent: print(f'{indent}  err = fd_bincode_uint128_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "bool" :      lambda indent: print(f'{indent}  err = fd_bincode_bool_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar" :     lambda indent: print(f'{indent}  err = fd_bincode_uint8_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "ulong" :     lambda indent: print(f'{indent}  err = fd_bincode_uint64_decode_footprint( ctx );\n  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body),
        "ushort" :    lambda indent: print(f'{indent}  err = fd_bincode_uint16_decode_footprint( ctx );\n  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
    }

    def emitDecodeFootprint(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeFootprintMap[self.type](indent)

    emitDecodeMap = {
        "char" :      lambda n, indent: print(f'{indent}  fd_bincode_uint8_decode_unsafe( (uchar *) &self->{n}, ctx );', file=body),
        "double" :    lambda n, indent: print(f'{indent}  fd_bincode_double_decode_unsafe( &self->{n}, ctx );', file=body),
        "long" :      lambda n, indent: print(f'{indent}  fd_bincode_uint64_decode_unsafe( (ulong *) &self->{n}, ctx );', file=body),
        "uint" :      lambda n, indent: print(f'{indent}  fd_bincode_uint32_decode_unsafe( &self->{n}, ctx );', file=body),
        "uint128" :   lambda n, indent: print(f'{indent}  fd_bincode_uint128_decode_unsafe( &self->{n}, ctx );', file=body),
        "bool" :      lambda n, indent: print(f'{indent}  fd_bincode_bool_decode_unsafe( &self->{n}, ctx );', file=body),
        "uchar" :     lambda n, indent: print(f'{indent}  fd_bincode_uint8_decode_unsafe( &self->{n}, ctx );', file=body),
        "ulong" :     lambda n, indent: print(f'{indent}  fd_bincode_uint64_decode_unsafe( &self->{n}, ctx );', file=body),
        "ushort" :    lambda n, indent: print(f'{indent}  fd_bincode_uint16_decode_unsafe( &self->{n}, ctx );', file=body)
    }

    def emitDecodeInner(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, indent)

    def emitDecodeInnerGlobal(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, indent)

    emitEncodeMap = {
        "char" :      lambda n, indent: print(f'{indent}  err = fd_bincode_uint8_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "double" :    lambda n, indent: print(f'{indent}  err = fd_bincode_double_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "long" :      lambda n, indent: print(f'{indent}  err = fd_bincode_uint64_encode( (ulong)self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint" :      lambda n, indent: print(f'{indent}  err = fd_bincode_uint32_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint128" :   lambda n, indent: print(f'{indent}  err = fd_bincode_uint128_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "bool" :      lambda n, indent: print(f'{indent}  err = fd_bincode_bool_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar" :     lambda n, indent: print(f'{indent}  err = fd_bincode_uint8_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "ulong" :     lambda n, indent: print(f'{indent}  err = fd_bincode_uint64_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "ushort" :    lambda n, indent: print(f'{indent}  err = fd_bincode_uint16_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body)
    }

    def emitEncode(self, indent=''):
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, indent)

    def emitEncodeGlobal(self, indent=''):
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, indent)

    emitSizeMap = {
        "char" :      lambda indent: print(f'{indent}  size += sizeof(char);', file=body),
        "double" :    lambda indent: print(f'{indent}  size += sizeof(double);', file=body),
        "long" :      lambda indent: print(f'{indent}  size += sizeof(long);', file=body),
        "uint" :      lambda indent: print(f'{indent}  size += sizeof(uint);', file=body),
        "uint128" :   lambda indent: print(f'{indent}  size += sizeof(uint128);', file=body),
        "bool" :      lambda indent: print(f'{indent}  size += sizeof(char);', file=body),
        "uchar" :     lambda indent: print(f'{indent}  size += sizeof(char);', file=body),
        "ulong" :     lambda indent: print(f'{indent}  size += sizeof(ulong);', file=body),
        "ushort" :    lambda indent: print(f'{indent}  size += sizeof(ushort);', file=body)
    }

    def emitSize(self, inner, indent=''):
        if self.encode:
            PrimitiveMember.emitSizeMap[self.type](indent)

    def emitSizeGlobal(self, inner, indent=''):
        if self.encode:
            PrimitiveMember.emitSizeMap[self.type](indent)

# This is a member which IS a struct, NOT a member OF a struct
class StructMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.type = json["type"]

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

# Class representing dynamic arrays/vectors
class VectorMember(TypeNode):
    """
    Represents a dynamic array (vector) of elements.

    Vectors are encoded as: [length][element1][element2]...[elementN]

    Supports:
    - Different element types (primitives or complex types)
    - Memory management for both regular and global variants

    Attributes:
        element: Type of elements stored in the vector
    """
    def __init__(self, container, json, **kwargs):
        if (json is not None):
            super().__init__(json)
            self.element = json["element"]
        elif(json is None and 'name' in kwargs):
            super().__init__(json, name=kwargs['name'])
            if 'element' in kwargs:
                self.element = kwargs['element']
            else:
                raise ValueError(f"missing element argument in {kwargs}")

    def isFlat(self):
        return False

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'  ulong {self.name}_len;', file=header)
        if self.element in simpletypes:
            print(f'  {self.element}* {self.name};', file=header)
        else:
            print(f'  {namespace}_{self.element}_t * {self.name};', file=header)

    def emitMemberGlobal(self):
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
    """
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.size = (json["size"] if "size" in json else None)

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

class DequeMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.min = json.get("min", None)

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
        if self.min:
            min_tag = f" (min cnt {self.min})"
        else:
            min_tag = ""
        print(f'  {self.elem_type()} * {self.name}; /* fd_deque_dynamic{min_tag} */', file=header)

    def emitMemberGlobal(self):
        if self.min:
            min_tag = f" (min cnt {self.min})"
        else:
            min_tag = ""
        print(f'  ulong {self.name}_offset; /* fd_deque_dynamic{min_tag} */', file=header)

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
        print(f'  ulong {self.name}_len;', file=body)
        print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY( err ) ) return err;', file=body)

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
        print(f'    ulong {self.name}_len = 0;', file=body)
        print(f'    err = fd_bincode_uint64_encode( {self.name}_len, ctx );', file=body)
        print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        print(f'  if( self->{self.name} ) {{', file=body)
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
        print('    size += sizeof(ulong);', file=body)
        print('  }', file=body)


memberTypeMap = {
    "static_vector" : StaticVectorMember,
    "vector" :        VectorMember,
    "deque" :         DequeMember,
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


# FIXME horrible code
def extract_sub_type(member):
    if isinstance(member, str):
        return None
    if isinstance(member, PrimitiveMember):
        return None
    if isinstance(member, BitVectorMember):
        return None
    if hasattr(member, "element"):
        return type_map[member.element] if member.element in type_map else None
    if hasattr(member, "type"):
        return type_map[member.type] if member.type in type_map else None
    raise ValueError(f"Unknown type {member} in extract_sub_type")

def extract_member_type(member):
    if isinstance(member, str):
        return None
    if isinstance(member, PrimitiveMember):
        return None
    if isinstance(member, BitVectorMember):
        return None
    if hasattr(member, "element"):
        return member
    if hasattr(member, "type"):
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
    - Both regular and "global" variants (using offsets vs pointers)

    Attributes:
        fullname: Full qualified name with namespace prefix
        fields: List of member fields in this struct
        comment: Optional comment/documentation for the struct
        encoders: Encoder configuration (if any)
        custom_decode_inner: Whether to use custom decode implementation
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
            if self.produce_seek_end:
                print(f'int {n}_seek_end( fd_bincode_decode_ctx_t * ctx );', file=header)
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
                print(f'  ctx->data = (void *)( (ulong)ctx->data + {self.fixedSize()}UL );', file=body)
                print(f'  return 0;', file=body)
                print(f'}}', file=body)
            else:
                print(f'static int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
                print(f'  if( ctx->data>=ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
                print(f'  int err = 0;', file=body)
                for f in self.fields:
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
                    f.emitDecodeInner()
                print(f'}}', file=body)

            if self.produce_seek_end:
                print(f'int {n}_seek_end( fd_bincode_decode_ctx_t * ctx ) {{', file=body)
                print(f'  ulong total_sz;', file=body)
                print(f'  int err = {n}_decode_footprint_inner( ctx, &total_sz );', file=body)
                print(f'  if( ctx->data>ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
                print(f'  return err;', file=body)
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
    4. Generate headers, prototypes, implementations

    The multi-pass approach ensures all types are properly declared before
    any code that references them is generated.
    """

    # Parse all type definitions from JSON
    alltypes = []
    for entry in entries:
        if entry['type'] == 'struct':
            alltypes.append(StructType(entry))

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

    print('#include "fd_types_custom.c"', file=body)

if __name__ == "__main__":
    main()
