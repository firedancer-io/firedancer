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

# Map from primitive types to their corresponding bincode function names
# This allows the code generator to emit the correct function calls for each type
simpletypes = dict()
for t,t2 in [("ulong","uint64")]:
    simpletypes[t] = t2

# Map from type name to encoded byte size for fixed-size types
# Used for memory allocation and size calculations
fixedsizetypes = dict()
for t,t2 in [("ulong",8)]:
    fixedsizetypes[t] = t2

# Set of types that do not contain nested local pointers
# These types can be serialized directly without special offset handling
flattypes = {
  "ulong",
}

# Types that are fixed size and valid for all possible bit patterns
# These types can be used in fuzzing without special validation
# (e.g. ulong is in here, but bool is not because not all bit patterns are valid bools)
fuzzytypes = {
    "ulong",
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
        encoders: Encoder configuration (if any)
        arch_index: Architecture-specific index for optimization
    """
    def __init__(self, json, **kwargs):
        if json is not None:
            self.name = json["name"]
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

    def emitNew(self, indent=''):
        """Generate constructor/initialization code for this primitive type."""
        pass

    def isFlat(self):
        return True

    # Map from primitive type names to functions that emit C struct member declarations
    emitMemberMap = {
        "ulong" :     lambda n: print(f'  ulong {n};',     file=header),
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
        "ulong" :     lambda indent: print(f'{indent}  err = fd_bincode_uint64_decode_footprint( ctx );\n  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body),
    }

    def emitDecodeFootprint(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeFootprintMap[self.type](indent)

    emitDecodeMap = {
        "ulong" :     lambda n, indent: print(f'{indent}  fd_bincode_uint64_decode_unsafe( &self->{n}, ctx );', file=body),
    }

    def emitDecodeInner(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, indent)

    def emitDecodeInnerGlobal(self, indent=''):
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, indent)

    emitEncodeMap = {
        "ulong" :     lambda n, indent: print(f'{indent}  err = fd_bincode_uint64_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
    }

    def emitEncode(self, indent=''):
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, indent)

    def emitEncodeGlobal(self, indent=''):
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, indent)

    emitSizeMap = {
        "ulong" :     lambda indent: print(f'{indent}  size += sizeof(ulong);', file=body)
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

    def emitMember(self, indent=''):
        print(f'{indent}  {namespace}_{self.type}_t {self.name};', file=header)

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

    def emitEncode(self, indent=''):
        print(f'{indent}  err = {namespace}_{self.type}_encode( &self->{self.name}, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitSize(self, inner, indent=''):
        print(f'{indent}  size += {namespace}_{self.type}_size( &self->{inner}{self.name} );', file=body)

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

    def emitMember(self):
        print(f'  ulong {self.name}_len;', file=header)
        print(f'  ulong {self.name}_size;', file=header)
        print(f'  ulong {self.name}_offset;', file=header)

        if self.element in simpletypes:
            print(f'  {self.element} {self.name}[{self.size}];', file=header)
        else:
            print(f'  {namespace}_{self.element}_t {self.name}[{self.size}];', file=header)

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

    def emitSize(self, inner):
        print('  size += sizeof(ulong);', file=body)
        if self.element == "uchar":
            print(f'  size += self->{self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'  size += self->{self.name}_len * sizeof({self.element});', file=body)
        else:
            print(f'  for( ulong i=0; i<self->{self.name}_len; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)


memberTypeMap = {
    "static_vector" : StaticVectorMember,
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
        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print("", file=header)

    def emitEncodes(self):
        n = self.fullname
        self.emitEncode(n)

    def emitEncode(self, n):
        print(f'int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        print('  int err;', file=body)
        for f in self.fields:
            if hasattr(f, 'encode') and not f.encode:
                continue
            f.emitEncode()
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

            print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_t * self = ({n}_t *)mem;', file=body)
            print(f'  {n}_new( self );', file=body)
            print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_t);', file=body)
            print(f'  void * * alloc_mem = &alloc_region;', file=body)
            print(f'  {n}_decode_inner( mem, alloc_mem, ctx );', file=body)
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

if __name__ == "__main__":
    main()
