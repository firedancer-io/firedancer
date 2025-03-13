import json
import sys


with open('fd_types.json', 'r') as json_file:
    json_object = json.load(json_file)

header = open(sys.argv[1], "w")
body = open(sys.argv[2], "w")
names = open(sys.argv[3], "w")

namespace = json_object["namespace"]
entries = json_object["entries"]

print("// This is an auto-generated file. To add entries, edit fd_types.json", file=header)
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=body)
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=names)
print("#ifndef HEADER_" + json_object["name"].upper(), file=header)
print("#define HEADER_" + json_object["name"].upper(), file=header)
print("", file=header)
for extra in json_object["extra_header"]:
    print(extra, file=header)
print("", file=header)

print(f'#include "{sys.argv[1]}"', file=body)

print('#pragma GCC diagnostic ignored "-Wunused-parameter"', file=body)
print('#pragma GCC diagnostic ignored "-Wunused-variable"', file=body)

print('#define SOURCE_fd_src_flamenco_types_fd_types_c', file=body)
print('#include "fd_types_custom.c"', file=body)

preambletypes = set()
postambletypes = set()
indent = ''

# Map from primitive types to bincode function names
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

# Map from type name to encoded size
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

# Types that are fixed size and valid for all possible bit patterns
# (e.g. ulong is in here, but bool is not)
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

class TypeNode:
    def __init__(self, json):
        self.name = json["name"]

    def isFixedSize(self):
        return False

    def fixedSize(self):
        return

    def isFuzzy(self):
        return False

class PrimitiveMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.type = json["type"]
        self.varint = ("modifier" in json and json["modifier"] == "varint")
        self.decode = ("decode" not in json or json["decode"])
        self.encode = ("encode" not in json or json["encode"])
        self.walk = ("walk" not in json or json["walk"])

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitNew(self):
        pass

    def emitDestroy(self):
        if self.type == "char*":
            print(f'  self->{self.name} = NULL;\n', file=body)

    emitMemberMap = {
        "char" :      lambda n: print(f'  char {n};',      file=header),
        "char*" :     lambda n: print(f'  char* {n};',     file=header),
        "char[32]" :  lambda n: print(f'  char {n}[32];',  file=header),
        "double" :    lambda n: print(f'  double {n};',    file=header),
        "long" :      lambda n: print(f'  long {n};',      file=header),
        "uint" :      lambda n: print(f'  uint {n};',      file=header),
        "uint128" :   lambda n: print(f'  uint128 {n};',   file=header),
        "bool" :      lambda n: print(f'  uchar {n};',     file=header),
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

    def string_decode_footprint(n, varint):
        # This ends up working for decode_footprint but in a hacky way
        print(f'{indent}  ulong slen;', file=body)
        print(f'{indent}  err = fd_bincode_uint64_decode( &slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'{indent}  err = fd_bincode_bytes_decode_footprint( slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    def ushort_decode_footprint(n, varint):
        if varint:
            print(f'{indent}  do {{ ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); }} while(0);', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint16_decode_footprint( ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    def ulong_decode_footprint(n, varint):
        if varint:
            print(f'{indent}  err = fd_bincode_varint_decode_footprint( ctx );', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint64_decode_footprint( ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    def string_decode_footprint(n, varint):
        print(f'{indent}  ulong slen;', file=body)
        print(f'{indent}  err = fd_bincode_uint64_decode( &slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'{indent}  err = fd_bincode_bytes_decode_footprint( slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'{indent}  *total_sz += slen;', file=body)

    emitDecodeFootprintMap = {
        "char" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_decode_footprint(n, varint),
        "char[32]" :  lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 32, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "double" :    lambda n, varint: print(f'{indent}  err = fd_bincode_double_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "long" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint64_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint32_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint128" :   lambda n, varint: print(f'{indent}  err = fd_bincode_uint128_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "bool" :      lambda n, varint: print(f'{indent}  err = fd_bincode_bool_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar" :     lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_decode_footprint( ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[32]" : lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 32, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[128]" :lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 128, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[2048]":lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_footprint( 2048, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_decode_footprint(n, varint),
        "ushort" :    lambda n, varint: PrimitiveMember.ushort_decode_footprint(n, varint),
    }

    def emitDecodeFootprint(self):
        if self.decode:
            PrimitiveMember.emitDecodeFootprintMap[self.type](self.name, self.varint)

    def string_decode_unsafe(n, varint):
        print(f'{indent}  ulong slen;', file=body)
        print(f'{indent}  fd_bincode_uint64_decode_unsafe( &slen, ctx );', file=body)
        print(f'{indent}  self->{n} = *alloc_mem;', file=body)
        print(f'{indent}  fd_bincode_bytes_decode_unsafe( (uchar *)self->{n}, slen, ctx );', file=body)
        print(f"{indent}  self->{n}[slen] = '\\0';", file=body)
        print(f'{indent}  *alloc_mem = (uchar *)(*alloc_mem) + slen;', file=body)

    def ushort_decode_unsafe(n, varint):
        if varint:
            print(f'{indent}  fd_bincode_compact_u16_decode_unsafe( &self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  fd_bincode_uint16_decode_unsafe( &self->{n}, ctx );', file=body),

    def ulong_decode_unsafe(n, varint):
        if varint:
            print(f'{indent}  fd_bincode_varint_decode_unsafe( &self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  fd_bincode_uint64_decode_unsafe( &self->{n}, ctx );', file=body),

    emitDecodeMap = {
        "char" :      lambda n, varint: print(f'{indent}  fd_bincode_uint8_decode_unsafe( (uchar *) &self->{n}, ctx );', file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_decode_unsafe(n, varint),
        "char[32]" :  lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "double" :    lambda n, varint: print(f'{indent}  fd_bincode_double_decode_unsafe( &self->{n}, ctx );', file=body),
        "long" :      lambda n, varint: print(f'{indent}  fd_bincode_uint64_decode_unsafe( (ulong *) &self->{n}, ctx );', file=body),
        "uint" :      lambda n, varint: print(f'{indent}  fd_bincode_uint32_decode_unsafe( &self->{n}, ctx );', file=body),
        "uint128" :   lambda n, varint: print(f'{indent}  fd_bincode_uint128_decode_unsafe( &self->{n}, ctx );', file=body),
        "bool" :      lambda n, varint: print(f'{indent}  fd_bincode_bool_decode_unsafe( &self->{n}, ctx );', file=body),
        "uchar" :     lambda n, varint: print(f'{indent}  fd_bincode_uint8_decode_unsafe( &self->{n}, ctx );', file=body),
        "uchar[32]" : lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "uchar[128]" :lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "uchar[2048]":lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe( &self->{n}[0], sizeof(self->{n}), ctx );', file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_decode_unsafe(n, varint),
        "ushort" :    lambda n, varint: PrimitiveMember.ushort_decode_unsafe(n, varint),
    }

    def emitDecodeInner(self):
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, self.varint)

    def emitDecodeInnerGlobal(self):
        if self.decode:
            PrimitiveMember.emitDecodeMap[self.type](self.name, self.varint)

    emitGlobalLocalConvertMap = {
        "char" :      lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "char*" :     lambda n: print(f'{indent}  strcpy( self->{n}, mem->{n});', file=body),
        "char[32]" :  lambda n: print(f'{indent}  fd_memcpy( &self->{n}[0], &mem->{n}[0], sizeof(self->{n}) );', file=body),
        "double" :    lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "long" :      lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "uint" :      lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "uint128" :   lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "bool" :      lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "uchar" :     lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "uchar[32]" : lambda n: print(f'{indent}  fd_memcpy( &self->{n}[0], &mem->{n}[0], sizeof(self->{n}) );', file=body),
        "uchar[128]" :lambda n: print(f'{indent}  fd_memcpy( &self->{n}[0], &mem->{n}[0], sizeof(self->{n}) );', file=body),
        "uchar[2048]":lambda n: print(f'{indent}  fd_memcpy( &self->{n}[0], &mem->{n}[0], sizeof(self->{n}) );', file=body),
        "ulong" :     lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
        "ushort" :    lambda n: print(f'{indent}  self->{n} = mem->{n};', file=body),
    }

    def emitGlobalLocalConvert(self):
        if self.decode:
            PrimitiveMember.emitGlobalLocalConvertMap[self.type](self.name)

    def string_encode(n, varint):
        print(f'{indent}  ulong slen = strlen( (char *) self->{n} );', file=body)
        print(f'{indent}  err = fd_bincode_uint64_encode( slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'{indent}  err = fd_bincode_bytes_encode( (uchar *) self->{n}, slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def ushort_encode(n, varint):
        if varint:
            print(f'{indent}  err = fd_bincode_compact_u16_encode( &self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint16_encode( self->{n}, ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def ulong_encode(n, varint):
        if varint:
            print(f'{indent}  err = fd_bincode_varint_encode( self->{n}, ctx );', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint64_encode( self->{n}, ctx );', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    emitEncodeMap = {
        "char" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_encode(n, varint),
        "char[32]" :  lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode( &self->{n}[0], sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "double" :    lambda n, varint: print(f'{indent}  err = fd_bincode_double_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "long" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint64_encode( (ulong)self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint32_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uint128" :   lambda n, varint: print(f'{indent}  err = fd_bincode_uint128_encode( self->{n}, ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "bool" :      lambda n, varint: print(f'{indent}  err = fd_bincode_bool_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar" :     lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_encode( (uchar)(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[32]" : lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode( self->{n}, sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[128]" : lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode( self->{n}, sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "uchar[2048]" : lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode( self->{n}, sizeof(self->{n}), ctx );\n  if( FD_UNLIKELY( err ) ) return err;', file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_encode(n, varint),
        "ushort" :    lambda n, varint: PrimitiveMember.ushort_encode(n, varint),
    }

    def emitEncode(self):
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, self.varint)

    emitSizeMap = {
        "char" :      lambda n, varint, inner: print(f'{indent}  size += sizeof(char);', file=body),
        "char*" :     lambda n, varint, inner: print(f'{indent}  size += sizeof(ulong) + strlen(self->{inner}{n});', file=body),
        "char[32]" :  lambda n, varint, inner: print(f'{indent}  size += sizeof(char) * 32;', file=body),
        "double" :    lambda n, varint, inner: print(f'{indent}  size += sizeof(double);', file=body),
        "long" :      lambda n, varint, inner: print(f'{indent}  size += sizeof(long);', file=body),
        "uint" :      lambda n, varint, inner: print(f'{indent}  size += sizeof(uint);', file=body),
        "uint128" :   lambda n, varint, inner: print(f'{indent}  size += sizeof(uint128);', file=body),
        "bool" :      lambda n, varint, inner: print(f'{indent}  size += sizeof(char);', file=body),
        "uchar" :     lambda n, varint, inner: print(f'{indent}  size += sizeof(char);', file=body),
        "uchar[32]" : lambda n, varint, inner: print(f'{indent}  size += sizeof(char) * 32;', file=body),
        "uchar[128]" :lambda n, varint, inner: print(f'{indent}  size += sizeof(char) * 128;', file=body),
        "uchar[2048]":lambda n, varint, inner: print(f'{indent}  size += sizeof(char) * 2048;', file=body),
        "ulong" :     lambda n, varint, inner: print(f'{indent}  size += { ("fd_bincode_varint_size( self->" + n + " );") if varint else "sizeof(ulong);" }', file=body),
        "ushort" :    lambda n, varint, inner: print(f'{indent}  size += { ("fd_bincode_compact_u16_size( &self->" + n + " );") if varint else "sizeof(ushort);" }', file=body),
    }

    def emitSize(self, inner):
        if self.encode:
            PrimitiveMember.emitSizeMap[self.type](self.name, self.varint, inner);

    emitWalkMap = {
        "char" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR, "char", level );', file=body),
        "char*" :     lambda n, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_CSTR, "char*", level );', file=body),
        "double" :    lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE, "double", level );', file=body),
        "long" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SLONG, "long", level );', file=body),
        "uint" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT, "uint", level );', file=body),
        "uint128" :   lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level );', file=body),
        "bool" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_BOOL, "bool", level );', file=body),
        "uchar" :     lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );', file=body),
        "uchar[32]" : lambda n, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level );', file=body),
        "uchar[128]" :lambda n, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH1024, "uchar[128]", level );', file=body),
        "uchar[2048]":lambda n, inner: print(f'  fun( w, self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH16384, "uchar[2048]", level );', file=body),
        "ulong" :     lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_ULONG, "ulong", level );', file=body),
        "ushort" :    lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_USHORT, "ushort", level );', file=body)
    }

    def emitWalk(self, inner):
        if self.walk:
            PrimitiveMember.emitWalkMap[self.type](self.name, inner);

# This is a member which IS a struct, NOT a member OF a struct
class StructMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.type = json["type"]
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'{indent}  {namespace}_{self.type}_t {self.name};', file=header)

    def emitMemberGlobal(self):
        if self.type in fixedsizetypes:
            print(f'{indent}  {namespace}_{self.type}_t {self.name};', file=header)
        else:
            print(f'{indent}  {namespace}_{self.type}_global_t {self.name};', file=header)

    def isFixedSize(self):
        return self.type in fixedsizetypes

    def fixedSize(self):
        return fixedsizetypes[self.type]

    def isFuzzy(self):
        return self.type in fuzzytypes

    def emitNew(self):
        print(f'{indent}  {namespace}_{self.type}_new( &self->{self.name} );', file=body)

    def emitDestroy(self):
        print(f'{indent}  {namespace}_{self.type}_destroy( &self->{self.name} );', file=body)

    def emitDecodeFootprint(self):
        print(f'{indent}  err = {namespace}_{self.type}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitDecodeInner(self):
        print(f'{indent}  {namespace}_{self.type}_decode_inner( &self->{self.name}, alloc_mem, ctx );', file=body)

    def emitDecodeInnerGlobal(self):
        print(f'{indent}  {namespace}_{self.type}_decode_inner_global( &self->{self.name}, alloc_mem, ctx );', file=body)

    def emitGlobalLocalConvert(self):
        print(f'{indent}  err = {namespace}_{self.type}_convert_global_to_local( &mem->{self.name}, &self->{self.name}, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitEncode(self):
        print(f'{indent}  err = {namespace}_{self.type}_encode( &self->{self.name}, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err ) ) return err;', file=body)

    def emitSize(self, inner):
        print(f'{indent}  size += {namespace}_{self.type}_size( &self->{inner}{self.name} );', file=body)

    def emitWalk(self, inner):
        print(f'{indent}  {namespace}_{self.type}_walk( w, &self->{inner}{self.name}, fun, "{self.name}", level );', file=body)

class VectorMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

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
        print(f'  ulong {self.name}_gaddr;', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        print(f'  if( self->{self.name} ) {{', file=body)
        if self.element in simpletypes:
            pass
        else:
            print(f'    for( ulong i=0; i < self->{self.name}_len; i++ )', file=body)
            print(f'      {namespace}_{self.element}_destroy( self->{self.name} + i );', file=body)
        print(f'    self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitDecodeFootprint(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  if( {self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'
        el = el.upper()

        if self.element == "uchar":
            print(f'    *total_sz += 8UL + {self.name}_len;', file=body)
            print(f'    err = fd_bincode_bytes_decode_footprint( {self.name}_len, ctx );', file=body)
            print(f'    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

        else:
            if self.element in simpletypes:
                  print(f'    *total_sz += 8UL + sizeof({self.element})*{self.name}_len;', file=body)
            else:
                  print(f'    *total_sz += {el}_ALIGN + {el}_FOOTPRINT*{self.name}_len;', file=body)

            print(f'    for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)

            if self.element in simpletypes:
                print(f'      err = fd_bincode_{simpletypes[self.element]}_decode_footprint( ctx );', file=body)
            else:
                print(f'      err = {namespace}_{self.element}_decode_footprint_inner( ctx, total_sz );', file=body)

            print(f'      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
            print('    }', file=body)

        print('  }', file=body)

    def emitDecodeInner(self):
        if self.compact:
            print(f'  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'  if( self->{self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'
        el = el.upper()

        if self.element == "uchar":
            print(f'    self->{self.name} = *alloc_mem;', file=body)
            print(f'    fd_bincode_bytes_decode_unsafe( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            print(f'    *alloc_mem = (uchar *)(*alloc_mem) + self->{self.name}_len;', file=body)
        else:
            if self.element in simpletypes:
                print(f'    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );', file=body)
                print(f'    self->{self.name} = *alloc_mem;', file=body)
                print(f'    *alloc_mem = (uchar *)(*alloc_mem) + sizeof({self.element})*self->{self.name}_len;', file=body)
            else:
                print(f'    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), {el}_ALIGN );', file=body)
                print(f'    self->{self.name} = *alloc_mem;', file=body)
                print(f'    *alloc_mem = (uchar *)(*alloc_mem) + {el}_FOOTPRINT*self->{self.name}_len;', file=body)

            print(f'    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)

            if self.element in simpletypes:
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name} + i, ctx );', file=body)
            else:
                print(f'      {namespace}_{self.element}_new( self->{self.name} + i );', file=body)
                print(f'      {namespace}_{self.element}_decode_inner( self->{self.name} + i, alloc_mem, ctx );', file=body)

            print('    }', file=body)

        print('  } else', file=body)
        print(f'    self->{self.name} = NULL;', file=body)

    def emitDecodeInnerGlobal(self):
        if self.compact:
            print(f'  fd_bincode_compact_u16_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'  fd_bincode_uint64_decode_unsafe( &self->{self.name}_len, ctx );', file=body)
        print(f'  if( self->{self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'
        el = el.upper()

        if self.element == "uchar":
            print(f'    self->{self.name}_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
            print(f'    fd_bincode_bytes_decode_unsafe( *alloc_mem, self->{self.name}_len, ctx );', file=body)
            print(f'    *alloc_mem = (uchar *)(*alloc_mem) + self->{self.name}_len;', file=body)
        else:
            if self.element in simpletypes:
                print(f'    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );', file=body)
                print(f'    self->{self.name}_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
                print(f'    uchar * cur_mem = (uchar *)(*alloc_mem);', file=body)
                print(f'    *alloc_mem = (uchar *)(*alloc_mem) + sizeof({self.element})*self->{self.name}_len;', file=body)
            else:
                print(f'    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), {el}_ALIGN );', file=body)
                print(f'    self->{self.name}_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
                print(f'    uchar * cur_mem = (uchar *)(*alloc_mem);', file=body)
                print(f'    *alloc_mem = (uchar *)(*alloc_mem) + {el}_FOOTPRINT*self->{self.name}_len;', file=body)

            print(f'    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
            if self.element in simpletypes:
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( ({self.element}*)(cur_mem + sizeof({self.element}) * i), ctx );', file=body)
            else:
                print(f'      {namespace}_{self.element}_new( ({namespace}_{self.element}_t *)(cur_mem + {el}_FOOTPRINT * i) );', file=body)
                print(f'      {namespace}_{self.element}_decode_inner_global( cur_mem + {el}_FOOTPRINT * i, alloc_mem, ctx );', file=body)

            print('    }', file=body)

        print('  } else', file=body)
        print(f'    self->{self.name}_gaddr = 0UL;', file=body)

    def emitGlobalLocalConvert(self):
        print(f'  self->{self.name}_len = mem->{self.name}_len;', file=body)
        print(f'  self->{self.name}     = fd_wksp_laddr_fast( ctx->wksp, mem->{self.name}_gaddr );', file=body);

    def emitEncode(self):
        if self.compact:
            print(f'  err = fd_bincode_compact_u16_encode( &self->{self.name}_len, ctx );', file=body)
        else:
            print(f'  err = fd_bincode_uint64_encode( self->{self.name}_len, ctx );', file=body)
        print(f'  if( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  if( self->{self.name}_len ) {{', file=body)

        if self.element == "uchar":
            print(f'    err = fd_bincode_bytes_encode( self->{self.name}, self->{self.name}_len, ctx );', file=body)
            print(f'    if( FD_UNLIKELY( err ) ) return err;', file=body)

        else:
            print(f'    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)

            if self.element in simpletypes:
                print(f'      err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}[i], ctx );', file=body)
            else:
                print(f'      err = {namespace}_{self.element}_encode( self->{self.name} + i, ctx );', file=body)
                print('      if( FD_UNLIKELY( err ) ) return err;', file=body)

            print('    }', file=body)

        print('  }', file=body)

    def emitSize(self, inner):
        print(f'  do {{', file=body)
        if self.compact:
            print(f'    ushort tmp = (ushort)self->{self.name}_len;', file=body)
            print(f'    size += fd_bincode_compact_u16_size( &tmp );', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        if self.element == "uchar":
            print(f'    size += self->{self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'    size += self->{self.name}_len * sizeof({self.element});', file=body)
        else:
            print(f'    for( ulong i=0; i < self->{self.name}_len; i++ )', file=body)
            print(f'      size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)
        print(f'  }} while(0);', file=body)

    emitWalkMap = {
        "double" :  lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_DOUBLE,  "double",  level );', file=body),
        "long" :    lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_LONG,    "long",    level );', file=body),
        "uint" :    lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_UINT,    "uint",    level );', file=body),
        "uint128" : lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level );', file=body),
        "ulong" :   lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );', file=body),
        "ushort" :  lambda n: print(f'  fun( w, self->{n} + i, "{n}", FD_FLAMENCO_TYPE_USHORT,  "ushort",  level );', file=body)
    }

    def emitWalk(self, inner):
        if self.element == "uchar":
            print(f'  fun(w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_UCHAR, "{self.element}", level );', file=body),
            return
        else:
            print(f'  if( self->{self.name}_len ) {{', file=body)
            print(f'    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR, "array", level++ );', file=body)
            print(f'    for( ulong i=0; i < self->{self.name}_len; i++ )', file=body)

        if self.element in VectorMember.emitWalkMap:
            body.write("    ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'      {namespace}_{self.element}_walk(w, self->{self.name} + i, fun, "{self.element}", level );', file=body)

        print(f'    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "array", level-- );', file=body)
        print('  }', file=body)

class StaticVectorMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.size = (json["size"] if "size" in json else None)
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def isFixedSize(self):
        return False

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
        else:
            print(f'  {namespace}_{self.element}_global_t {self.name}[{self.size}];', file=header)

    def emitNew(self):
        size = self.size
        print(f'  self->{self.name}_size = {self.size};', file=body)
        if self.element in simpletypes:
            pass
        else:
            print(f'  for( ulong i=0; i<{size}; i++ )', file=body)
            print(f'    {namespace}_{self.element}_new( self->{self.name} + i );', file=body)


    def emitDestroy(self):
        size = self.size

        if self.element in simpletypes:
            pass
        else:
            print(f'  for( ulong i=0; i<{size}; i++ )', file=body)
            print(f'    {namespace}_{self.element}_destroy( self->{self.name} + i );', file=body)

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
        else:
            print(f'    {namespace}_{self.element}_decode_inner_global( self->{self.name} + i, alloc_mem, ctx );', file=body)
        print('  }', file=body)

    def emitGlobalLocalConvert(self):
        print(f'  self->{self.name}_len    = mem->{self.name}_len;', file=body)
        print(f'  self->{self.name}_size   = mem->{self.name}_size;', file=body)
        print(f'  self->{self.name}_offset = mem->{self.name}_offset;', file=body)
        print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
        if self.element in simpletypes:
            print(f'    self->{self.name}[i] = mem->{self.name}[i];', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_convert_global_to_local( &mem->{self.name}[i], &self->{self.name}[i], ctx );', file=body)
            print(f'    if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'  }}', file=body)


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
        if (self.size & (self.size - 1)) == 0:
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

    emitWalkMap = {
        "double" :  lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_DOUBLE,  "double",  level );', file=body),
        "long" :    lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_LONG,    "long",    level );', file=body),
        "uint" :    lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_UINT,    "uint",    level );', file=body),
        "uint128" : lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level );', file=body),
        "ulong" :   lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );', file=body),
        "ushort" :  lambda n: print(f'  fun( w, self->{n} + idx, "{n}", FD_FLAMENCO_TYPE_USHORT,  "ushort",  level );', file=body)
    }

    def emitWalk(self, inner):
        if self.element == "uchar":
            print(f'  TODO: IMPLEMENT', file=body),
            return

        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR, "{self.element}[]", level++ );', file=body)
        print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
        if (self.size & (self.size - 1)) == 0:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) & ({self.size} - 1);', file=body)
        else:
            print(f'    ulong idx = ( i + self->{self.name}_offset ) % self->{self.name}_size;', file=body)
        if self.element in VectorMember.emitWalkMap:
            body.write("  ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'    {namespace}_{self.element}_walk( w, self->{self.name} + idx, fun, "{self.element}", level );', file=body)
        print('  }', file=body)
        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.element}[]", level-- );', file=body)

class StringMember(VectorMember):
    def __init__(self, container, json):
        json["element"] = "uchar"
        super().__init__(container, json)
        self.compact = False
        self.ignore_underflow = False

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
        self.growth = (json["growth"] if "growth" in json else None)

    def elem_type(self):
        if self.element in simpletypes:
            return self.element
        else:
            return f'{namespace}_{self.element}_t'

    def prefix(self):
        return f'deq_{self.elem_type()}'

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
        print(f'  ulong {self.name}_gaddr; /* fd_deque_dynamic{min_tag} */', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        print(f'  if( self->{self.name} ) {{', file=body)
        if self.element in simpletypes:
            pass
        else:
            print(f'    for( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );', file=body)
            print(f'      {namespace}_{self.element}_destroy( ele );', file=body)
            print('    }', file=body)
        print(f'    self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitDecodeFootprint(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
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

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {self.prefix()}_align() );', file=body)

        deque_type =  f"{self.element}" if self.element in simpletypes else f"{namespace}_{self.element}_t"

        if self.min:
            print(f'  ulong {self.name}_max = fd_ulong_max( {self.name}_len, {self.min} );', file=body)
            print(f'  self->{self.name}_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
            print(f'  {deque_type} * {self.name} = {self.prefix()}_join_new( alloc_mem, {self.name}_max );', file=body)
        else:
            print(f'  self->{self.name}_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
            print(f'  {deque_type} * {self.name} = {self.prefix()}_join_new( alloc_mem, {self.name}_len );', file=body)

        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {self.elem_type()} * elem = {self.prefix()}_push_tail_nocopy( {self.name} );', file=body);

        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe( elem, ctx );', file=body)
        else:
            print(f'    {namespace}_{self.element}_new( elem );', file=body)
            print(f'    {namespace}_{self.element}_decode_inner_global( elem, alloc_mem, ctx );', file=body)

        print('  }', file=body)

    def emitGlobalLocalConvert(self):
        print(f'  self->{self.name} = {self.prefix()}_join( fd_wksp_laddr_fast( ctx->wksp, mem->{self.name}_gaddr ) );', file=body)

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

    def emitWalk(self, inner):
        print(
            f'''
  /* Walk deque */
  fun( w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_ARR, "{self.name}", level++ );
  if( self->{self.name} ) {{
    for( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} );
         !{self.prefix()}_iter_done( self->{self.name}, iter );
         iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{
      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );''',
            file=body
        )

        if self.element == "uchar":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );', file=body),
        elif self.element == "ulong":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level );', file=body),
        elif self.element == "uint":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level );', file=body),
        else:
            print(f'      {namespace}_{self.element}_walk(w, ele, fun, "{self.name}", level );', file=body)

        print(f'''    }}
  }}
  fun( w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.name}", level-- );
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

    def emitMember(self):
        element_type = self.elem_type()
        print(f'  {element_type}_mapnode_t * {self.name}_pool;', file=header)
        print(f'  {element_type}_mapnode_t * {self.name}_root;', file=header)

    def emitMemberGlobal(self):
        element_type = self.elem_type()
        print(f'  ulong {self.name}_pool_gaddr;', file=header)
        print(f'  ulong {self.name}_root_gaddr;', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  for( {nodename} * n = {mapname}_minimum(self->{self.name}_pool, self->{self.name}_root ); n; n = {mapname}_successor(self->{self.name}_pool, n) ) {{', file=body);
        print(f'    {namespace}_{self.element}_destroy( &n->elem );', file=body)
        print('  }', file=body)
        print(f'  self->{self.name}_pool = NULL;', file=body)
        print(f'  self->{self.name}_root = NULL;', file=body)

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
            print(f'  ulong {self.name}_cnt = {self.name}_len;', file=body)
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
        print(f'    {mapname}_insert( self->{self.name}_pool, &self->{self.name}_root, node );', file=body)
        print('  }', file=body)

    def emitDecodeInnerGlobal(self):
        element_type = self.elem_type()
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
        print(f'  self->{self.name}_root_gaddr = 0UL;', file=body)
        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {nodename} * node = {mapname}_acquire( {self.name}_pool );', file=body)
        print(f'    {namespace}_{self.element}_new( &node->elem );', file=body)
        print(f'    {namespace}_{self.element}_decode_inner( &node->elem, alloc_mem, ctx );', file=body)
        print(f'    {mapname}_insert( {self.name}_pool, &{self.name}_root, node );', file=body)
        print(f'  }}', file=body)

        print(f'  self->{self.name}_pool_gaddr = fd_wksp_gaddr_fast( ctx->wksp, {self.name}_pool );', file=body)
        print(f'  self->{self.name}_root_gaddr = fd_wksp_gaddr_fast( ctx->wksp, {self.name}_root );', file=body)

    def emitGlobalLocalConvert(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        print(f'  self->{self.name}_pool = fd_wksp_laddr_fast( ctx->wksp, mem->{self.name}_pool_gaddr );', file=body)
        print(f'  self->{self.name}_root = fd_wksp_laddr_fast( ctx->wksp, mem->{self.name}_root_gaddr );', file=body)

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
        print(f'    for( {nodename} * n = {mapname}_minimum( self->{self.name}_pool, self->{self.name}_root ); n; n = {mapname}_successor( self->{self.name}_pool, n ) ) {{', file=body);
        print(f'      size += {namespace}_{self.element}_size( &n->elem );', file=body)
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
            print('      fun(w, &n->elem, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );', file=body),
        elif self.element == "ulong":
            print('      fun(w, &n->elem, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level );', file=body),
        elif self.element == "uint":
            print('      fun(w, &n->elem, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level );', file=body),
        else:
            print(f'      {namespace}_{self.element}_walk(w, &n->elem, fun, "{self.name}", level );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)


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
        print(f'  ulong pool_gaddr;', file=header)
        print(f'  ulong treap_gaddr;', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool = self.name + '_pool'

        print(f'  if( !self->treap || !self->pool ) return;', file=body)
        print(f'  for( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body);
        print(f'         !{treap_name}_fwd_iter_done( iter );', file=body);
        print(f'         iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
        print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)
        print(f'      {treap_t.rstrip("_t")}_destroy( ele );', file=body)
        print('    }', file=body)
        print(f'  self->pool = NULL;', file=body)
        print(f'  self->treap = NULL;', file=body)

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
        print(f'  self->pool_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
        print(f'  {treap_t} * pool = {pool_name}_join_new( alloc_mem, {treap_name}_max );', file=body)

        print(f'  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {treap_name}_align() );', file=body)
        print(f'  self->treap_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
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

    def emitGlobalLocalConvert(self):
        pool_name = self.name + '_pool'
        treap_name = self.name + '_treap'
        print(f'  self->pool  = {pool_name}_join( fd_wksp_laddr_fast( ctx->wksp, mem->pool_gaddr ) );', file=body)
        print(f'  self->treap = {treap_name}_join( fd_wksp_laddr_fast( ctx->wksp, mem->treap_gaddr ) );', file=body)

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
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );', file=body),
        elif treap_t == "ulong":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level );', file=body),
        elif treap_t == "uint":
            print('      fun( w, ele, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level );', file=body),
        else:
            print(f'      {treap_t.rstrip("_t")}_walk( w, ele, fun, "{treap_t}", level );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)


class OptionMember(TypeNode):
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
            else:
                print(f'  {namespace}_{self.element}_t {self.name};', file=header)
            print(f'  uchar has_{self.name};', file=header)
        else:
            print(f'  ulong {self.name}_gaddr;', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        if self.flat:
            print(f'  if( self->has_{self.name} ) {{', file=body)
            if self.element not in simpletypes:
                print(f'    {namespace}_{self.element}_destroy( &self->{self.name} );', file=body)
            print(f'    self->has_{self.name} = 0;', file=body)
            print('  }', file=body)
        else:
            print(f'  if( self->{self.name} ) {{', file=body)
            if self.element not in simpletypes:
                print(f'    {namespace}_{self.element}_destroy( self->{self.name} );', file=body)
            print(f'    self->{self.name} = NULL;', file=body)
            print('  }', file=body)

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
              el = el.upper()
              print(f'    *total_sz += {el}_ALIGN + {el}_FOOTPRINT;', file=body)
        if self.element in simpletypes:
            print(f'      err = fd_bincode_{simpletypes[self.element]}_decode_footprint( ctx );', file=body)
        else:
            el = f'{namespace}_{self.element}'
            el = el.upper()
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
                el = el.upper()
                print(f'      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {el}_ALIGN );', file=body)
                print(f'      self->{self.name} = *alloc_mem;', file=body)
                print(f'      *alloc_mem = (uchar *)*alloc_mem + {el}_FOOTPRINT;', file=body)
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
                print(f'      {namespace}_{self.element}_new( &self->{self.name} );', file=body)
                print(f'      {namespace}_{self.element}_decode_inner_global( &self->{self.name}, alloc_mem, ctx );', file=body)
            print('    }', file=body)
        else:
            print('    if( o ) {', file=body)
            if self.element in simpletypes:
                print(f'      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, 8UL );', file=body)
                print(f'      self->{self.name}_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( *alloc_mem, ctx );', file=body)
                print(f'      *alloc_mem = (uchar *)*alloc_mem + sizeof({self.element});', file=body)
            else:
                el = f'{namespace}_{self.element}'
                el = el.upper()
                print(f'      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, {el}_ALIGN );', file=body)
                print(f'      self->{self.name}_gaddr = fd_wksp_gaddr_fast( ctx->wksp, *alloc_mem );', file=body)
                print(f'      {namespace}_{self.element}_new( *alloc_mem );', file=body)
                print(f'      *alloc_mem = (uchar *)*alloc_mem + {el}_FOOTPRINT;', file=body)
                print(f'      {namespace}_{self.element}_decode_inner_global( fd_wksp_laddr_fast( ctx->wksp, self->{self.name}_gaddr ), alloc_mem, ctx );', file=body)
            print('    } else {', file=body)
            print(f'      self->{self.name}_gaddr = 0UL;', file=body)
            print('    }', file=body)
        print('  }', file=body)

    def emitGlobalLocalConvert(self):
        if self.flat:
            print(f'  self->{self.name} = mem->{self.name};', file=body)
            print(f'  self->has_{self.name} = mem->has_{self.name};', file=body)
        else:
            print(f'  self->{self.name} = fd_wksp_laddr_fast( ctx->wksp, mem->{self.name}_gaddr );', file=body)

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
            print(f'  if( NULL !=  self->{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    size += sizeof({self.element});', file=body)
            else:
                print(f'    size += {namespace}_{self.element}_size( self->{self.name} );', file=body)
            print('  }', file=body)

    emitWalkMap = {
        "bool" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_BOOL, "char", level );', file=body),
        "char" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR, "char", level );', file=body),
        "double" :    lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE, "double", level );', file=body),
        "long" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_SLONG, "long", level );', file=body),
        "uint" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT, "uint", level );', file=body),
        "uint128" :   lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level );', file=body),
        "uchar" :     lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );', file=body),
        "uchar[32]" : lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level );', file=body),
        "uchar[128]" :lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH1024, "uchar[128]", level );', file=body),
        "uchar[2048]":lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH16384, "uchar[2048]", level );', file=body),
        "ulong" :     lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_ULONG, "ulong", level );', file=body),
        "ushort" :    lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_USHORT, "ushort", level );', file=body),
    }

    def emitWalk(self, inner):
        if self.flat:
            print(f'  if( !self->has_{self.name} ) {{', file=body)
            print(f'    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_NULL, "{self.element}", level );', file=body)
            print( '  } else {', file=body)
            if self.element in OptionMember.emitWalkMap:
                OptionMember.emitWalkMap[self.element](self.name, '&')
            else:
                print(f'    {namespace}_{self.element}_walk( w, &self->{self.name}, fun, "{self.name}", level );', file=body)
            print( '  }', file=body)
        else:
            print(f'  if( !self->{self.name} ) {{', file=body)
            print(f'    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_NULL, "{self.element}", level );', file=body)
            print( '  } else {', file=body)
            if self.element in OptionMember.emitWalkMap:
                OptionMember.emitWalkMap[self.element](self.name, '')
            else:
                print(f'    {namespace}_{self.element}_walk( w, self->{self.name}, fun, "{self.name}", level );', file=body)
            print( '  }', file=body)

class ArrayMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.length = int(json["length"])

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
      else:
          print(f'  {namespace}_{self.element}_t {self.name}[{self.length}];', file=header)

    def emitNew(self):
        length = self.length
        if self.element in simpletypes:
            pass
        else:
            print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
            print(f'    {namespace}_{self.element}_new( self->{self.name} + i );', file=body)

    def emitDestroy(self):
        length = self.length

        if self.element in simpletypes:
            pass
        else:
            print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
            print(f'    {namespace}_{self.element}_destroy( self->{self.name} + i );', file=body)

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
            print(f'    {namespace}_{self.element}_decode_inner( self->{self.name} + i, alloc_mem, ctx );', file=body)
        print('  }', file=body)

    def emitGlobalLocalConvert(self):
      if self.element in simpletypes:
          print(f'  fd_memcpy( self->{self.name}, mem->{self.name}, {self.length} * sizeof({self.element}) );', file=body)
      else:
          print(f'  for( ulong i=0; i<{self.length}; i++ ) {{', file=body)
          print(f'    {namespace}_{self.element}_convert_global_to_local( &mem->{self.name}[i], &self->{self.name}[i], ctx );', file=body)
          print(f'  }}', file=body)

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

    def emitSize(self, inner):
        length = self.length

        if self.element == "uchar":
            print(f'  size += {length};', file=body)
        elif self.element in simpletypes:
            print(f'  size += {length} * sizeof({self.element});', file=body)
        else:
            print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
            print(f'    size += {namespace}_{self.element}_size( self->{self.name} + i );', file=body)

    def emitWalk(self, inner):
        length = self.length

        if self.element == "uchar":
            print(f'  fun(w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_UCHAR, "{self.element}", level );', file=body),
            return

        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR, "{self.element}[]", level++ );', file=body)
        print(f'  for( ulong i=0; i<{length}; i++ )', file=body)
        if self.element in VectorMember.emitWalkMap:
            body.write("  ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'    {namespace}_{self.element}_walk( w, self->{self.name} + i, fun, "{self.element}", level );', file=body)
        print(f'  fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.element}[]", level-- );', file=body)

memberTypeMap = {
    "static_vector" :    StaticVectorMember,
    "vector" :    VectorMember,
    "string" :    StringMember,
    "deque" :     DequeMember,
    "array" :     ArrayMember,
    "option" :    OptionMember,
    "map" :       MapMember,
    "treap" :     TreapMember
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

    def emitHeader(self):
        pass

    def isFixedSize(self):
        return self.size is not None

    def fixedSize(self):
        return self.size

    def emitPrototypes(self):
        if not self.emitprotos:
            return
        n = self.fullname
        print(f"void {n}_new( {n}_t * self );", file=header)
        print(f"int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
        print(f"void {n}_destroy( {n}_t * self );", file=header)
        print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char * name, uint level );", file=header)
        print(f"ulong {n}_size( {n}_t const * self );", file=header)
        print(f'ulong {n}_footprint( void );', file=header)
        print(f'ulong {n}_align( void );', file=header)
        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'int {n}_convert_global_to_local( void const * global_self, {n}_t * self, fd_bincode_decode_ctx_t * ctx );', file=header)
        print("", file=header)

    def emitImpls(self):
        if not self.emitprotos:
            return
        n = self.fullname

        print(f'void {n}_new( {n}_t * self ) {{ }}', file=body)

        print(f'void {n}_destroy( {n}_t * self ) {{ }}', file=body)

        print(f'ulong {n}_footprint( void ) {{ return sizeof({n}_t); }}', file=body)
        print(f'ulong {n}_align( void ) {{ return alignof({n}_t); }}', file=body)

        print(f'ulong {n}_size( {n}_t const * self ) {{ (void)self; return sizeof({n}_t); }}', file=body)

        print(f'int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        print(f'  return fd_bincode_bytes_encode( (uchar const *)self, sizeof({n}_t), ctx );', file=body)
        print("}", file=body)

        if self.walktype is not None:
            print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level ) {{", file=body)
            print(f'  fun( w, (uchar const *)self, name, {self.walktype}, name, level );', file=body)
            print("}", file=body)

        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print(f'  *total_sz += sizeof({n}_t);', file=body)
        print(f'  void const * start_data = ctx->data;', file=body)
        print(f'  int err = {n}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'  if( ctx->data>ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
        print(f'  ctx->data = start_data;', file=body)
        print(f'  return err;', file=body)
        print(f'}}', file=body)

        print(f'int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print(f'  if( ctx->data>=ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
        print(f'  return fd_bincode_bytes_decode_footprint( sizeof({n}_t), ctx );', file=body)
        print(f'}}', file=body)

        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  fd_bincode_bytes_decode_unsafe( mem, sizeof({n}_t), ctx );', file=body)
        print(f'  return mem;', file=body)
        print(f'}}', file=body)

        print(f'void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  fd_bincode_bytes_decode_unsafe( struct_mem, sizeof({n}_t), ctx );', file=body)
        print(f'  return;', file=body)
        print(f'}}', file=body)

        print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  fd_bincode_bytes_decode_unsafe( mem, sizeof({n}_t), ctx );', file=body)
        print(f'  return mem;', file=body)
        print(f'}}', file=body)

        print(f'void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  fd_bincode_bytes_decode_unsafe( struct_mem, sizeof({n}_t), ctx );', file=body)
        print(f'  return;', file=body)
        print(f'}}', file=body)

        print(f'int {n}_convert_global_to_local( void const * global_self, {n}_t * self, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  fd_memcpy( self, global_self, sizeof({n}_t) );', file=body)
        print(f'  return FD_BINCODE_SUCCESS;', file=body)
        print(f'}}', file=body)

        print("", file=body)

    def emitPostamble(self):
        pass


class StructType(TypeNode):
    def __init__(self, json):
        super().__init__(json)
        self.fullname = f'{namespace}_{json["name"]}'
        self.fields = []
        index = 0
        for f in json["fields"]:
            if not (bool(f["removed"]) if "removed" in f else False):
                m = parseMember(self.fullname, f)
                self.fields.append(m)
                m.arch_index = (int(f["tag"]) if "tag" in f else index)
            index = index + 1
        self.comment = (json["comment"] if "comment" in json else None)
        self.nomethods = ("attribute" in json)
        self.encoders = (json["encoders"] if "encoders" in json else None)
        if "alignment" in json:
            self.attribute = f'__attribute__((aligned({json["alignment"]}UL))) '
            self.alignment = json["alignment"]
        elif "attribute" in json:
            self.attribute = f'__attribute__{json["attribute"]} '
            self.alignment = 8
        else:
            self.attribute = f'__attribute__((aligned(8UL))) '
            self.alignment = 8

    def isFixedSize(self):
        for f in self.fields:
            if not f.isFixedSize():
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

    def emitHeader(self):
        for f in self.fields:
            f.emitPreamble()

        if self.comment is not None:
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

        print(f"#define {n.upper()}_FOOTPRINT sizeof({n}_t)", file=header)
        print(f"#define {n.upper()}_ALIGN ({self.alignment}UL)", file=header)
        print("", file=header)

        # Global type
        print(f'struct {self.attribute}{n}_global {{', file=header)
        for f in self.fields:
            f.emitMemberGlobal()
        print("};", file=header)
        print(f'typedef struct {n}_global {n}_global_t;', file=header)

        print(f"#define {n.upper()}_GLOBAL_FOOTPRINT sizeof({n}_global_t)", file=header)
        print(f"#define {n.upper()}_GLOBAL_ALIGN ({self.alignment}UL)", file=header)
        print("", file=header)

    def emitPrototypes(self):
        if self.nomethods:
            return
        n = self.fullname
        print(f"void {n}_new( {n}_t * self );", file=header)
        print(f"int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
        print(f"void {n}_destroy( {n}_t * self );", file=header)
        print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level );", file=header)
        print(f"ulong {n}_size( {n}_t const * self );", file=header)
        print(f'ulong {n}_footprint( void );', file=header)
        print(f'ulong {n}_align( void );', file=header)
        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'int {n}_convert_global_to_local( void const * global_self, {n}_t * self, fd_bincode_decode_ctx_t * ctx );', file=header)
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
        if self.nomethods:
            return
        n = self.fullname

        if self.encoders is not False:
            self.emitEncodes()

        if self.encoders is not False:
            print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
            print(f'  *total_sz += sizeof({n}_t);', file=body)
            print(f'  void const * start_data = ctx->data;', file=body)
            print(f'  int err = {n}_decode_footprint_inner( ctx, total_sz );', file=body)
            print(f'  if( ctx->data>ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
            print(f'  ctx->data = start_data;', file=body)
            print(f'  return err;', file=body)
            print(f'}}', file=body)

            print(f'int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
            print(f'  if( ctx->data>=ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
            print(f'  int err = 0;', file=body)
            for f in self.fields:
                if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                    print('  if( ctx->data == ctx->dataend ) return FD_BINCODE_SUCCESS;', file=body)
                f.emitDecodeFootprint()
            print(f'  return 0;', file=body)
            print(f'}}', file=body)

            print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_t * self = ({n}_t *)mem;', file=body)
            print(f'  {n}_new( self );', file=body)
            print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_t);', file=body)
            print(f'  void * * alloc_mem = &alloc_region;', file=body)
            print(f'  {n}_decode_inner( mem, alloc_mem, ctx );', file=body)
            print(f'  return self;', file=body)
            print(f'}}', file=body)

            print(f'void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_t * self = ({n}_t *)struct_mem;', file=body)
            for f in self.fields:
                if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                    print('  if( ctx->data == ctx->dataend ) return;', file=body)
                f.emitDecodeInner()
            print(f'}}', file=body)

            print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_global_t * self = ({n}_global_t *)mem;', file=body)
            print(f'  {n}_new( ({n}_t *)self );', file=body)
            print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_global_t);', file=body)
            print(f'  void * * alloc_mem = &alloc_region;', file=body)
            print(f'  {n}_decode_inner_global( mem, alloc_mem, ctx );', file=body)
            print(f'  return self;', file=body)
            print(f'}}', file=body)

            print(f'void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
            print(f'  {n}_global_t * self = ({n}_global_t *)struct_mem;', file=body)
            for f in self.fields:
                if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                    print('  if( ctx->data == ctx->dataend ) return;', file=body)
                f.emitDecodeInnerGlobal()
            print(f'}}', file=body)

        print(f'int {n}_convert_global_to_local( void const * global_self, {n}_t * self, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  int err = 0;', file=body)
        print(f'  {n}_global_t const * mem = ({n}_global_t const *)global_self;', file=body)
        for f in self.fields:
            f.emitGlobalLocalConvert()
        print(f'  return FD_BINCODE_SUCCESS;', file=body)
        print(f'}}', file=body)

        print(f'void {n}_new({n}_t * self) {{', file=body)
        print(f'  fd_memset( self, 0, sizeof({n}_t) );', file=body)
        for f in self.fields:
            f.emitNew()
        print("}", file=body)

        print(f'void {n}_destroy( {n}_t * self ) {{', file=body)
        for f in self.fields:
            f.emitDestroy()
        print("}", file=body)
        print("", file=body)

        print(f'ulong {n}_footprint( void ){{ return {n.upper()}_FOOTPRINT; }}', file=body)
        print(f'ulong {n}_align( void ){{ return {n.upper()}_ALIGN; }}', file=body)
        print("", file=body)

        print(f'void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level ) {{', file=body)
        print(f'  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "{n}", level++ );', file=body)
        for f in self.fields:
            f.emitWalk('')
        print(f'  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "{n}", level-- );', file=body)
        print("}", file=body)

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


class EnumType:
    def __init__(self, json):
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
        elif "attribute" in json:
            self.attribute = f'__attribute__{json["attribute"]} '
            self.alignment = 8
        else:
            self.attribute = ''
            self.alignment = 8
        self.compact = (json["compact"] if "compact" in json else False)

        # Current supported repr types for enum are uint and ulong
        self.repr = (json["repr"] if "repr" in json else "uint")
        self.repr_codec_stem = "uint32"
        self.repr_max_val = "UINT_MAX"

        if self.repr == "ulong":
            self.repr_codec_stem = "uint64"
            self.repr_max_val = "ULONG_MAX"

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
        print(f'  {n}_inner_t inner;', file=header)
        print("};", file=header)
        print(f"typedef struct {n} {n}_t;", file=header)
        print(f"#define {n.upper()}_FOOTPRINT sizeof({n}_t)", file=header)
        print(f"#define {n.upper()}_ALIGN ({self.alignment}UL)", file=header)

        print(f"struct {self.attribute}{n}_global {{", file=header)
        print(f'  {self.repr} discriminant;', file=header)
        print(f'  {n}_inner_global_t inner;', file=header)
        print("};", file=header)
        print(f"typedef struct {n}_global {n}_global_t;", file=header)

        print(f"#define {n.upper()}_GLOBAL_FOOTPRINT sizeof({n}_global_t)", file=header)
        print(f"#define {n.upper()}_GLOBAL_ALIGN ({self.alignment}UL)", file=header)
        print("", file=header)

    def emitPrototypes(self):
        n = self.fullname
        print(f"void {n}_new_disc( {n}_t * self, {self.repr} discriminant );", file=header)
        print(f"void {n}_new( {n}_t * self );", file=header)
        print(f"int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx );", file=header)
        print(f"void {n}_destroy( {n}_t * self );", file=header)
        print(f"void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level );", file=header)
        print(f"ulong {n}_size( {n}_t const * self );", file=header)
        print(f'ulong {n}_footprint( void );', file=header)
        print(f'ulong {n}_align( void );', file=header)
        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );', file=header)
        print(f'void * {n}_decode( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );', file=header)
        print(f'int {n}_convert_global_to_local( void const * global_self, {n}_t * self, fd_bincode_decode_ctx_t * ctx );', file=header)
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
        global indent

        n = self.fullname
        indent = '  '

        for i, v in enumerate(self.variants):
            name = (v if isinstance(v, str) else v.name)
            print(f'FD_FN_PURE uchar {n}_is_{name}({n}_t const * self) {{', file=body)
            print(f'  return self->discriminant == {i};', file=body)
            print("}", file=body)

        print(f'void {n}_inner_new( {n}_inner_t * self, {self.repr} discriminant );', file=body)

        print(f'int {n}_inner_decode_footprint( {self.repr} discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print('  int err;', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitDecodeFootprint()
            print('    return FD_BINCODE_SUCCESS;', file=body)
            print('  }', file=body)
        print('  default: return FD_BINCODE_ERR_ENCODING;', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'int {n}_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
        print(f'  *total_sz += sizeof({n}_t);', file=body)
        print(f'  void const * start_data = ctx->data;', file=body)
        print(f'  int err =  {n}_decode_footprint_inner( ctx, total_sz );', file=body)
        print(f'  if( ctx->data>ctx->dataend ) {{ return FD_BINCODE_ERR_OVERFLOW; }};', file=body)
        print(f'  ctx->data = start_data;', file=body)
        print(f'  return err;', file=body)
        print("}", file=body)

        print(f'int {n}_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {{', file=body)
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

        print(f'void {n}_inner_decode_inner( {n}_inner_t * self, void * * alloc_mem, {self.repr} discriminant, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitDecodeInner()
            print('    break;', file=body)
            print('  }', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'void {n}_inner_decode_inner_global( {n}_inner_global_t * self, void * * alloc_mem, {self.repr} discriminant, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitDecodeInnerGlobal()
            print('    break;', file=body)
            print('  }', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'int {n}_convert_global_to_local_inner( {n}_inner_global_t const * mem, {n}_inner_t * self, {self.repr} discriminant, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  int err = 0;', file=body)
        print(f'  switch( discriminant ) {{', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitGlobalLocalConvert()
            print(f'    break;', file=body)
            print(f'  }}', file=body)
        print(f'  }}', file=body)
        print(f'  return FD_BINCODE_SUCCESS;', file=body)
        print(f'}}', file=body)

        print(f'int {n}_convert_global_to_local( void const * global_self, {n}_t * self, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  {n}_global_t const * mem = ({n}_global_t const *)global_self;', file=body)
        print(f'  {self.repr} discriminant = mem->discriminant;', file=body)
        print(f'  self->discriminant = mem->discriminant;', file=body)
        print(f'  int err = {n}_convert_global_to_local_inner( &mem->inner, &self->inner, discriminant, ctx );', file=body)
        print(f'  return FD_BINCODE_SUCCESS;', file=body)
        print(f'}}', file=body)

        print(f'void {n}_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  {n}_t * self = ({n}_t *)struct_mem;', file=body)
        if self.compact:
            print('  ushort tmp = 0;', file=body)
            print('  fd_bincode_compact_u16_decode_unsafe( &tmp, ctx );', file=body)
            print('  self->discriminant = tmp;', file=body)
        else:
            print(f'  fd_bincode_{self.repr_codec_stem}_decode_unsafe( &self->discriminant, ctx );', file=body)
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

        print(f'void * {n}_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  {n}_t * self = ({n}_t *)mem;', file=body)
        print(f'  {n}_new( self );', file=body)
        print(f'  void * alloc_region = (uchar *)mem + sizeof({n}_t);', file=body)
        print(f'  void * * alloc_mem = &alloc_region;', file=body)
        print(f'  {n}_decode_inner_global( mem, alloc_mem, ctx );', file=body)
        print(f'  return self;', file=body)
        print(f'}}', file=body)

        print(f'void {n}_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {{', file=body)
        print(f'  {n}_global_t * self = ({n}_global_t *)struct_mem;', file=body)
        if self.compact:
            print('  ushort tmp = 0;', file=body)
            print('  fd_bincode_compact_u16_decode_unsafe( &tmp, ctx );', file=body)
            print('  self->discriminant = tmp;', file=body)
        else:
            print(f'  fd_bincode_{self.repr_codec_stem}_decode_unsafe( &self->discriminant, ctx );', file=body)
        print(f'  {n}_inner_decode_inner_global( &self->inner, alloc_mem, self->discriminant, ctx );', file=body)
        print(f'}}', file=body)

        print(f'void {n}_inner_new( {n}_inner_t * self, {self.repr} discriminant ) {{', file=body)
        print('  switch( discriminant ) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitNew()
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

        print(f'void {n}_inner_destroy( {n}_inner_t * self, {self.repr} discriminant ) {{', file=body)
        print('  switch( discriminant ) {', file=body)
        for i, v in enumerate(self.variants):
            if not isinstance(v, str):
                print(f'  case {i}: {{', file=body)
                v.emitDestroy()
                print('    break;', file=body)
                print('  }', file=body)
        print('  default: break; // FD_LOG_ERR(( "unhandled type" ));', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'void {n}_destroy( {n}_t * self ) {{', file=body)
        print(f'  {n}_inner_destroy( &self->inner, self->discriminant );', file=body)
        print("}", file=body)
        print("", file=body)

        print(f'ulong {n}_footprint( void ){{ return {n.upper()}_FOOTPRINT; }}', file=body)
        print(f'ulong {n}_align( void ){{ return {n.upper()}_ALIGN; }}', file=body)
        print("", file=body)

        print(f'void {n}_walk( void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level ) {{', file=body)
        print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "{n}", level++);', file=body)
        print('  switch( self->discriminant ) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                print(f'    fun( w, self, "{v.name}", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level );', file=body)
                v.emitWalk("inner.")
            else:
                print(f'    fun( w, self, "{v}", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level );', file=body)
            print('    break;', file=body)
            print('  }', file=body)
        print('  }', file=body)
        print(f'  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "{n}", level-- );', file=body)
        print("}", file=body)

        print(f'ulong {n}_size( {n}_t const * self ) {{', file=body)
        print('  ulong size = 0;', file=body)
        print(f'  size += sizeof({self.repr});', file=body)
        print('  switch (self->discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            if not isinstance(v, str):
                print(f'  case {i}: {{', file=body)
                v.emitSize('inner.')
                print('    break;', file=body)
                print('  }', file=body)
        print('  }', file=body)
        print('  return size;', file=body)
        print("}", file=body)
        print("", file=body)

        print(f'int {n}_inner_encode( {n}_inner_t const * self, {self.repr} discriminant, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        first = True
        for i, v in enumerate(self.variants):
            if not isinstance(v, str):
                if first:
                    print('  int err;', file=body)
                    print('  switch (discriminant) {', file=body)
                    first = False
                print(f'  case {i}: {{', file=body)
                v.emitEncode()
                print('    break;', file=body)
                print('  }', file=body)
        if not first:
            print('  }', file=body)
        print('  return FD_BINCODE_SUCCESS;', file=body)
        print("}", file=body)

        print(f'int {n}_encode( {n}_t const * self, fd_bincode_encode_ctx_t * ctx ) {{', file=body)
        print(f'  int err = fd_bincode_{self.repr_codec_stem}_encode( self->discriminant, ctx );', file=body)
        print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'  return {n}_inner_encode( &self->inner, self->discriminant, ctx );', file=body)
        print("}", file=body)
        print("", file=body)

        indent = ''

    def emitPostamble(self):
        for v in self.variants:
            if not isinstance(v, str):
                v.emitPostamble()

def main():
    alltypes = []
    for entry in entries:
        if entry['type'] == 'opaque':
            alltypes.append(OpaqueType(entry))
        if entry['type'] == 'struct':
            alltypes.append(StructType(entry))
        if entry['type'] == 'enum':
            alltypes.append(EnumType(entry))

    nametypes = {}
    for t in alltypes:
        if hasattr(t, 'fullname') and not (hasattr(t, 'nomethods') and t.nomethods):
            nametypes[t.fullname] = t

    global fixedsizetypes
    global fuzzytypes
    for typeinfo in alltypes:
        if typeinfo.isFixedSize():
            fixedsizetypes[typeinfo.name] = typeinfo.fixedSize()
        if typeinfo.isFuzzy():
            fuzzytypes.add(typeinfo.name)
    for t in alltypes:
        t.emitHeader()

    print("", file=header)
    print("FD_PROTOTYPES_BEGIN", file=header)
    print("", file=header)

    for t in alltypes:
        t.emitPrototypes()

    print("FD_PROTOTYPES_END", file=header)
    print("", file=header)
    print("#endif // HEADER_" + json_object["name"].upper(), file=header)

    for t in alltypes:
        t.emitImpls()

    for t in alltypes:
        t.emitPostamble()

    type_name_count = len(nametypes)
    print(f'#define FD_TYPE_NAME_COUNT {type_name_count}', file=names)
    print("static char const * fd_type_names[FD_TYPE_NAME_COUNT] = {", file=names)
    for key,val in nametypes.items():
        print(f' \"{key}\",', file=names)
    print("};", file=names)

if __name__ == "__main__":
    main()
