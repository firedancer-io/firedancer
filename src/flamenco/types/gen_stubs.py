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

class PrimitiveMember:
    def __init__(self, container, json):
        self.name = json["name"]
        self.type = json["type"]
        self.varint = ("modifier" in json and json["modifier"] == "varint")
        self.decode = ("decode" not in json or json["decode"])
        self.encode = ("encode" not in json or json["encode"])
        self.walk = ("walk" not in json or json["walk"])

    def fixupType(t):
        if t == 'uint64_t':
            return 'ulong'
        elif t == 'int64_t':
            return 'long'
        else:
            return t

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitNew(self):
        pass

    def emitDestroy(self):
        if self.type == "char*":
            print(f"""  if (NULL != self->{self.name}) {{\n    fd_valloc_free( ctx->valloc, self->{self.name});\n    self->{self.name} = NULL;\n  }}""", file=body)

    emitMemberMap = {
        "char" :      lambda n: print(f'  char {n};',      file=header),
        "char*" :     lambda n: print(f'  char* {n};',     file=header),
        "char[32]" :  lambda n: print(f'  char {n}[32];',  file=header),
        "char[7]" :   lambda n: print(f'  char {n}[7];',   file=header),
        "double" :    lambda n: print(f'  double {n};',    file=header),
        "long" :      lambda n: print(f'  long {n};',      file=header),
        "uint" :      lambda n: print(f'  uint {n};',      file=header),
        "uint128" :   lambda n: print(f'  uint128 {n};',   file=header),
        "uchar" :     lambda n: print(f'  uchar {n};',     file=header),
        "uchar[32]" : lambda n: print(f'  uchar {n}[32];', file=header),
        "uchar[128]" :lambda n: print(f'  uchar {n}[128];', file=header),
        "ulong" :     lambda n: print(f'  ulong {n};',     file=header),
        "ushort" :    lambda n: print(f'  ushort {n};',    file=header)
    }

    def emitMember(self):
        PrimitiveMember.emitMemberMap[self.type](self.name);

    def string_decode_preflight(n, varint):
        print(f'{indent}  ulong slen;', file=body)
        print(f'{indent}  err = fd_bincode_uint64_decode( &slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'{indent}  err = fd_bincode_bytes_decode_preflight( slen, ctx );', file=body)
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    def ushort_decode_preflight(n, varint):
        if varint:
            print(f'{indent}  do {{ ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); }} while(0);', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint16_decode_preflight(ctx);', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    def ulong_decode_preflight(n, varint):
        if varint:
            print(f'{indent}  err = fd_bincode_varint_decode_preflight(ctx);', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint64_decode_preflight(ctx);', file=body),
        print(f'{indent}  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

    emitDecodePreflightMap = {
        "char" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_decode_preflight(ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_decode_preflight(n, varint),
        "char[32]" :  lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_preflight(32, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "char[7]" :   lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_preflight(7, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "double" :    lambda n, varint: print(f'{indent}  err = fd_bincode_double_decode_preflight(ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "long" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint64_decode_preflight(ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uint" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint32_decode_preflight(ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uint128" :   lambda n, varint: print(f'{indent}  err = fd_bincode_uint128_decode_preflight(ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uchar" :     lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_decode_preflight(ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uchar[32]" : lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_preflight(32, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uchar[128]" :lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_decode_preflight(128, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_decode_preflight(n, varint),
        "ushort" :    lambda n, varint: PrimitiveMember.ushort_decode_preflight(n, varint),
    }

    def emitDecodePreflight(self):
        if self.decode:
            PrimitiveMember.emitDecodePreflightMap[self.type](self.name, self.varint);

    def string_decode_unsafe(n, varint):
        print(f'{indent}  ulong slen;', file=body)
        print(f'{indent}  fd_bincode_uint64_decode_unsafe( &slen, ctx );', file=body)
        print(f'{indent}  self->{n} = fd_valloc_malloc( ctx->valloc, 1, slen + 1 );', file=body)
        print(f'{indent}  fd_bincode_bytes_decode_unsafe( (uchar *)self->{n}, slen, ctx );', file=body)
        print(f"{indent}  self->{n}[slen] = '\\0';", file=body)

    def ushort_decode_unsafe(n, varint):
        if varint:
            print(f'{indent}  fd_bincode_compact_u16_decode_unsafe(&self->{n}, ctx);', file=body),
        else:
            print(f'{indent}  fd_bincode_uint16_decode_unsafe(&self->{n}, ctx);', file=body),

    def ulong_decode_unsafe(n, varint):
        if varint:
            print(f'{indent}  fd_bincode_varint_decode_unsafe(&self->{n}, ctx);', file=body),
        else:
            print(f'{indent}  fd_bincode_uint64_decode_unsafe(&self->{n}, ctx);', file=body),

    emitDecodeUnsafeMap = {
        "char" :      lambda n, varint: print(f'{indent}  fd_bincode_uint8_decode_unsafe((uchar *) &self->{n}, ctx);', file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_decode_unsafe(n, varint),
        "char[32]" :  lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe(&self->{n}[0], sizeof(self->{n}), ctx);', file=body),
        "char[7]" :   lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe(&self->{n}[0], sizeof(self->{n}), ctx);', file=body),
        "double" :    lambda n, varint: print(f'{indent}  fd_bincode_double_decode_unsafe(&self->{n}, ctx);', file=body),
        "long" :      lambda n, varint: print(f'{indent}  fd_bincode_uint64_decode_unsafe((ulong *) &self->{n}, ctx);', file=body),
        "uint" :      lambda n, varint: print(f'{indent}  fd_bincode_uint32_decode_unsafe(&self->{n}, ctx);', file=body),
        "uint128" :   lambda n, varint: print(f'{indent}  fd_bincode_uint128_decode_unsafe(&self->{n}, ctx);', file=body),
        "uchar" :     lambda n, varint: print(f'{indent}  fd_bincode_uint8_decode_unsafe(&self->{n}, ctx);', file=body),
        "uchar[32]" : lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe(&self->{n}[0], sizeof(self->{n}), ctx);', file=body),
        "uchar[128]" :lambda n, varint: print(f'{indent}  fd_bincode_bytes_decode_unsafe(&self->{n}[0], sizeof(self->{n}), ctx);', file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_decode_unsafe(n, varint),
        "ushort" :    lambda n, varint: PrimitiveMember.ushort_decode_unsafe(n, varint),
    }

    def emitDecodeUnsafe(self):
        if self.decode:
            PrimitiveMember.emitDecodeUnsafeMap[self.type](self.name, self.varint);

    def string_encode(n, varint):
        print(f'{indent}  ulong slen = strlen( (char *) self->{n} );', file=body)
        print(f'{indent}  err = fd_bincode_uint64_encode(&slen, ctx);', file=body)
        print(f'{indent}  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'{indent}  err = fd_bincode_bytes_encode((uchar *) self->{n}, slen, ctx);', file=body)
        print(f'{indent}  if ( FD_UNLIKELY(err) ) return err;', file=body)

    def ushort_encode(n, varint):
        if varint:
            print(f'{indent}  err = fd_bincode_compact_u16_encode(&self->{n}, ctx);', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint16_encode(&self->{n}, ctx);', file=body),
        print(f'{indent}  if ( FD_UNLIKELY(err) ) return err;', file=body)

    def ulong_encode(n, varint):
        if varint:
            print(f'{indent}  err = fd_bincode_varint_encode(self->{n}, ctx);', file=body),
        else:
            print(f'{indent}  err = fd_bincode_uint64_encode(&self->{n}, ctx);', file=body),
        print(f'{indent}  if ( FD_UNLIKELY(err) ) return err;', file=body)

    emitEncodeMap = {
        "char" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_encode((uchar *) &self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_encode(n, varint),
        "char[32]" :  lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "char[7]" :   lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "double" :    lambda n, varint: print(f'{indent}  err = fd_bincode_double_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "long" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint64_encode((ulong *) &self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uint" :      lambda n, varint: print(f'{indent}  err = fd_bincode_uint32_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uint128" :   lambda n, varint: print(f'{indent}  err = fd_bincode_uint128_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uchar" :     lambda n, varint: print(f'{indent}  err = fd_bincode_uint8_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uchar[32]" : lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "uchar[128]" :lambda n, varint: print(f'{indent}  err = fd_bincode_bytes_encode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_encode(n, varint),
        "ushort" :    lambda n, varint: print(f'{indent}  err = fd_bincode_uint16_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;', file=body),
    }

    def emitEncode(self):
        if self.encode:
            PrimitiveMember.emitEncodeMap[self.type](self.name, self.varint);

    emitSizeMap = {
        "char" :      lambda n, varint: print(f'{indent}  size += sizeof(char);', file=body),
        "char*" :     lambda n, varint: print(f'{indent}  size += sizeof(ulong) + strlen(self->{n});', file=body),
        "char[32]" :  lambda n, varint: print(f'{indent}  size += sizeof(char) * 32;', file=body),
        "char[7]" :   lambda n, varint: print(f'{indent}  size += sizeof(char) * 7;', file=body),
        "double" :    lambda n, varint: print(f'{indent}  size += sizeof(double);', file=body),
        "long" :      lambda n, varint: print(f'{indent}  size += sizeof(long);', file=body),
        "uint" :      lambda n, varint: print(f'{indent}  size += sizeof(uint);', file=body),
        "uint128" :   lambda n, varint: print(f'{indent}  size += sizeof(uint128);', file=body),
        "uchar" :     lambda n, varint: print(f'{indent}  size += sizeof(char);', file=body),
        "uchar[32]" : lambda n, varint: print(f'{indent}  size += sizeof(char) * 32;', file=body),
        "uchar[128]" :lambda n, varint: print(f'{indent}  size += sizeof(char) * 128;', file=body),
        "ulong" :     lambda n, varint: print(f'{indent}  size += { ("fd_bincode_varint_size(self->" + n + ");") if varint else "sizeof(ulong);" }', file=body),
        "ushort" :    lambda n, varint: print(f'{indent}  size += { ("fd_bincode_compact_u16_size(&self->" + n + ");") if varint else "sizeof(ushort);" }', file=body),
    }

    def emitSize(self, inner):
        PrimitiveMember.emitSizeMap[self.type](self.name, self.varint);

    emitWalkMap = {
        "char" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR,   "char",      level );', file=body),
        "char*" :     lambda n, inner: print(f'  fun( w,  self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_CSTR,    "char*",     level );', file=body),
        "double" :    lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );', file=body),
        "long" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SLONG,   "long",      level );', file=body),
        "uint" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT,    "uint",      level );', file=body),
        "uint128" :   lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128",   level );', file=body),
        "uchar" :     lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );', file=body),
        "uchar[32]" : lambda n, inner: print(f'  fun( w,  self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level );', file=body),
        "uchar[128]" :lambda n, inner: print(f'  fun( w,  self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH1024, "uchar[128]", level );', file=body),
        "ulong" :     lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );', file=body),
        "ushort" :    lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );', file=body)
    }

    def emitWalk(self, inner):
        if self.walk:
            PrimitiveMember.emitWalkMap[self.type](self.name, inner);


# This is a member which IS a struct, NOT a member OF a struct
class StructMember:
    def __init__(self, container, json):
        self.name = json["name"]
        self.type = json["type"]
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'{indent}  {namespace}_{self.type}_t {self.name};', file=header)

    def emitNew(self):
        print(f'{indent}  {namespace}_{self.type}_new(&self->{self.name});', file=body)

    def emitDestroy(self):
        print(f'{indent}  {namespace}_{self.type}_destroy(&self->{self.name}, ctx);', file=body)

    def emitDecodePreflight(self):
        print(f'{indent}  err = {namespace}_{self.type}_decode_preflight(ctx);', file=body)
        print(f'{indent}  if ( FD_UNLIKELY(err) ) return err;', file=body)

    def emitDecodeUnsafe(self):
        print(f'{indent}  {namespace}_{self.type}_decode_unsafe(&self->{self.name}, ctx);', file=body)

    def emitEncode(self):
        print(f'{indent}  err = {namespace}_{self.type}_encode(&self->{self.name}, ctx);', file=body)
        print(f'{indent}  if ( FD_UNLIKELY(err) ) return err;', file=body)

    def emitSize(self, inner):
        print(f'{indent}  size += {namespace}_{self.type}_size(&self->{inner}{self.name});', file=body)

    def emitWalk(self, inner):
        print(f'{indent}  {namespace}_{self.type}_walk(w, &self->{inner}{self.name}, fun, "{self.name}", level);', file=body)


class VectorMember:
    def __init__(self, container, json):
        self.name = json["name"]
        self.element = json["element"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")

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
            print(f'  {namespace}_{self.element}_t* {self.name};', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        print(f'  if (NULL != self->{self.name}) {{', file=body)
        if self.element in simpletypes:
            pass
        else:
            print(f'    for (ulong i = 0; i < self->{self.name}_len; ++i)', file=body)
            print(f'      {namespace}_{self.element}_destroy(self->{self.name} + i, ctx);', file=body)
        print(f'    fd_valloc_free( ctx->valloc, self->{self.name} );', file=body)
        print(f'    self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitDecodePreflight(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode(&{self.name}_len, ctx);', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  if ({self.name}_len != 0) {{', file=body)
        el = f'{namespace}_{self.element}'
        el = el.upper()

        if self.element == "uchar":
            print(f'    err = fd_bincode_bytes_decode_preflight({self.name}_len, ctx);', file=body)
            print(f'    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)

        else:
            print(f'    for( ulong i = 0; i < {self.name}_len; ++i) {{', file=body)

            if self.element in simpletypes:
                print(f'      err = fd_bincode_{simpletypes[self.element]}_decode_preflight(ctx);', file=body)
            else:
                print(f'      err = {namespace}_{self.element}_decode_preflight(ctx);', file=body)

            print(f'      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
            print('    }', file=body)

        print('  }', file=body)

    def emitDecodeUnsafe(self):
        if self.compact:
            print(f'  fd_bincode_compact_u16_decode_unsafe(&self->{self.name}_len, ctx);', file=body)
        else:
            print(f'  fd_bincode_uint64_decode_unsafe(&self->{self.name}_len, ctx);', file=body)
        print(f'  if (self->{self.name}_len != 0) {{', file=body)
        el = f'{namespace}_{self.element}'
        el = el.upper()

        if self.element == "uchar":
            print(f'    self->{self.name} = fd_valloc_malloc( ctx->valloc, 8UL, self->{self.name}_len );', file=body)
            print(f'    fd_bincode_bytes_decode_unsafe(self->{self.name}, self->{self.name}_len, ctx);', file=body)

        else:
            if self.element in simpletypes:
                print(f'    self->{self.name} = fd_valloc_malloc( ctx->valloc, 8UL, sizeof({self.element})*self->{self.name}_len );', file=body)
            else:
                print(f'    self->{self.name} = ({namespace}_{self.element}_t *)fd_valloc_malloc( ctx->valloc, {el}_ALIGN, {el}_FOOTPRINT*self->{self.name}_len);', file=body)

            print(f'    for( ulong i = 0; i < self->{self.name}_len; ++i) {{', file=body)

            if self.element in simpletypes:
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe(self->{self.name} + i, ctx);', file=body)
            else:
                print(f'      {namespace}_{self.element}_new(self->{self.name} + i);', file=body)
                print(f'      {namespace}_{self.element}_decode_unsafe(self->{self.name} + i, ctx);', file=body)

            print('    }', file=body)

        print('  } else', file=body)
        print(f'    self->{self.name} = NULL;', file=body)

    def emitEncode(self):
        if self.compact:
            print(f'  err = fd_bincode_compact_u16_encode(&self->{self.name}_len, ctx);', file=body)
        else:
            print(f'  err = fd_bincode_uint64_encode(&self->{self.name}_len, ctx);', file=body)
        print(f'  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  if (self->{self.name}_len != 0) {{', file=body)

        if self.element == "uchar":
            print(f'    err = fd_bincode_bytes_encode(self->{self.name}, self->{self.name}_len, ctx);', file=body)
            print(f'    if ( FD_UNLIKELY(err) ) return err;', file=body)

        else:
            print(f'    for (ulong i = 0; i < self->{self.name}_len; ++i) {{', file=body)

            if self.element in simpletypes:
                print(f'      err = fd_bincode_{simpletypes[self.element]}_encode(self->{self.name} + i, ctx);', file=body)
            else:
                print(f'      err = {namespace}_{self.element}_encode(self->{self.name} + i, ctx);', file=body)
                print('      if ( FD_UNLIKELY(err) ) return err;', file=body)

            print('    }', file=body)

        print('  }', file=body)

    def emitSize(self, inner):
        print(f'  do {{', file=body)
        if self.compact:
            print(f'    ushort tmp = (ushort)self->{self.name}_len;', file=body)
            print(f'    size += fd_bincode_compact_u16_size(&tmp);', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        if self.element == "uchar":
            print(f'    size += self->{self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'    size += self->{self.name}_len * sizeof({self.element});', file=body)
        else:
            print(f'    for (ulong i = 0; i < self->{self.name}_len; ++i)', file=body)
            print(f'      size += {namespace}_{self.element}_size(self->{self.name} + i);', file=body)
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
            print(f'  if (self->{self.name}_len != 0) {{', file=body)
            print(f'    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "{self.name}", level++);', file=body)
            print(f'    for (ulong i = 0; i < self->{self.name}_len; ++i)', file=body)

        if self.element in VectorMember.emitWalkMap:
            body.write("    ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'      {namespace}_{self.element}_walk(w, self->{self.name} + i, fun, "{self.element}", level );', file=body)

        print(f'    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "{self.name}", level-- );', file=body)
        print('  }', file=body)


class DequeMember:
    def __init__(self, container, json):
        self.name = json["name"]
        self.element = json["element"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.max = (json["max"] if "max" in json else None)
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
        if self.max is not None:
            print("#define DEQUE_NAME " + dp, file=header)
            print("#define DEQUE_T " + element_type, file=header)
            print(f'#define DEQUE_MAX {self.max}', file=header)
            print('#include "../../util/tmpl/fd_deque.c"', file=header)
            print("#undef DEQUE_NAME", file=header)
            print("#undef DEQUE_T", file=header)
            print("#undef DEQUE_MAX", file=header)
            print(f'static inline {element_type} *', file=header)
            print(f'{dp}_alloc( fd_valloc_t valloc ) {{', file=header)
            print(f'  void * mem = fd_valloc_malloc( valloc, {dp}_align(), {dp}_footprint());', file=header)
            print(f'  return {dp}_join( {dp}_new( mem ) );', file=header)
            print("}", file=header)
        else:
            print("#define DEQUE_NAME " + dp, file=header)
            print("#define DEQUE_T " + element_type, file=header)
            print('#include "../../util/tmpl/fd_deque_dynamic.c"', file=header)
            print("#undef DEQUE_NAME", file=header)
            print("#undef DEQUE_T\n", file=header)
            print(f'static inline {element_type} *', file=header)
            print(f'{dp}_alloc( fd_valloc_t valloc, ulong len ) {{', file=header)
            if self.growth is not None:
                print(f'  ulong max = len + {self.growth};', file=header) # Provide headroom
            else:
                print(f'  ulong max = len + len/5 + 10;', file=header) # Provide headroom
            print(f'  void * mem = fd_valloc_malloc( valloc, {dp}_align(), {dp}_footprint( max ));', file=header)
            print(f'  return {dp}_join( {dp}_new( mem, max ) );', file=header)
            print("}", file=header)

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'  {self.elem_type()} * {self.name};', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        print(f'  if ( self->{self.name} ) {{', file=body)
        if self.element in simpletypes:
            pass
        else:
            print(f'    for ( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );', file=body)
            print(f'      {namespace}_{self.element}_destroy(ele, ctx);', file=body)
            print('    }', file=body)
        print(f'    fd_valloc_free( ctx->valloc, {self.prefix()}_delete( {self.prefix()}_leave( self->{self.name}) ) );', file=body)
        print(f'    self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitDecodePreflight(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'  if ( FD_UNLIKELY(err) ) return err;', file=body)
        if self.max is not None:
            print(f'  if ( {self.name}_len > {self.max} ) return FD_BINCODE_ERR_SMALL_DEQUE;', file=body)

        print(f'  for (ulong i = 0; i < {self.name}_len; ++i) {{', file=body)

        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_decode_preflight(ctx);', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_decode_preflight(ctx);', file=body)
        print(f'    if ( FD_UNLIKELY(err) ) return err;', file=body)

        print('  }', file=body)

    def emitDecodeUnsafe(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe( &{self.name}_len, ctx );', file=body)
        if self.max is not None:
            print(f'  self->{self.name} = {self.prefix()}_alloc( ctx->valloc );', file=body)
        else:
            print(f'  self->{self.name} = {self.prefix()}_alloc( ctx->valloc, {self.name}_len );', file=body)

        print(f'  for (ulong i = 0; i < {self.name}_len; ++i) {{', file=body)
        print(f'    {self.elem_type()} * elem = {self.prefix()}_push_tail_nocopy(self->{self.name});', file=body);

        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe(elem, ctx);', file=body)
        else:
            print(f'    {namespace}_{self.element}_new(elem);', file=body)
            print(f'    {namespace}_{self.element}_decode_unsafe(elem, ctx);', file=body)

        print('  }', file=body)

    def emitEncode(self):
        print(f'  if ( self->{self.name} ) {{', file=body)

        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    err = fd_bincode_compact_u16_encode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    err = fd_bincode_uint64_encode(&{self.name}_len, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)

        print(f'    for ( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
        print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );', file=body)

        if self.element in simpletypes:
            print(f'      err = fd_bincode_{simpletypes[self.element]}_encode(ele, ctx);', file=body)
        else:
            print(f'      err = {namespace}_{self.element}_encode(ele, ctx);', file=body)
            print('      if ( FD_UNLIKELY(err) ) return err;', file=body)

        print('    }', file=body)

        print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'    ulong {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode(&{self.name}_len, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        print(f'  if ( self->{self.name} ) {{', file=body)

        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += fd_bincode_compact_u16_size(&{self.name}_len);', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)

        if self.element == "uchar":
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += {self.name}_len;', file=body)
        elif self.element in simpletypes:
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += {self.name}_len * sizeof({self.element});', file=body)
        else:
            print(f'    for ( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );', file=body)
            print(f'      size += {namespace}_{self.element}_size(ele);', file=body)
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


class MapMember:
    def __init__(self, container, json):
        self.name = json["name"]
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
        print(f"#undef REDBLK_T", file=header)
        print(f"#undef REDBLK_NAME", file=header)
        print(f"struct {nodename} {{", file=header)
        print(f"    {element_type} elem;", file=header)
        print(f"    ulong redblack_parent;", file=header)
        print(f"    ulong redblack_left;", file=header)
        print(f"    ulong redblack_right;", file=header)
        print(f"    int redblack_color;", file=header)
        print("};", file=header)
        print(f'static inline {nodename}_t *', file=header)
        print(f'{mapname}_alloc( fd_valloc_t valloc, ulong len ) {{', file=header)
        print(f'  void * mem = fd_valloc_malloc( valloc, {mapname}_align(), {mapname}_footprint(len));', file=header)
        print(f'  return {mapname}_join({mapname}_new(mem, len));', file=header)
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
        print(f'#undef REDBLK_T', file=body)
        print(f'#undef REDBLK_NAME', file=body)
        print(f'long {mapname}_compare({nodename} * left, {nodename} * right) {{', file=body)
        key = self.key
        if key == "pubkey" or key == "account" or key == "key":
            print(f'  return memcmp(left->elem.{key}.uc, right->elem.{key}.uc, sizeof(right->elem.{key}));', file=body)
        else:
            print(f'  return (long)(left->elem.{key} - right->elem.{key});', file=body)
        print("}", file=body)

    def emitMember(self):
        element_type = self.elem_type()
        print(f'  {element_type}_mapnode_t * {self.name}_pool;', file=header)
        print(f'  {element_type}_mapnode_t * {self.name}_root;', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  for ( {nodename}* n = {mapname}_minimum(self->{self.name}_pool, self->{self.name}_root); n; n = {mapname}_successor(self->{self.name}_pool, n) ) {{', file=body);
        print(f'    {namespace}_{self.element}_destroy(&n->elem, ctx);', file=body)
        print('  }', file=body)
        print(f'  fd_valloc_free( ctx->valloc, {mapname}_delete({mapname}_leave( self->{self.name}_pool) ) );', file=body)
        print(f'  self->{self.name}_pool = NULL;', file=body)
        print(f'  self->{self.name}_root = NULL;', file=body)

    def emitDecodePreflight(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode(&{self.name}_len, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)

        print(f'  for (ulong i = 0; i < {self.name}_len; ++i) {{', file=body)
        print(f'    err = {namespace}_{self.element}_decode_preflight(ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeUnsafe(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe(&{self.name}_len, ctx);', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe(&{self.name}_len, ctx);', file=body)

        if self.minalloc > 0:
            print(f'  self->{self.name}_pool = {mapname}_alloc(ctx->valloc, fd_ulong_max({self.name}_len, {self.minalloc}));', file=body)
        else:
            print(f'  self->{self.name}_pool = {mapname}_alloc(ctx->valloc, {self.name}_len);', file=body)
        print(f'  self->{self.name}_root = NULL;', file=body)
        print(f'  for (ulong i = 0; i < {self.name}_len; ++i) {{', file=body)
        print(f'    {nodename}* node = {mapname}_acquire(self->{self.name}_pool);', file=body);
        print(f'    {namespace}_{self.element}_new(&node->elem);', file=body)
        print(f'    {namespace}_{self.element}_decode_unsafe(&node->elem, ctx);', file=body)
        print(f'    {mapname}_insert(self->{self.name}_pool, &self->{self.name}_root, node);', file=body)
        print('  }', file=body)

    def emitEncode(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  if (self->{self.name}_root) {{', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){mapname}_size(self->{self.name}_pool, self->{self.name}_root);', file=body)
            print(f'    err = fd_bincode_compact_u16_encode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'    ulong {self.name}_len = {mapname}_size(self->{self.name}_pool, self->{self.name}_root);', file=body)
            print(f'    err = fd_bincode_uint64_encode(&{self.name}_len, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)

        print(f'    for ( {nodename}* n = {mapname}_minimum(self->{self.name}_pool, self->{self.name}_root); n; n = {mapname}_successor(self->{self.name}_pool, n) ) {{', file=body);
        print(f'      err = {namespace}_{self.element}_encode(&n->elem, ctx);', file=body)
        print('      if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('    }', file=body)
        print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'    ulong {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode(&{self.name}_len, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  if (self->{self.name}_root) {{', file=body)
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){mapname}_size(self->{self.name}_pool, self->{self.name}_root);', file=body)
            print(f'    size += fd_bincode_compact_u16_size(&{self.name}_len);', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
        print(f'    for ( {nodename}* n = {mapname}_minimum(self->{self.name}_pool, self->{self.name}_root); n; n = {mapname}_successor(self->{self.name}_pool, n) ) {{', file=body);
        print(f'      size += {namespace}_{self.element}_size(&n->elem);', file=body)
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
        print(f'  if (self->{self.name}_root) {{', file=body)
        print(f'    for ( {nodename}* n = {mapname}_minimum(self->{self.name}_pool, self->{self.name}_root); n; n = {mapname}_successor(self->{self.name}_pool, n) ) {{', file=body);

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


class TreapMember:
    def __init__(self, container, json):
        self.name = json["name"]
        self.treap_t = json["treap_t"]
        self.treap_query_t = json["treap_query_t"]
        self.treap_cmp = json["treap_cmp"]
        self.treap_lt = json["treap_lt"]
        self.max = int(json["max"])
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.treap_prio = (json["treap_prio"] if "treap_prio" in json else None)
        self.rev = json.get("rev", False)

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
        max_name = f"{name.upper()}_MAX"
        print(f"#define {max_name} {self.max}", file=header)
        print(f"#define POOL_NAME {pool}", file=header)
        print(f"#define POOL_T {treap_t}", file=header)
        print(f"#define POOL_NEXT parent", file=header)
        print("#include \"../../util/tmpl/fd_pool.c\"", file=header)
        print(f'static inline {treap_t} *', file=header)
        print(f'{pool}_alloc( fd_valloc_t valloc ) {{', file=header)
        print(f'  return {pool}_join( {pool}_new(', file=header)
        print(f'      fd_valloc_malloc( valloc,', file=header)
        print(f'                        {pool}_align(),', file=header)
        print(f'                        {pool}_footprint( {max_name} ) ),', file=header)
        print(f'      {max_name} ) );', file=header)
        print("}", file=header)
        print(f"#define TREAP_NAME {treap_name}", file=header)
        print(f"#define TREAP_T {treap_t}", file=header)
        print(f"#define TREAP_QUERY_T {treap_query_t}", file=header)
        print(f"#define TREAP_CMP(q,e) {treap_cmp}", file=header)
        print(f"#define TREAP_LT(e0,e1) {treap_lt}", file=header)
        if self.treap_prio is not None:
            print(f"#define TREAP_PRIO {self.treap_prio}", file=header)
        print("#include \"../../util/tmpl/fd_treap.c\"", file=header)
        print(f'static inline {treap_name}_t *', file=header)
        print(f'{treap_name}_alloc( fd_valloc_t valloc ) {{', file=header)
        print(f'  return {treap_name}_join( {treap_name}_new(', file=header)
        print(f'      fd_valloc_malloc( valloc,', file=header)
        print(f'                        {treap_name}_align(),', file=header)
        print(f'                        {treap_name}_footprint( {name.upper()}_MAX ) ),', file=header)
        print(f'      {name.upper()}_MAX ) );', file=header)
        print("}", file=header)

    def emitPostamble(self):
        pass

    def emitMember(self):
        print(f'  {self.treap_t} * pool;', file=header)
        print(f'  {self.name}_treap_t * treap;', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool = self.name + '_pool'

        print(f'  if ( !self->treap || !self->pool ) return;', file=body)
        print(f'  for ( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body);
        print(f'          !{treap_name}_fwd_iter_done( iter );', file=body);
        print(f'          iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
        print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)
        print(f'      {treap_t.rstrip("_t")}_destroy( ele, ctx );', file=body)
        print('    }', file=body)
        print(f'  fd_valloc_free( ctx->valloc, {treap_name}_delete({treap_name}_leave( self->treap) ) );', file=body)
        print(f'  fd_valloc_free( ctx->valloc, {pool}_delete({pool}_leave( self->pool) ) );', file=body)
        print(f'  self->pool = NULL;', file=body)
        print(f'  self->treap = NULL;', file=body)

    def emitDecodePreflight(self):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool_name = self.name + '_pool'

        if self.compact:
            print(f'  ushort {treap_name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode(&{treap_name}_len, ctx);', file=body)
        else:
            print(f'  ulong {treap_name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode(&{treap_name}_len, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  if ( {treap_name}_len > {self.name.upper()}_MAX ) return FD_BINCODE_ERR_SMALL_DEQUE;', file=body)

        print(f'  for (ulong i = 0; i < {treap_name}_len; ++i) {{', file=body)
        print(f'    err = {treap_t.rstrip("_t")}_decode_preflight( ctx );', file=body)
        print(f'    if ( FD_UNLIKELY ( err ) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeUnsafe(self):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool_name = self.name + '_pool'

        if self.compact:
            print(f'  ushort {treap_name}_len;', file=body)
            print(f'  fd_bincode_compact_u16_decode_unsafe(&{treap_name}_len, ctx);', file=body)
        else:
            print(f'  ulong {treap_name}_len;', file=body)
            print(f'  fd_bincode_uint64_decode_unsafe(&{treap_name}_len, ctx);', file=body)

        print(f'  self->pool = {pool_name}_alloc( ctx->valloc );', file=body)
        print(f'  self->treap = {treap_name}_alloc( ctx->valloc );', file=body)
        print(f'  for (ulong i = 0; i < {treap_name}_len; ++i) {{', file=body)
        print(f'    {treap_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'    {treap_t.rstrip("_t")}_new( ele );', file=body)
        print(f'    {treap_t.rstrip("_t")}_decode_unsafe( ele, ctx );', file=body)
        print(f'    {treap_name}_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */', file=body);
        print('  }', file=body)

    def emitEncode(self):
        name = self.name
        treap_name = name + '_treap'
        treap_t = self.treap_t

        print(f'  if (self->treap) {{', file=body)
        if self.compact:
            print(f'    ushort {name}_len = {treap_name}_ele_cnt( self->treap );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{name}_len, ctx );', file=body)
        else:
            print(f'    ulong {name}_len = {treap_name}_ele_cnt( self->treap );', file=body)
            print(f'    err = fd_bincode_uint64_encode( &{name}_len, ctx );', file=body)
        print('    if ( FD_UNLIKELY( err ) ) return err;', file=body)

        if self.rev:
            print(f'    for ( {treap_name}_rev_iter_t iter = {treap_name}_rev_iter_init( self->treap, self->pool );', file=body);
            print(f'          !{treap_name}_rev_iter_done( iter );', file=body);
            print(f'          iter = {treap_name}_rev_iter_next( iter, self->pool ) ) {{', file=body);
            print(f'      {treap_t} * ele = {treap_name}_rev_iter_ele( iter, self->pool );', file=body)
            print(f'      err = {treap_t.rstrip("_t")}_encode( ele, ctx );', file=body)
            print('      if ( FD_UNLIKELY(err) ) return err;', file=body)
            print('    }', file=body)
            print('  } else {', file=body)
        else:
            print(f'    for ( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body);
            print(f'          !{treap_name}_fwd_iter_done( iter );', file=body);
            print(f'          iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
            print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)
            print(f'      err = {treap_t.rstrip("_t")}_encode( ele, ctx );', file=body)
            print('      if ( FD_UNLIKELY(err) ) return err;', file=body)
            print('    }', file=body)
            print('  } else {', file=body)
        if self.compact:
            print(f'    ushort {name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode(&{name}_len, ctx);', file=body)
        else:
            print(f'    ulong {name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode(&{name}_len, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
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
        print(f'  if (self->treap) {{', file=body)
        print(f'    for ( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body);
        print(f'          !{treap_name}_fwd_iter_done( iter );', file=body);
        print(f'          iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
        print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)
        print(f'      size += {treap_t.rstrip("_t")}_size( ele );', file=body)
        print('    }', file=body)
        print('  }', file=body)

    def emitWalk(self, inner):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t

        print(f'  if (self->treap) {{', file=body)
        print(f'    for ( {treap_name}_fwd_iter_t iter = {treap_name}_fwd_iter_init( self->treap, self->pool );', file=body);
        print(f'          !{treap_name}_fwd_iter_done( iter );', file=body);
        print(f'          iter = {treap_name}_fwd_iter_next( iter, self->pool ) ) {{', file=body);
        print(f'      {treap_t} * ele = {treap_name}_fwd_iter_ele( iter, self->pool );', file=body)

        if treap_t == "uchar":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );', file=body),
        elif treap_t == "ulong":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level );', file=body),
        elif treap_t == "uint":
            print('      fun(w, ele, "ele", FD_FLAMENCO_TYPE_UINT,  "uint",  level );', file=body),
        else:
            print(f'      {treap_t.rstrip("_t")}_walk(w, ele, fun, "{treap_t}", level );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)


class OptionMember:
    def __init__(self, container, json):
        self.name = json["name"]
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
                print(f'  {namespace}_{self.element}_t* {self.name};', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        if self.flat:
            print(f'  if( self->has_{self.name} ) {{', file=body)
            if self.element not in simpletypes:
                print(f'    {namespace}_{self.element}_destroy( &self->{self.name}, ctx );', file=body)
            print(f'    self->has_{self.name} = 0;', file=body)
            print('  }', file=body)
        else:
            print(f'  if( NULL != self->{self.name} ) {{', file=body)
            if self.element not in simpletypes:
                print(f'    {namespace}_{self.element}_destroy( self->{self.name}, ctx );', file=body)
            print(f'    fd_valloc_free( ctx->valloc, self->{self.name} );', file=body)
            print(f'    self->{self.name} = NULL;', file=body)
            print('  }', file=body)

    def emitDecodePreflight(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    err = fd_bincode_option_decode( &o, ctx );', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('    if( o ) {', file=body)
        if self.element in simpletypes:
            print(f'      err = fd_bincode_{simpletypes[self.element]}_decode_preflight( ctx );', file=body)
        else:
            el = f'{namespace}_{self.element}'
            el = el.upper()
            print(f'      err = {namespace}_{self.element}_decode_preflight( ctx );', file=body)
        print('      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('    }', file=body)
        print('  }', file=body)

    def emitDecodeUnsafe(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    fd_bincode_option_decode_unsafe( &o, ctx );', file=body)
        if self.flat:
            print(f'    self->has_{self.name} = !!o;', file=body)
            print('    if( o ) {', file=body)
            if self.element in simpletypes:
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( &self->{self.name}, ctx );', file=body)
            else:
                el = f'{namespace}_{self.element}'
                el = el.upper()
                print(f'      {namespace}_{self.element}_new( &self->{self.name} );', file=body)
                print(f'      {namespace}_{self.element}_decode_unsafe( &self->{self.name}, ctx );', file=body)
            print('    }', file=body)
        else:
            print('    if( o ) {', file=body)
            if self.element in simpletypes:
                print(f'      self->{self.name} = fd_valloc_malloc( ctx->valloc, 8, sizeof({self.element}) );', file=body)
                print(f'      fd_bincode_{simpletypes[self.element]}_decode_unsafe( self->{self.name}, ctx );', file=body)
            else:
                el = f'{namespace}_{self.element}'
                el = el.upper()
                print(f'      self->{self.name} = ({namespace}_{self.element}_t*)fd_valloc_malloc( ctx->valloc, {el}_ALIGN, {el}_FOOTPRINT );', file=body)
                print(f'      {namespace}_{self.element}_new( self->{self.name} );', file=body)
                print(f'      {namespace}_{self.element}_decode_unsafe( self->{self.name}, ctx );', file=body)
            print('    } else', file=body)
            print(f'      self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitEncode(self):
        if self.flat:
            print(f'  err = fd_bincode_option_encode( self->has_{self.name}, ctx );', file=body)
            print('  if( FD_UNLIKELY( err ) ) return err;', file=body)
            print(f'  if( self->has_{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( &self->{self.name}, ctx );', file=body)
            else:
                print(f'    err = {namespace}_{self.element}_encode( &self->{self.name}, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  }', file=body)
        else:
            print(f'  if( self->{self.name} != NULL ) {{', file=body)
            print('    err = fd_bincode_option_encode( 1, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            if self.element in simpletypes:
                print(f'    err = fd_bincode_{simpletypes[self.element]}_encode( self->{self.name}, ctx );', file=body)
            else:
                print(f'    err = {namespace}_{self.element}_encode( self->{self.name}, ctx );', file=body)
            print('    if( FD_UNLIKELY( err ) ) return err;', file=body)
            print('  } else {', file=body)
            print('    err = fd_bincode_option_encode( 0, ctx );', file=body)
            print('    if ( FD_UNLIKELY( err ) ) return err;', file=body)
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
        "char" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR, "char", level );', file=body),
        "char*" :     lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_CSTR, "char*", level );', file=body),
        "double" :    lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE, "double", level );', file=body),
        "long" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_SLONG, "long", level );', file=body),
        "uint" :      lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT, "uint", level );', file=body),
        "uint128" :   lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128", level );', file=body),
        "uchar" :     lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );', file=body),
        "uchar[32]" : lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level );', file=body),
        "uchar[128]" :lambda n, p: print(f'    fun( w, {p}self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH1024, "uchar[128]", level );', file=body),
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


class ArrayMember:
    def __init__(self, container, json):
        self.name = json["name"]
        self.element = json["element"]
        self.length = int(json["length"])

    def emitPreamble(self):
        pass

    def emitPostamble(self):
        pass

    def emitMember(self):
        if self.element in simpletypes:
            print(f'  {self.element} {self.name}[{self.length}];', file=header)
        else:
            print(f'  {namespace}_{self.element}_t {self.name}[{self.length}];', file=header)

    def emitNew(self):
        length = self.length
        if self.element in simpletypes:
            pass
        else:
            print(f'  for (ulong i = 0; i < {length}; ++i)', file=body)
            print(f'    {namespace}_{self.element}_new(self->{self.name} + i);', file=body)

    def emitDestroy(self):
        length = self.length

        if self.element in simpletypes:
            pass
        else:
            print(f'  for (ulong i = 0; i < {length}; ++i)', file=body)
            print(f'    {namespace}_{self.element}_destroy(self->{self.name} + i, ctx);', file=body)

    def emitDecodePreflight(self):
        length = self.length

        if self.element == "uchar":
            print(f'  err = fd_bincode_bytes_decode_preflight( {length}, ctx );', file=body)
            print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
            return

        print(f'  for (ulong i = 0; i < {length}; ++i) {{', file=body)
        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_decode_preflight(ctx);', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_decode_preflight(ctx);', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('  }', file=body)

    def emitDecodeUnsafe(self):
        length = self.length

        if self.element == "uchar":
            print(f'  fd_bincode_bytes_decode_unsafe( self->{self.name}, {length}, ctx );', file=body)
            return

        print(f'  for (ulong i = 0; i < {length}; ++i) {{', file=body)
        if self.element in simpletypes:
            print(f'    fd_bincode_{simpletypes[self.element]}_decode_unsafe(self->{self.name} + i, ctx);', file=body)
        else:
            print(f'    {namespace}_{self.element}_decode_unsafe(self->{self.name} + i, ctx);', file=body)
        print('  }', file=body)

    def emitEncode(self):
        length = self.length

        if self.element == "uchar":
            print(f'  err = fd_bincode_bytes_encode(self->{self.name}, {length}, ctx);', file=body)
            print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
            return

        print(f'  for (ulong i = 0; i < {length}; ++i) {{', file=body)
        if self.element in simpletypes:
            print(f'    err = fd_bincode_{simpletypes[self.element]}_encode(self->{self.name} + i, ctx);', file=body)
        else:
            print(f'    err = {namespace}_{self.element}_encode(self->{self.name} + i, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self, inner):
        length = self.length

        if self.element == "uchar":
            print(f'  size += {length};', file=body)
        elif self.element in simpletypes:
            print(f'  size += {length} * sizeof({self.element});', file=body)
        else:
            print(f'  for (ulong i = 0; i < {length}; ++i)', file=body)
            print(f'    size += {namespace}_{self.element}_size(self->{self.name} + i);', file=body)

    def emitWalk(self, inner):
        length = self.length

        if self.element == "uchar":
            print(f'fd_bincode_bytes_walk(w, self->{self.name}, {length}, ctx);', file=body)
            return

        print(f'  fun(w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR, "{self.element}[]", level++);', file=body)
        print(f'  for (ulong i = 0; i < {length}; ++i)', file=body)
        if self.element in VectorMember.emitWalkMap:
            body.write("  ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'    {namespace}_{self.element}_walk(w, self->{self.name} + i, fun, "{self.element}", level );', file=body)
        print(f'  fun(w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.element}[]", level--);', file=body)


memberTypeMap = {
    "vector" :    VectorMember,
    "deque" :     DequeMember,
    "array" :     ArrayMember,
    "option" :    OptionMember,
    "map" :       MapMember,
    "treap" :     TreapMember
}

def parseMember(namespace, json):
    type = PrimitiveMember.fixupType(str(json["type"]))
    if type in memberTypeMap:
        c = memberTypeMap[type]
    elif type in PrimitiveMember.emitMemberMap:
        json["type"] = type
        c = PrimitiveMember
    else:
        c = StructMember
    return c(namespace, json)


class OpaqueType:
    def __init__(self, json):
        self.fullname = f'{namespace}_{json["name"]}'
        self.walktype = (json["walktype"] if "walktype" in json else None)

    def emitHeader(self):
        pass

    def emitPrototypes(self):
        n = self.fullname
        print(f"void {n}_new({n}_t* self);", file=header)
        print(f"int {n}_decode({n}_t* self, fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"int {n}_decode_preflight(fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"void {n}_decode_unsafe({n}_t* self, fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"int {n}_encode({n}_t const * self, fd_bincode_encode_ctx_t * ctx);", file=header)
        print(f"void {n}_destroy({n}_t* self, fd_bincode_destroy_ctx_t * ctx);", file=header)
        print(f"void {n}_walk(void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level);", file=header)
        print(f"ulong {n}_size({n}_t const * self);", file=header)
        print(f'ulong {n}_footprint( void );', file=header)
        print(f'ulong {n}_align( void );', file=header)
        print("", file=header)

    def emitImpls(self):
        n = self.fullname

        print(f'int {n}_decode({n}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print(f'  void const * data = ctx->data;', file=body)
        print(f'  int err = {n}_decode_preflight(ctx);', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  ctx->data = data;', file=body)
        print(f'  {n}_new(self);', file=body)
        print(f'  {n}_decode_unsafe(self, ctx);', file=body)
        print(f'  return FD_BINCODE_SUCCESS;', file=body)
        print(f'}}', file=body)

        print(f'int {n}_decode_preflight(fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print(f'  return fd_bincode_bytes_decode_preflight( sizeof({n}_t), ctx );', file=body)
        print("}", file=body)

        print(f'void {n}_decode_unsafe({n}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print(f'  fd_bincode_bytes_decode_unsafe( (uchar*)self, sizeof({n}_t), ctx );', file=body)
        print("}", file=body)

        print(f'void {n}_new({n}_t* self) {{ }}', file=body)

        print(f'void {n}_destroy({n}_t* self, fd_bincode_destroy_ctx_t * ctx) {{ }}', file=body)

        print(f'ulong {n}_footprint( void ){{ return sizeof({n}_t); }}', file=body)
        print(f'ulong {n}_align( void ){{ return alignof({n}_t); }}', file=body)

        print(f'ulong {n}_size({n}_t const * self) {{ (void)self; return sizeof({n}_t); }}', file=body)

        print(f'int {n}_encode({n}_t const * self, fd_bincode_encode_ctx_t * ctx) {{', file=body)
        print(f'  return fd_bincode_bytes_encode( (uchar const *)self, sizeof({n}_t), ctx );', file=body)
        print("}", file=body)

        if self.walktype is not None:
            print(f"void {n}_walk(void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {{", file=body)
            print(f'  fun( w, (uchar const*)self, name, {self.walktype}, name, level );', file=body)
            print("}", file=body)

        print("", file=body)

    def emitPostamble(self):
        pass


class StructType:
    def __init__(self, json):
        self.fullname = f'{namespace}_{json["name"]}'
        self.fields = []
        for f in entry["fields"]:
            self.fields.append(parseMember(self.fullname, f))
        self.comment = (json["comment"] if "comment" in json else None)
        self.nomethods = ("attribute" in json)
        if "alignment" in json:
            self.attribute = f'__attribute__((aligned({json["alignment"]}UL))) '
            self.alignment = json["alignment"]
        elif "attribute" in json:
            self.attribute = f'__attribute__{json["attribute"]} '
            self.alignment = 8
        else:
            self.attribute = f'__attribute__((aligned(8UL))) '
            self.alignment = 8

    def emitHeader(self):
        for f in self.fields:
            f.emitPreamble()

        if self.comment is not None:
            print(f'/* {self.comment} */', file=header)

        n = self.fullname
        print(f'struct {self.attribute}{n} {{', file=header)
        for f in self.fields:
            f.emitMember()
        print("};", file=header)
        print(f'typedef struct {n} {n}_t;', file=header)

        print(f"#define {n.upper()}_FOOTPRINT sizeof({n}_t)", file=header)
        print(f"#define {n.upper()}_ALIGN ({self.alignment}UL)", file=header)
        print("", file=header)

    def emitPrototypes(self):
        if self.nomethods:
            return
        n = self.fullname
        print(f"void {n}_new({n}_t* self);", file=header)
        print(f"int {n}_decode({n}_t* self, fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"int {n}_decode_preflight(fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"void {n}_decode_unsafe({n}_t* self, fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"int {n}_encode({n}_t const * self, fd_bincode_encode_ctx_t * ctx);", file=header)
        print(f"void {n}_destroy({n}_t* self, fd_bincode_destroy_ctx_t * ctx);", file=header)
        print(f"void {n}_walk(void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level);", file=header)
        print(f"ulong {n}_size({n}_t const * self);", file=header)
        print(f'ulong {n}_footprint( void );', file=header)
        print(f'ulong {n}_align( void );', file=header)
        print("", file=header)

    def emitImpls(self):
        if self.nomethods:
            return
        n = self.fullname

        print(f'int {n}_decode({n}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print(f'  void const * data = ctx->data;', file=body)
        print(f'  int err = {n}_decode_preflight(ctx);', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  ctx->data = data;', file=body)
        print(f'  {n}_new(self);', file=body)
        print(f'  {n}_decode_unsafe(self, ctx);', file=body)
        print(f'  return FD_BINCODE_SUCCESS;', file=body)
        print(f'}}', file=body)

        print(f'int {n}_decode_preflight(fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print('  int err;', file=body)
        for f in self.fields:
            if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                print('  if (ctx->data == ctx->dataend) return FD_BINCODE_SUCCESS;', file=body)
            f.emitDecodePreflight()
        print('  return FD_BINCODE_SUCCESS;', file=body)
        print("}", file=body)

        print(f'void {n}_decode_unsafe({n}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        for f in self.fields:
            if hasattr(f, "ignore_underflow") and f.ignore_underflow:
                print('  if (ctx->data == ctx->dataend) return;', file=body)
            f.emitDecodeUnsafe()
        print("}", file=body)

        print(f'void {n}_new({n}_t* self) {{', file=body)
        print(f'  fd_memset(self, 0, sizeof({n}_t));', file=body)
        for f in self.fields:
            f.emitNew()
        print("}", file=body)

        print(f'void {n}_destroy({n}_t* self, fd_bincode_destroy_ctx_t * ctx) {{', file=body)
        for f in self.fields:
            f.emitDestroy()
        print("}", file=body)
        print("", file=body)

        print(f'ulong {n}_footprint( void ){{ return {n.upper()}_FOOTPRINT; }}', file=body)
        print(f'ulong {n}_align( void ){{ return {n.upper()}_ALIGN; }}', file=body)
        print("", file=body)

        print(f'void {n}_walk(void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {{', file=body)
        print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "{n}", level++);', file=body)
        for f in self.fields:
            f.emitWalk('')
        print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "{n}", level--);', file=body)
        print("}", file=body)

        print(f'ulong {n}_size({n}_t const * self) {{', file=body)
        print('  ulong size = 0;', file=body)
        for f in self.fields:
            f.emitSize('')
        print('  return size;', file=body)
        print("}", file=body)
        print("", file=body)

        print(f'int {n}_encode({n}_t const * self, fd_bincode_encode_ctx_t * ctx) {{', file=body)
        print('  int err;', file=body)
        for f in self.fields:
            f.emitEncode()
        print('  return FD_BINCODE_SUCCESS;', file=body)
        print("}", file=body)
        print("", file=body)

    def emitPostamble(self):
        for f in self.fields:
            f.emitPostamble()


class EnumType:
    def __init__(self, json):
        self.fullname = f'{namespace}_{json["name"]}'
        self.variants = []
        for f in entry["variants"]:
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

    def emitHeader(self):
        for v in self.variants:
            if not isinstance(v, str):
                v.emitPreamble()

        n = self.fullname
        print(f'union {self.attribute}{n}_inner {{', file=header)
        empty = True
        for v in self.variants:
            if not isinstance(v, str):
              empty = False
              v.emitMember()
        if empty:
            print('  uchar nonempty; /* Hack to support enums with no inner structures */ ', file=header)
        print("};", file=header)
        print(f"typedef union {n}_inner {n}_inner_t;\n", file=header)

        if self.comment is not None:
            print(f'/* {self.comment} */', file=header)

        print(f"struct {self.attribute}{n} {{", file=header)
        print('  uint discriminant;', file=header)
        print(f'  {n}_inner_t inner;', file=header)
        print("};", file=header)
        print(f"typedef struct {n} {n}_t;", file=header)

        print(f"#define {n.upper()}_FOOTPRINT sizeof({n}_t)", file=header)
        print(f"#define {n.upper()}_ALIGN ({self.alignment}UL)", file=header)
        print("", file=header)

    def emitPrototypes(self):
        n = self.fullname
        print(f"void {n}_new_disc({n}_t* self, uint discriminant);", file=header)
        print(f"void {n}_new({n}_t* self);", file=header)
        print(f"int {n}_decode({n}_t* self, fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"int {n}_decode_preflight(fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"void {n}_decode_unsafe({n}_t* self, fd_bincode_decode_ctx_t * ctx);", file=header)
        print(f"int {n}_encode({n}_t const * self, fd_bincode_encode_ctx_t * ctx);", file=header)
        print(f"void {n}_destroy({n}_t* self, fd_bincode_destroy_ctx_t * ctx);", file=header)
        print(f"void {n}_walk(void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level);", file=header)
        print(f"ulong {n}_size({n}_t const * self);", file=header)
        print(f'ulong {n}_footprint( void );', file=header)
        print(f'ulong {n}_align( void );', file=header)
        print("", file=header)

        for i, v in enumerate(self.variants):
            name = (v if isinstance(v, str) else v.name)
            print(f'FD_FN_PURE uchar {n}_is_{name}({n}_t const * self);', file=header)

        print("enum {", file=header)
        for i, v in enumerate(self.variants):
            name = (v if isinstance(v, str) else v.name)
            print(f'{n}_enum_{name} = {i},', file=header)
        print("}; ", file=header)

    def emitImpls(self):
        global indent

        n = self.fullname
        indent = '  '

        for i, v in enumerate(self.variants):
            name = (v if isinstance(v, str) else v.name)
            print(f'FD_FN_PURE uchar {n}_is_{name}({n}_t const * self) {{', file=body)
            print(f'  return self->discriminant == {i};', file=body)
            print("}", file=body)

        print(f'void {n}_inner_new({n}_inner_t* self, uint discriminant);', file=body)

        print(f'int {n}_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print('  int err;', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitDecodePreflight()
            print('    return FD_BINCODE_SUCCESS;', file=body)
            print('  }', file=body)
        print('  default: return FD_BINCODE_ERR_ENCODING;', file=body);
        print('  }', file=body)
        print("}", file=body)

        print(f'void {n}_inner_decode_unsafe({n}_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitDecodeUnsafe()
            print('    break;', file=body)
            print('  }', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'int {n}_decode({n}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print(f'  void const * data = ctx->data;', file=body)
        print(f'  int err = {n}_decode_preflight(ctx);', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  ctx->data = data;', file=body)
        print(f'  {n}_new(self);', file=body)
        print(f'  {n}_decode_unsafe(self, ctx);', file=body)
        print(f'  return FD_BINCODE_SUCCESS;', file=body)
        print(f'}}', file=body)

        print(f'int {n}_decode_preflight(fd_bincode_decode_ctx_t * ctx) {{', file=body)
        if self.compact:
            print('  ushort discriminant = 0;', file=body)
            print('  int err = fd_bincode_compact_u16_decode(&discriminant, ctx);', file=body)
        else:
            print('  uint discriminant = 0;', file=body)
            print('  int err = fd_bincode_uint32_decode(&discriminant, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  return {n}_inner_decode_preflight(discriminant, ctx);', file=body)
        print("}", file=body)

        print(f'void {n}_decode_unsafe({n}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        if self.compact:
            print('  ushort tmp = 0;', file=body)
            print('  fd_bincode_compact_u16_decode_unsafe(&tmp, ctx);', file=body)
            print('  self->discriminant = tmp;', file=body)
        else:
            print('  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);', file=body)
        print(f'  {n}_inner_decode_unsafe(&self->inner, self->discriminant, ctx);', file=body)
        print("}", file=body)

        print(f'void {n}_inner_new({n}_inner_t* self, uint discriminant) {{', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            print(f'  case {i}: {{', file=body)
            if not isinstance(v, str):
                v.emitNew()
            print('    break;', file=body)
            print('  }', file=body)
        print('  default: break; // FD_LOG_ERR(( "unhandled type"));', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'void {n}_new_disc({n}_t* self, uint discriminant) {{', file=body)
        print('  self->discriminant = discriminant;', file=body)
        print(f'  {n}_inner_new(&self->inner, self->discriminant);', file=body)
        print("}", file=body)

        print(f'void {n}_new({n}_t* self) {{', file=body)
        print(f'  fd_memset(self, 0, sizeof(*self));', file=body)
        print(f'  {n}_new_disc(self, UINT_MAX);', file=body) # Invalid by default
        print("}", file=body)

        print(f'void {n}_inner_destroy({n}_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {{', file=body)
        print('  switch (discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            if not isinstance(v, str):
                print(f'  case {i}: {{', file=body)
                v.emitDestroy()
                print('    break;', file=body)
                print('  }', file=body)
        print('  default: break; // FD_LOG_ERR(( "unhandled type" ));', file=body)
        print('  }', file=body)
        print("}", file=body)

        print(f'void {n}_destroy({n}_t* self, fd_bincode_destroy_ctx_t * ctx) {{', file=body)
        print(f'  {n}_inner_destroy(&self->inner, self->discriminant, ctx);', file=body)
        print("}", file=body)
        print("", file=body)

        print(f'ulong {n}_footprint( void ){{ return {n.upper()}_FOOTPRINT; }}', file=body)
        print(f'ulong {n}_align( void ){{ return {n.upper()}_ALIGN; }}', file=body)
        print("", file=body)

        print(f'void {n}_walk(void * w, {n}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {{', file=body)
        print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "{n}", level++);', file=body)
        print('  switch (self->discriminant) {', file=body)
        for i, v in enumerate(self.variants):
            if not isinstance(v, str):
                print(f'  case {i}: {{', file=body)
                v.emitWalk("inner.")
                print('    break;', file=body)
                print('  }', file=body)
        print('  }', file=body)
        print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "{n}", level--);', file=body)
        print("}", file=body)

        print(f'ulong {n}_size({n}_t const * self) {{', file=body)
        print('  ulong size = 0;', file=body)
        print('  size += sizeof(uint);', file=body)
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

        print(f'int {n}_inner_encode({n}_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {{', file=body)
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

        print(f'int {n}_encode({n}_t const * self, fd_bincode_encode_ctx_t * ctx) {{', file=body)
        print('  int err;', file=body)
        print('  err = fd_bincode_uint32_encode(&self->discriminant, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  return {n}_inner_encode(&self->inner, self->discriminant, ctx);', file=body)
        print("}", file=body)
        print("", file=body)

        indent = ''

    def emitPostamble(self):
        for v in self.variants:
            if not isinstance(v, str):
                v.emitPostamble()

alltypes = []
for entry in entries:
    if entry['type'] == 'opaque':
        alltypes.append(OpaqueType(entry))
    if entry['type'] == 'struct':
        alltypes.append(StructType(entry))
    if entry['type'] == 'enum':
        alltypes.append(EnumType(entry))

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

nametypes = [t for t in alltypes if not (hasattr(t, 'nomethods') and t.nomethods)]
type_name_count = len(nametypes)
print(f'#define FD_TYPE_NAME_COUNT {type_name_count}', file=names)
print("static char const * fd_type_names[FD_TYPE_NAME_COUNT] = {", file=names)
for t in nametypes:
    print(f' \"{t.fullname}\",', file=names)
print("};", file=names)
