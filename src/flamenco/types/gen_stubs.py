# This stub generator is horrible...  the resulting code is horrible...  please... rewrite
# It must die.

import json
import sys


with open('fd_types.json', 'r') as json_file:
    json_object = json.load(json_file)

header = open(sys.argv[1], "w")
body = open(sys.argv[2], "w")

namespace = json_object["namespace"]
entries = json_object["entries"]
defined = set()
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=header)
print("// This is an auto-generated file. To add entries, edit fd_types.json", file=body)
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

class VectorMember:
    def __init__(self, namespace, json):
        self.namespace = namespace
        self.name = json["name"]
        self.element = json["element"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")


    def emitMember(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=header)
        else:
            print(f'  ulong {self.name}_len;', file=header)
            
        if self.element == "uchar":
            print(f'  {self.element}* {self.name};', file=header)
        elif self.element == "ulong":
            print(f'  {self.element}* {self.name};', file=header)
        elif self.element == "uint":
            print(f'  {self.element}* {self.name};', file=header)
        else:
            print(f'  {self.namespace}_{self.element}_t* {self.name};', file=header)
        
    def emitNew(self):
        pass

    def emitDestroy(self):
        print(f'  if (NULL != self->{self.name}) {{', file=body)
        if self.element == "uchar":
            pass
        elif self.element == "ulong":
            pass
        elif self.element == "uint":
            pass
        else:
            print(f'    for (ulong i = 0; i < self->{self.name}_len; ++i)', file=body)
            print(f'      {self.namespace}_{self.element}_destroy(self->{self.name} + i, ctx);', file=body)
        print(f'    fd_valloc_free( ctx->valloc, self->{self.name} );', file=body)
        print(f'    self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitDecode(self):
        if self.compact:
            print(f'  err = fd_bincode_compact_u16_decode(&self->{self.name}_len, ctx);', file=body)
        else:
            print(f'  err = fd_bincode_uint64_decode(&self->{self.name}_len, ctx);', file=body)
        print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  if (self->{self.name}_len != 0) {{', file=body)
        el = f'{self.namespace}_{self.element}'
        el = el.upper()
    
        if self.element == "uchar":
            print(f'    self->{self.name} = fd_valloc_malloc( ctx->valloc, 8UL, self->{self.name}_len );', file=body)
            print(f'    err = fd_bincode_bytes_decode(self->{self.name}, self->{self.name}_len, ctx);', file=body)
            print(f'    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
    
        else:
            if self.element == "ulong":
                print(f'    self->{self.name} = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ulong)*self->{self.name}_len );', file=body)
            elif self.element == "uint":
                print(f'    self->{self.name} = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(uint)*self->{self.name}_len );', file=body)
            elif self.element == "ushort":
                print(f'    self->{self.name} = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ushort)*self->{self.name}_len );', file=body)
            else:
                print(f'    self->{self.name} = ({self.namespace}_{self.element}_t *)fd_valloc_malloc( ctx->valloc, {el}_ALIGN, {el}_FOOTPRINT*self->{self.name}_len);', file=body)
    
            print(f'    for( ulong i = 0; i < self->{self.name}_len; ++i) {{', file=body)
    
            if self.element == "ulong":
                print(f'      err = fd_bincode_uint64_decode(self->{self.name} + i, ctx);', file=body)
            elif self.element == "uint":
                print(f'      err = fd_bincode_uint32_decode(self->{self.name} + i, ctx);', file=body)
            else:
                print(f'      {self.namespace}_{self.element}_new(self->{self.name} + i);', file=body)
                print(f'    }}', file=body)
                print(f'    for( ulong i = 0; i < self->{self.name}_len; ++i ) {{', file=body)
                print(f'      err = {self.namespace}_{self.element}_decode(self->{self.name} + i, ctx);', file=body)
    
            print(f'      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
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
    
            if self.element == "ulong":
                print(f'      err = fd_bincode_uint64_encode(self->{self.name} + i, ctx);', file=body)
            elif self.element == "uint":
                print(f'      err = fd_bincode_uint32_encode(self->{self.name} + i, ctx);', file=body)
            else:
                print(f'      err = {self.namespace}_{self.element}_encode(self->{self.name} + i, ctx);', file=body)
                print('      if ( FD_UNLIKELY(err) ) return err;', file=body)
    
            print('    }', file=body)
    
        print('  }', file=body)

    def emitSize(self):
        print('  size += sizeof(ulong);', file=body)  # FIX COMPACT CASE!!!
        if self.element == "uchar":
            print(f'  size += self->{self.name}_len;', file=body)
        elif self.element == "ulong":
            print(f'  size += self->{self.name}_len * sizeof(ulong);', file=body)
        elif self.element == "uint":
            print(f'  size += self->{self.name}_len * sizeof(uint);', file=body)
        else:
            print(f'  for (ulong i = 0; i < self->{self.name}_len; ++i)', file=body)
            print(f'    size += {self.namespace}_{self.element}_size(self->{self.name} + i);', file=body)

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
    
        if self.element in fields_body_vector_walk:
            body.write("    ")
            VectorMember.emitWalkMap[self.element](self.name)
        else:
            print(f'      {self.namespace}_{self.element}_walk(w, self->{self.name} + i, fun, "{self.element}", level );', file=body)
    
        print(f'    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "{self.name}", level-- );', file=body)
        print('  }', file=body)


class DequeMember:
    def __init__(self, namespace, json):
        self.namespace = namespace
        self.name = json["name"]
        self.element = json["element"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")

    def elem_type(self):
        if self.element == "uchar":
            return "uchar"
        elif self.element == "ulong":
            return "ulong"
        elif self.element == "uint":
            return "uint"
        else:
            return f'{self.namespace}_{self.element}_t'
        
    def prefix(self):
        return f'deq_{self.elem_type()}'

    def emitMember(self):
        print(f'  {self.elem_type()} * {self.name};', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        print(f'  if ( self->{self.name} ) {{', file=body)
        if self.element == "uchar":
            pass
        elif self.element == "ulong":
            pass
        elif self.element == "uint":
            pass
        else:
            print(f'    for ( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );', file=body)
            print(f'      {self.namespace}_{self.element}_destroy(ele, ctx);', file=body)
            print('    }', file=body)
        print(f'    fd_valloc_free( ctx->valloc, {self.prefix()}_delete( {self.prefix()}_leave( self->{self.name}) ) );', file=body)
        print(f'    self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitDecode(self):
        if self.compact:
            print(f'  ushort {self.name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode( &{self.name}_len, ctx );', file=body)
        else:
            print(f'  ulong {self.name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode( &{self.name}_len, ctx );', file=body)
        print(f'  if ( FD_UNLIKELY(err) ) return err;', file=body)
        if "max" in f:
            print(f'  self->{self.name} = {self.prefix()}_alloc( ctx->valloc );', file=body)
        else:
            print(f'  self->{self.name} = {self.prefix()}_alloc( ctx->valloc, {self.name}_len );', file=body)
        print(f'  if ( {self.name}_len > {self.prefix()}_max(self->{self.name}) ) return FD_BINCODE_ERR_SMALL_DEQUE;', file=body)
    
        print(f'  for (ulong i = 0; i < {self.name}_len; ++i) {{', file=body)
        print(f'    {self.elem_type()} * elem = {self.prefix()}_push_tail_nocopy(self->{self.name});', file=body);
    
        if self.element == "ulong":
            print(f'    err = fd_bincode_uint64_decode(elem, ctx);', file=body)
        elif self.element == "uint":
            print(f'    err = fd_bincode_uint32_decode(elem, ctx);', file=body)
        else:
            print(f'    {self.namespace}_{self.element}_new(elem);', file=body)
            print(f'    err = {self.namespace}_{self.element}_decode(elem, ctx);', file=body)
        print(f'    if ( FD_UNLIKELY(err) ) return err;', file=body)
    
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
    
        if self.element == "uchar":
            print('      err = fd_bincode_uint8_encode(ele, ctx);', file=body)
        elif self.element == "ulong":
            print('      err = fd_bincode_uint64_encode(ele, ctx);', file=body)
        elif self.element == "uint":
            print('      err = fd_bincode_uint32_encode(ele, ctx);', file=body)
        else:
            print(f'      err = {self.namespace}_{self.element}_encode(ele, ctx);', file=body)
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
        
    def emitSize(self):
        print(f'  if ( self->{self.name} ) {{', file=body)
    
        if self.compact:
            print(f'    ushort {self.name}_len = (ushort){self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += fd_bincode_compact_u16_size(&{self.name}_len);', file=body)
        else:
            print('    size += sizeof(ulong);', file=body)
    
        if self.element == "uchar":
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += {self.name}_len;', file=body)
        elif self.element == "ulong":
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += {self.name}_len * sizeof(ulong);', file=body)
        elif self.element == "uint":
            print(f'    ulong {self.name}_len = {self.prefix()}_cnt(self->{self.name});', file=body)
            print(f'    size += {self.name}_len * sizeof(uint);', file=body)
        else:
            print(f'    for ( {self.prefix()}_iter_t iter = {self.prefix()}_iter_init( self->{self.name} ); !{self.prefix()}_iter_done( self->{self.name}, iter ); iter = {self.prefix()}_iter_next( self->{self.name}, iter ) ) {{', file=body)
            print(f'      {self.elem_type()} * ele = {self.prefix()}_iter_ele( self->{self.name}, iter );', file=body)
            print(f'      size += {self.namespace}_{self.element}_size(ele);', file=body)
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
            print(f'      {self.namespace}_{self.element}_walk(w, ele, fun, "{self.name}", level );', file=body)
    
        print(f'''    }}
  }}
  fun( w, self->{self.name}, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.name}", level-- );
  /* Done walking deque */
''', file=body)

        
class MapMember:
    def __init__(self, namespace, json):
        self.namespace = namespace
        self.name = json["name"]
        self.element = json["element"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.minalloc = (int(json["minalloc"]) if "minalloc" in json else 0)

    def elem_type(self):
        if self.element == "uchar":
            return "uchar"
        elif self.element == "ulong":
            return "ulong"
        elif self.element == "uint":
            return "uint"
        else:
            return f'{self.namespace}_{self.element}_t'
        
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
        print(f'    {self.namespace}_{self.element}_destroy(&n->elem, ctx);', file=body)
        print('  }', file=body)
        print(f'  fd_valloc_free( ctx->valloc, {mapname}_delete({mapname}_leave( self->{self.name}_pool) ) );', file=body)
        print(f'  self->{self.name}_pool = NULL;', file=body)
        print(f'  self->{self.name}_root = NULL;', file=body)

    def emitDecode(self):
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
    
        if self.minalloc > 0:
            print(f'  self->{self.name}_pool = {mapname}_alloc(ctx->valloc, fd_ulong_max({self.name}_len, {self.minalloc}));', file=body)
        else:
            print(f'  self->{self.name}_pool = {mapname}_alloc(ctx->valloc, {self.name}_len);', file=body)
        print(f'  self->{self.name}_root = NULL;', file=body)
        print(f'  for (ulong i = 0; i < {self.name}_len; ++i) {{', file=body)
        print(f'    {nodename}* node = {mapname}_acquire(self->{self.name}_pool);', file=body);
        print(f'    {self.namespace}_{self.element}_new(&node->elem);', file=body)
        print(f'    err = {self.namespace}_{self.element}_decode(&node->elem, ctx);', file=body)
        print(f'    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'    {mapname}_insert(self->{self.name}_pool, &self->{self.name}_root, node);', file=body)
        print('  }', file=body)

    def emitEncode(self):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"
    
        print(f'  if (self->{self.name}_root) {{', file=body)
        if "modifier" in f and f["modifier"] == "compact":
            print(f'    ushort {self.name}_len = (ushort){mapname}_size(self->{self.name}_pool, self->{self.name}_root);', file=body)
            print(f'    err = fd_bincode_compact_u16_encode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'    ulong {self.name}_len = {mapname}_size(self->{self.name}_pool, self->{self.name}_root);', file=body)
            print(f'    err = fd_bincode_uint64_encode(&{self.name}_len, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
    
        print(f'    for ( {nodename}* n = {mapname}_minimum(self->{self.name}_pool, self->{self.name}_root); n; n = {mapname}_successor(self->{self.name}_pool, n) ) {{', file=body);
        print(f'      err = {self.namespace}_{self.element}_encode(&n->elem, ctx);', file=body)
        print('      if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('    }', file=body)
        print('  } else {', file=body)
        if "modifier" in f and f["modifier"] == "compact":
            print(f'    ushort {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_compact_u16_encode(&{self.name}_len, ctx);', file=body)
        else:
            print(f'    ulong {self.name}_len = 0;', file=body)
            print(f'    err = fd_bincode_uint64_encode(&{self.name}_len, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('  }', file=body)

    def emitSize(self):
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
        print(f'      size += {self.namespace}_{self.element}_size(&n->elem);', file=body)
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
            print(f'      {self.namespace}_{self.element}_walk(w, &n->elem, fun, "{self.name}", level );', file=body)
        print(f'    }}', file=body)
        print(f'  }}', file=body)

    
class TreapMember:
    def __init__(self, namespace, json):
        self.namespace = namespace
        self.name = json["name"]
        self.treap_t = json["treap_t"]
        self.treap_query_t = json["treap_query_t"]
        self.treap_cmp = json["treap_cmp"]
        self.treap_lt = json["treap_lt"]
        self.max = int(json["max"])
        self.compact = ("modifier" in json and json["modifier"] == "compact")

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

    def emitDecode(self):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool_name = name + '_pool'
    
        if self.compact:
            print(f'  ushort {treap_name}_len;', file=body)
            print(f'  err = fd_bincode_compact_u16_decode(&{treap_name}_len, ctx);', file=body)
        else:
            print(f'  ulong {treap_name}_len;', file=body)
            print(f'  err = fd_bincode_uint64_decode(&{treap_name}_len, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  FD_TEST( {treap_name}_len < {name.upper()}_MAX );', file=body)
    
        print(f'  self->pool = {pool_name}_alloc( ctx->valloc );', file=body)
        print(f'  self->treap = {treap_name}_alloc( ctx->valloc );', file=body)
        print(f'  for (ulong i = 0; i < {treap_name}_len; ++i) {{', file=body)
        print(f'    if ( FD_UNLIKELY( err ) ) return err;', file=body)
        print(f'    {treap_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'    err = {treap_t.rstrip("_t")}_decode( ele, ctx );', file=body)
        print(f'    if ( FD_UNLIKELY ( err ) ) return err;', file=body)
        print(f'    {treap_name}_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */', file=body);
        print('  }', file=body)

    def emitEncode(self):
        name = self.name
        treap_name = name + '_treap'
        treap_t = self.treap_t
    
        print(f'  if (self->treap) {{', file=body)
        if "modifier" in f and f["modifier"] == "compact":
            print(f'    ushort {name}_len = {treap_name}_ele_cnt( self->treap );', file=body)
            print(f'    err = fd_bincode_compact_u16_encode( &{name}_len, ctx );', file=body)
        else:
            print(f'    ulong {name}_len = {treap_name}_ele_cnt( self->treap );', file=body)
            print(f'    err = fd_bincode_uint64_encode( &{name}_len, ctx );', file=body)
        print('    if ( FD_UNLIKELY( err ) ) return err;', file=body)
    
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

    def emitSize(self):
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
    def __init__(self, namespace, json):
        self.namespace = namespace
        self.name = json["name"]
        self.element = json["element"]

    def emitMember(self):
        if self.element == "ulong":
            print(f'  {self.element}* {self.name};', file=header)
        elif self.element == "uint":
            print(f'  {self.element}* {self.name};', file=header)
        else:
            print(f'  {self.namespace}_{self.element}_t* {self.name};', file=header)

    def emitNew(self):
        pass

    def emitDestroy(self):
        print(f'  if (NULL != self->{self.name}) {{', file=body)
        if self.element == "ulong":
            pass
        elif self.element == "uint":
            pass
        else:
            print(f'    {self.namespace}_{self.element}_destroy(self->{self.name}, ctx);', file=body)
    
        print(f'    fd_valloc_free( ctx->valloc, self->{self.name});', file=body)
        print(f'    self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitDecode(self):
        print('  {', file=body)
        print('    uchar o;', file=body)
        print('    err = fd_bincode_option_decode( &o, ctx );', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('    if( o ) {', file=body)
        if self.element == "ulong":
            print(f'      self->{self.name} = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );', file=body)
            print(f'      err = fd_bincode_uint64_decode( self->{self.name}, ctx );', file=body)
        elif self.element == "uint":
            print(f'      self->{self.name} = fd_valloc_malloc( ctx->valloc, 8, sizeof(uint) );', file=body)
            print(f'      err = fd_bincode_uint32_decode( self->{self.name}, ctx );', file=body)
        else:
            el = f'{self.namespace}_{self.element}'
            el = el.upper()
            print(f'      self->{self.name} = ({self.namespace}_{self.element}_t*)fd_valloc_malloc( ctx->valloc, {el}_ALIGN, {el}_FOOTPRINT );', file=body)
            print(f'      {self.namespace}_{self.element}_new( self->{self.name} );', file=body)
            print(f'      err = {self.namespace}_{self.element}_decode( self->{self.name}, ctx );', file=body)
        print('      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print('    } else', file=body)
        print(f'      self->{self.name} = NULL;', file=body)
        print('  }', file=body)

    def emitEncode(self):
        print(f'  if (self->{self.name} != NULL) {{', file=body)
        print('    err = fd_bincode_option_encode(1, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
    
        if self.element == "ulong":
            print(f'    err = fd_bincode_uint64_encode(self->{self.name}, ctx);', file=body)
        elif self.element == "uint":
            print(f'    err = fd_bincode_uint32_encode(self->{self.name}, ctx);', file=body)
        else:
            print(f'    err = {self.namespace}_{self.element}_encode(self->{self.name}, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('  } else {', file=body)
        print('    err = fd_bincode_option_encode(0, ctx);', file=body)
        print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
        print('  }', file=body)
    
    def emitSize(self):
        print('  size += sizeof(char);', file=body)
        print(f'  if (NULL !=  self->{self.name}) {{', file=body)
    
        if self.element == "ulong":
            print('    size += sizeof(ulong);', file=body)
        elif self.element == "uint":
            print('    size += sizeof(uint);', file=body)
        else:
            print(f'    size += {self.namespace}_{self.element}_size(self->{self.name});', file=body)
        print('  }', file=body)

    emitWalkMap = {
        "char" :      lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR,   "char",      level );', file=body),
        "char*" :     lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_CSTR,    "char*",     level );', file=body),
        "double" :    lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );', file=body),
        "long" :      lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_SLONG,   "long",      level );', file=body),
        "uint" :      lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT,    "uint",      level );', file=body),
        "uint128" :   lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128",   level );', file=body),
        "uchar" :     lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );', file=body),
        "uchar[32]" : lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level );', file=body),
        "ulong" :     lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );', file=body),
        "ushort" :    lambda n: print(f'  fun( w, self->{n}, "{n}", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );', file=body),
       }
    
    def emitWalk(self, inner):
        print(f'''  if( !self->{self.name} ) {{
    fun( w, NULL, "{self.name}", FD_FLAMENCO_TYPE_NULL, "{self.element}", level );
  }} else {{''', file=body)
        if self.element in OptionMember.emitWalkMap:
            OptionMember.emitWalkMap[self.element](self.name)
        else:
            print(f'  {self.namespace}_{self.element}_walk( w, self->{self.name}, fun, "{self.name}", level );', file=body)
        print(f'  }}', file=body)


class ArrayMember:
    def __init__(self, namespace, json):
        self.namespace = namespace
        self.name = json["name"]
        self.element = json["element"]
        self.length = int(json["length"])

    def emitMember(self):
        if self.element == "uchar":
            print(f'  {self.element} {self.name}[{self.length}];', file=header)
        elif self.element == "ulong":
            print(f'  {self.element} {self.name}[{self.length}];', file=header)
        elif self.element == "uint":
            print(f'  {self.element} {self.name}[{self.length}];', file=header)
        else:
            print(f'  {self.namespace}_{self.element}_t {self.name}[{self.length}];', file=header)

    def emitNew(self):
        length = self.length
    
        if self.element == "uchar":
            pass
        elif self.element == "ulong":
            pass
        elif self.element == "uint":
            pass
        else:
            print(f'  for (ulong i = 0; i < {length}; ++i)', file=body)
            print(f'    {self.namespace}_{self.element}_new(self->{self.name} + i);', file=body)

    def emitDestroy(self):
        length = self.length
    
        if self.element == "uchar":
            pass
        elif self.element == "ulong":
            pass
        elif self.element == "uint":
            pass
        else:
            print(f'  for (ulong i = 0; i < {length}; ++i)', file=body)
            print(f'    {self.namespace}_{self.element}_destroy(self->{self.name} + i, ctx);', file=body)

    def emitDecode(self):
        length = f["length"]
    
        if self.element == "uchar":
            print(f'  err = fd_bincode_bytes_decode( self->{self.name}, {length}, ctx );', file=body)
            print(f'  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
            return
    
        print(f'  for (ulong i = 0; i < {length}; ++i) {{', file=body)
    
        if self.element == "ulong":
            print(f'    err = fd_bincode_uint64_decode(self->{self.name} + i, ctx);', file=body)
        elif self.element == "uint":
            print(f'    err = fd_bincode_uint32_decode(self->{self.name} + i, ctx);', file=body)
        else:
            print(f'    err = {self.namespace}_{self.element}_decode(self->{self.name} + i, ctx);', file=body)
        print('    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
    
        print('  }', file=body)

    def emitEncode(self):
        length = self.length
    
        if self.element == "uchar":
            print(f'  err = fd_bincode_bytes_encode(self->{self.name}, {length}, ctx);', file=body)
            print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
    
        else:
            print(f'  for (ulong i = 0; i < {length}; ++i) {{', file=body)
    
            if self.element == "ulong":
                print(f'    err = fd_bincode_uint64_encode(self->{self.name} + i, ctx);', file=body)
            elif self.element == "uint":
                print(f'    err = fd_bincode_uint32_encode(self->{self.name} + i, ctx);', file=body)
            else:
                print(f'    err = {self.namespace}_{self.element}_encode(self->{self.name} + i, ctx);', file=body)
            print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
    
            print('  }', file=body)

    def emitSize(self):
        length = self.length
    
        if self.element == "uchar":
            print(f'  size += {length};', file=body)
        elif self.element == "ulong":
            print(f'  size += {length} * sizeof(ulong);', file=body)
        elif self.element == "uint":
            print(f'  size += {length} * sizeof(uint);', file=body)
        else:
            print(f'  for (ulong i = 0; i < {length}; ++i)', file=body)
            print(f'    size += {self.namespace}_{self.element}_size(self->{self.name} + i);', file=body)

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
            print(f'    {self.namespace}_{self.element}_walk(w, self->{self.name} + i, fun, "{self.element}", level );', file=body)
        print(f'  fun(w, NULL, "{self.name}", FD_FLAMENCO_TYPE_ARR_END, "{self.element}[]", level--);', file=body)


class PrimitiveMember:
    def __init__(self, namespace, json):
        self.name = json["name"]
        self.type = json["type"]
        self.varint = ("modifier" in json and json["modifier"] == "varint")

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
        "ulong" :     lambda n: print(f'  ulong {n};',     file=header),
        "ushort" :    lambda n: print(f'  ushort {n};',    file=header)
    }
    
    def emitMember(self):
        PrimitiveMember.emitMemberMap[self.type](self.name);

    def string_decode(n, varint):
        print('  ulong slen;', file=body)
        print('  err = fd_bincode_uint64_decode( &slen, ctx );', file=body)
        print('  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f'  self->{n} = fd_valloc_malloc( ctx->valloc, 1, slen + 1 );', file=body)
        print(f'  err = fd_bincode_bytes_decode( (uchar *)self->{n}, slen, ctx );', file=body)
        print('  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
        print(f"  self->{n}[slen] = '\\0';", file=body)
    
    def ulong_decode(n, varint):
        if varint:
            print(f'  err = fd_bincode_varint_decode(&self->{n}, ctx);', file=body),
        else:
            print(f'  err = fd_bincode_uint64_decode(&self->{n}, ctx);', file=body),
        print('  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;', file=body)
    
    emitDecodeMap = {
        "char" :      lambda n, varint: print(f"""  err = fd_bincode_uint8_decode((uchar *) &self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_decode(n, varint),
        "char[32]" :  lambda n, varint: print(f"""  err = fd_bincode_bytes_decode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "char[7]" :   lambda n, varint: print(f"""  err = fd_bincode_bytes_decode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "double" :    lambda n, varint: print(f"""  err = fd_bincode_double_decode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "long" :      lambda n, varint: print(f"""  err = fd_bincode_uint64_decode((ulong *) &self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uint" :      lambda n, varint: print(f"""  err = fd_bincode_uint32_decode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uint128" :   lambda n, varint: print(f"""  err = fd_bincode_uint128_decode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uchar" :     lambda n, varint: print(f"""  err = fd_bincode_uint8_decode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uchar[32]" : lambda n, varint: print(f"""  err = fd_bincode_bytes_decode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_decode(n, varint),
        "ushort" :    lambda n, varint: print(f"""  err = fd_bincode_uint16_decode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body)
    }

    def emitNew(self):
        pass

    def emitDestroy(self):
        if self.type == "char*":
            print(f"""  if (NULL != self->{self.name}) {{\n    fd_valloc_free( ctx->valloc, self->{self.name});\n    self->{self.name} = NULL;\n  }}""", file=body)
        
    def emitDecode(self):
        PrimitiveMember.emitDecodeMap[self.type](self.name, self.varint);

    def string_encode(n, varint):
        print(f'  ulong slen = strlen( (char *) self->{n} );', file=body)
        print('  err = fd_bincode_uint64_encode(&slen, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  err = fd_bincode_bytes_encode((uchar *) self->{n}, slen, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
    
    def ulong_encode(n, varint):
        if self.varint:
            print(f'  err = fd_bincode_varint_encode(self->{n}, ctx);', file=body),
        else:
            print(f'  err = fd_bincode_uint64_encode(&self->{n}, ctx);', file=body),
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
    
    emitEncodeMap = {
        "char" :      lambda n, varint: print(f"""  err = fd_bincode_uint8_encode((uchar *) &self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "char*" :     lambda n, varint: PrimitiveMember.string_encode(n, varint),
        "char[32]" :  lambda n, varint: print(f"""  err = fd_bincode_bytes_encode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "char[7]" :   lambda n, varint: print(f"""  err = fd_bincode_bytes_encode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "double" :    lambda n, varint: print(f"""  err = fd_bincode_double_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "long" :      lambda n, varint: print(f"""  err = fd_bincode_uint64_encode((ulong *) &self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uint" :      lambda n, varint: print(f"""  err = fd_bincode_uint32_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uint128" :   lambda n, varint: print(f"""  err = fd_bincode_uint128_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uchar" :     lambda n, varint: print(f"""  err = fd_bincode_uint8_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "uchar[32]" : lambda n, varint: print(f"""  err = fd_bincode_bytes_encode(&self->{n}[0], sizeof(self->{n}), ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
        "ulong" :     lambda n, varint: PrimitiveMember.ulong_encode(n, varint),
        "ushort" :    lambda n, varint: print(f"""  err = fd_bincode_uint16_encode(&self->{n}, ctx);\n  if ( FD_UNLIKELY(err) ) return err;""", file=body),
    }

    def emitEncode(self):
        PrimitiveMember.emitEncodeMap[self.type](self.name, self.varint);

    def string_size(n):
        print(f'  size += sizeof(ulong) + strlen(self->{self.name});', file=body)
    
    emitSizeMap = {
        "char" :      lambda n: print('  size += sizeof(char);', file=body),
        "char*" :     lambda n: PrimitiveMember.string_size(n),
        "char[32]" :  lambda n: print('  size += sizeof(char) * 32;', file=body),
        "char[7]" :   lambda n: print('  size += sizeof(char) * 7;', file=body),
        "double" :    lambda n: print('  size += sizeof(double);', file=body),
        "long" :      lambda n: print('  size += sizeof(long);', file=body),
        "uint" :      lambda n: print('  size += sizeof(uint);', file=body),
        "uint128" :   lambda n: print('  size += sizeof(uint128);', file=body),
        "uchar" :     lambda n: print('  size += sizeof(char);', file=body),
        "uchar[32]" : lambda n: print('  size += sizeof(char) * 32;', file=body),
        "ulong" :     lambda n: print('  size += sizeof(ulong);', file=body), # FIX varint case!!!!
        "ushort" :    lambda n: print('  size += sizeof(ushort);', file=body)
    }

    def emitSize(self):
        PrimitiveMember.emitSizeMap[self.type](self.name);
    
    emitWalkMap = {
        "char" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SCHAR,   "char",      level );', file=body),
        "char*" :     lambda n, inner: print(f'  fun( w,  self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_CSTR,    "char*",     level );', file=body),
        "double" :    lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );', file=body),
        "long" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_SLONG,   "long",      level );', file=body),
        "uint" :      lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT,    "uint",      level );', file=body),
        "uint128" :   lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UINT128, "uint128",   level );', file=body),
        "uchar" :     lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );', file=body),
        "uchar[32]" : lambda n, inner: print(f'  fun( w,  self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level );', file=body),
        "ulong" :     lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );', file=body),
        "ushort" :    lambda n, inner: print(f'  fun( w, &self->{inner}{n}, "{n}", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );', file=body)
    }

    def emitWalk(self, inner):
        PrimitiveMember.emitWalkMap[self.type](self.name);









# Generate one instance of the fd_deque.c template for each unique element type.
deque_element_types = set()

map_element_types = dict()

for entry in entries:
    # Create the dynamic vector types needed for this entry
    if "fields" in entry:
      for f in entry["fields"]:
          if f["type"] == "deque":
              element_type = deque_elem_type(namespace, f)
              if element_type in deque_element_types:
                  continue

              dp = deque_prefix(namespace, f)
              if "max" in f:
                  print("#define DEQUE_NAME " + dp, file=header)
                  print("#define DEQUE_T " + element_type, file=header)
                  print(f'#define DEQUE_MAX {f["max"]}', file=header)
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
                  if "growth" in f:
                      print(f'  ulong max = len + {f["growth"]};', file=header) # Provide headroom
                  else:
                      print(f'  ulong max = len + len/5 + 10;', file=header) # Provide headroom
                  print(f'  void * mem = fd_valloc_malloc( valloc, {dp}_align(), {dp}_footprint( max ));', file=header)
                  print(f'  return {dp}_join( {dp}_new( mem, max ) );', file=header)
                  print("}", file=header)

              deque_element_types.add(element_type)

          if f["type"] == "map":
            element_type = deque_elem_type(namespace, f)
            if element_type in map_element_types:
                continue

            mapname = element_type + "_map"
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

            map_element_types[element_type] = f["key"]

          if f["type"] == "map_chain" and f['name'] not in defined:
            map_name = f['name'] + '_map'
            map_ele_t = f['map_ele_t']
            map_seed = f['map_seed']
            pool = f['name'] + '_pool'
            pool_max = f["pool_max"]

            print(f"#define POOL_NAME {pool}", file=header)
            print(f"#define POOL_T {map_ele_t}", file=header)
            print(f"#define POOL_MAX {pool_max}", file=header)
            print("#include \"../../util/tmpl/fd_pool.c\"", file=header)

            print(f'static inline {map_ele_t} *', file=header)
            print(f'{pool}_alloc( fd_valloc_t valloc ) {{', file=header)
            print(f'  return {pool}_join( {pool}_new(', file=header)
            print(f'      fd_valloc_malloc( valloc,', file=header)
            print(f'                        {pool}_align(),', file=header)
            print(f'                        {pool}_footprint( POOL_MAX ) ),', file=header)
            print(f'      POOL_MAX ) );', file=header)
            print("}", file=header)

            print(f"#define MAP_NAME {map_name}", file=header)
            print(f"#define MAP_ELE_T {map_ele_t}", file=header)
            if 'map_key' in f:
                print(f"#define MAP_KEY {f['map_key']}", file=header)
            print(f"#define MAP_SEED {map_seed}", file=header)
            print("#include \"../../util/tmpl/fd_map_chain.c\"", file=header)

            print(f'static inline {map_name}_t *', file=header)
            print(f'{map_name}_alloc( fd_valloc_t valloc ) {{', file=header)
            print(f'  ulong chain_cnt = {map_name}_chain_cnt_est( POOL_MAX );', file=header)
            print(f'  return {map_name}_join( {map_name}_new(', file=header)
            print(f'      fd_valloc_malloc( valloc,', file=header)
            print(f'                        {map_name}_align(),', file=header)
            print(f'                        {map_name}_footprint( chain_cnt ) ),', file=header)
            print(f'      chain_cnt,', file=header)
            print(f'      MAP_SEED ) );', file=header)
            print("}", file=header)
            defined.add(map_name)

          if f["type"] == "treap" and f['name'] not in defined:
            name = f['name']
            treap_name = name + '_treap'
            treap_t = f['treap_t']
            treap_query_t = f['treap_query_t']
            treap_cmp = f['treap_cmp']
            treap_lt = f['treap_lt']
            pool = name + '_pool'
            max_name = f"{name.upper()}_MAX"

            print(f"#define {max_name} {f['max']}", file=header)
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
            if 'treap_prio' in f:
                print(f"#define TREAP_PRIO {f['treap_prio']}", file=header)
            print("#include \"../../util/tmpl/fd_treap.c\"", file=header)

            print(f'static inline {treap_name}_t *', file=header)
            print(f'{treap_name}_alloc( fd_valloc_t valloc ) {{', file=header)
            print(f'  return {treap_name}_join( {treap_name}_new(', file=header)
            print(f'      fd_valloc_malloc( valloc,', file=header)
            print(f'                        {treap_name}_align(),', file=header)
            print(f'                        {treap_name}_footprint( {name.upper()}_MAX ) ),', file=header)
            print(f'      {name.upper()}_MAX ) );', file=header)
            print("}", file=header)
            defined.add(treap_name)

    if "comment" in entry and "type" in entry and entry["type"] != "enum":
      print(f'/* {entry["comment"]} */', file=header)

    n = f'{namespace}_{entry["name"]}'

    if "attribute" in entry:
        a = f'__attribute__{entry["attribute"]} '
    else:
        a = ""

    alignment = "8"
    if "alignment" in entry:
        alignment = entry["alignment"]

    if "type" in entry and entry["type"] == "struct":
      if a == "":
          a = "__attribute__((aligned(" + alignment + "UL))) "
      print(f'struct {a}{namespace} {{', file=header)
      for f in entry["fields"]:
          if f["type"] in fields_header:
              fields_header[f["type"]](namespace, f)
          else:
               print(f'  {namespace}_{f["type"]}_t {self.name};', file=header)

      print("};", file=header)
      print(f'typedef struct {namespace} {namespace}_t;', file=header)

    elif "type" in entry and entry["type"] == "enum":
      print(f'union {a}{namespace}_inner {{', file=header)

      empty = True
      for v in entry["variants"]:
          if "type" in v:
            empty = False
            if v["type"] in fields_header:
                fields_header[v["type"]](namespace, v)
            else:
                print(f'  {namespace}_{v["type"]}_t {v["name"]};', file=header)
      if empty:
          print('  uchar nonempty; /* Hack to support enums with no inner structures */ ', file=header)

      print("};", file=header)
      print(f"typedef union {namespace}_inner {namespace}_inner_t;\n", file=header)

      if "comment" in entry:
        print("/* " + entry["comment"] + " */", file=header)

      print(f"struct {a}{namespace} {{", file=header)
      print('  uint discriminant;', file=header)
      print(f'  {namespace}_inner_t inner;', file=header)
      print("};", file=header)
      print(f"typedef struct {namespace} {namespace}_t;", file=header)

    print(f"#define {n.upper()}_FOOTPRINT sizeof({namespace}_t)", file=header)
    print(f"#define {n.upper()}_ALIGN ({alignment}UL)", file=header)
    print("", file=header)

print("", file=header)
print("FD_PROTOTYPES_BEGIN", file=header)
print("", file=header)

for entry in entries:
    if "attribute" in entry:
        continue
    n = namespace + "_" + entry["name"]

    if entry["type"] == "enum":
        print(f"void {namespace}_new_disc({namespace}_t* self, uint discriminant);", file=header)
    print(f"void {namespace}_new({namespace}_t* self);", file=header)
    print(f"int {namespace}_decode({namespace}_t* self, fd_bincode_decode_ctx_t * ctx);", file=header)
    print(f"int {namespace}_encode({namespace}_t const * self, fd_bincode_encode_ctx_t * ctx);", file=header)
    print(f"void {namespace}_destroy({namespace}_t* self, fd_bincode_destroy_ctx_t * ctx);", file=header)
    print(f"void {namespace}_walk(void * w, {namespace}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level);", file=header)
    print(f"ulong {namespace}_size({namespace}_t const * self);", file=header)
    print(f'ulong {namespace}_footprint( void );', file=header)
    print(f'ulong {namespace}_align( void );', file=header)
    print("", file=header)

    if entry["type"] == "enum":
        for i, v in enumerate(entry["variants"]):
            print(f'FD_FN_PURE uchar {namespace}_is_{v["name"]}({self.namespace}_t const * self);', file=header)
            print(f'FD_FN_PURE uchar {self.namespace}_is_{v["name"]}({self.namespace}_t const * self) {{', file=body)
            print(f'  return self->discriminant == {i};', file=body)
            print("}", file=body)
        print("enum {", file=header)

        for i, v in enumerate(entry["variants"]):
            print(f'{self.namespace}_enum_{v["name"]} = {i},', file=header)
        print("}; ", file=header)

    if entry["type"] == "enum":
        print(f'void {self.namespace}_inner_new({self.namespace}_inner_t* self, uint discriminant);', file=body)
        print(f'int {self.namespace}_inner_decode({self.namespace}_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        print(f'  {self.namespace}_inner_new(self, discriminant);', file=body)
        print('  int err;', file=body)
        print('  switch (discriminant) {', file=body)

        for i, v in enumerate(entry["variants"]):
            print(f'  case {i}: {{', file=body)
            if "type" in v:
                if v["type"] in fields_body_decode:
                    body.write("  ")
                    fields_body_decode[v["type"]](namespace, v)
                    print('    return FD_BINCODE_SUCCESS;', file=body)
                else:
                    print(f'    return {namespace}_{v["type"]}_decode(&self->{v["name"]}, ctx);', file=body)
            else:
                print('    return FD_BINCODE_SUCCESS;', file=body)
            print('  }', file=body)

        print('  default: return FD_BINCODE_ERR_ENCODING;', file=body);

        print('  }', file=body)
        print("}", file=body)

        print(f'int {self.namespace}_decode({self.namespace}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
        if "compact" in entry and entry["compact"]:
            print('  ushort tmp = 0;', file=body)
            print('  int err = fd_bincode_compact_u16_decode(&tmp, ctx);', file=body)
            print('  self->discriminant = tmp;', file=body)
        else:
            print('  int err = fd_bincode_uint32_decode(&self->discriminant, ctx);', file=body)

        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  return {namespace}_{entry["name"]}_inner_decode(&self->inner, self->discriminant, ctx);', file=body)
        print("}", file=body)
    else:
      print(f'int {self.namespace}_decode({self.namespace}_t* self, fd_bincode_decode_ctx_t * ctx) {{', file=body)
      print('  int err;', file=body)
      assert "fields" in entry, "no fields in " + entry["name"]
      for f in entry["fields"]:
          if f["type"] in fields_body_decode:
              fields_body_decode[f["type"]](namespace, f)
          else:
              print(f'  err = {namespace}_{f["type"]}_decode(&self->{self.name}, ctx);', file=body)
              print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
      print('  return FD_BINCODE_SUCCESS;', file=body)
      print("}", file=body)

    if entry["type"] == "enum":
      print(f'void {self.namespace}_inner_new({self.namespace}_inner_t* self, uint discriminant) {{', file=body)
      print('  switch (discriminant) {', file=body)
      for i, v in enumerate(entry["variants"]):
        print(f'  case {i}: {{', file=body)
        if "type" in v:
            if v["type"] in fields_body_new:
                fields_body_new[v["type"]](namespace, v)
            else:
                print(f'    {namespace}_{v["type"]}_new(&self->{v["name"]});', file=body)
        print('    break;', file=body)
        print('  }', file=body)
      print('  default: break; // FD_LOG_ERR(( "unhandled type"));', file=body)
      print('  }', file=body)
      print("}", file=body)

      print(f'void {self.namespace}_new_disc({self.namespace}_t* self, uint discriminant) {{', file=body)
      print('  self->discriminant = discriminant;', file=body)
      print(f'  {namespace}_{entry["name"]}_inner_new(&self->inner, self->discriminant);', file=body)
      print("}", file=body)
      print(f'void {self.namespace}_new({self.namespace}_t* self) {{', file=body)
      print(f'  fd_memset(self, 0, sizeof(*self));', file=body)
      print(f'  {namespace}_{entry["name"]}_new_disc(self, UINT_MAX);', file=body) # Invalid by default
      print("}", file=body)
    else:
      print(f'void {self.namespace}_new({self.namespace}_t* self) {{', file=body)
      print(f'  fd_memset(self, 0, sizeof({self.namespace}_t));', file=body)
      for f in entry["fields"]:
          if f["type"] in fields_body_new:
              fields_body_new[f["type"]](namespace, f)
          else:
              print(f'  {namespace}_{f["type"]}_new(&self->{self.name});', file=body)
      print("}", file=body)

    if entry["type"] == "enum":
      print(f'void {self.namespace}_inner_destroy({self.namespace}_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {{', file=body)
      print('  switch (discriminant) {', file=body)
      for i, v in enumerate(entry["variants"]):
        print(f'  case {i}: {{', file=body)
        if "type" in v:
            if v["type"] in fields_body_destroy:
                fields_body_destroy[v["type"]](namespace, v)
            else:
                print(f'    {namespace}_{v["type"]}_destroy(&self->{v["name"]}, ctx);', file=body)
        print('    break;', file=body)
        print('  }', file=body)
      print('  default: break; // FD_LOG_ERR(( "unhandled type" ));', file=body)
      print('  }', file=body)
      print("}", file=body)

      print(f'void {self.namespace}_destroy({self.namespace}_t* self, fd_bincode_destroy_ctx_t * ctx) {{', file=body)
      print(f'  {namespace}_{entry["name"]}_inner_destroy(&self->inner, self->discriminant, ctx);', file=body)
      print("}", file=body)
    else:
      print(f'void {self.namespace}_destroy({self.namespace}_t* self, fd_bincode_destroy_ctx_t * ctx) {{', file=body)
      for f in entry["fields"]:
          if f["type"] in fields_body_destroy:
              fields_body_destroy[f["type"]](namespace, f)
          else:
              print(f'  {namespace}_{f["type"]}_destroy(&self->{self.name}, ctx);', file=body)
      print("}", file=body)
    print("", file=body)

    print(f'ulong {self.namespace}_footprint( void ){{ return {n.upper()}_FOOTPRINT; }}', file=body)
    print(f'ulong {self.namespace}_align( void ){{ return {n.upper()}_ALIGN; }}', file=body)
    print("", file=body)

    print(f'void {self.namespace}_walk(void * w, {self.namespace}_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {{', file=body)
    print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "{self.namespace}", level++);', file=body)

    if entry["type"] == "enum":
        print(f'  // enum {namespace}_{f["type"]}_walk(w, &self->{self.name}, fun, "{self.name}", level);', file=body)

        print('  switch (self->discriminant) {', file=body)
        for i, v in enumerate(entry["variants"]):
          if "type" in v:
            print(f'  case {i}: {{', file=body)
            if v["type"] in fields_body_walk:
                fields_body_walk[v["type"]](namespace, v, "inner.")
            else:
                print(f'    {namespace}_{v["type"]}_walk(w, &self->inner.{v["name"]}, fun, "{v["name"]}", level);', file=body)
            print('    break;', file=body)
            print('  }', file=body)
        print('  }', file=body)
    else:
        for f in entry["fields"]:
            if f["type"] in fields_body_walk:
                if f.get('walk', True):
                    
                    fields_body_walk[f["type"]](namespace, f, "")
            else:
                print(f'  {namespace}_{f["type"]}_walk(w, &self->{self.name}, fun, "{self.name}", level);', file=body)

    print(f'  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "{self.namespace}", level--);', file=body)
    print("}", file=body)

    print(f'ulong {self.namespace}_size({self.namespace}_t const * self) {{', file=body)

    if entry["type"] == "enum":
      print('  ulong size = 0;', file=body)
      print('  size += sizeof(uint);', file=body)
      print('  switch (self->discriminant) {', file=body)
      for i, v in enumerate(entry["variants"]):
          if "type" in v:
            print(f'  case {i}: {{', file=body)
            if v["type"] in fields_body_size:
                body.write("  ")
                fields_body_size[v["type"]](namespace, v)
            else:
                print(f'    size += {namespace}_{v["type"]}_size(&self->inner.{v["name"]});', file=body)
            print('    break;', file=body)
            print('  }', file=body)
      print('  }', file=body)

    else:
      print('  ulong size = 0;', file=body)
      for f in entry["fields"]:
          if f["type"] in fields_body_size:
              fields_body_size[f["type"]](namespace, f)
          else:
              print(f'  size += {namespace}_{f["type"]}_size(&self->{self.name});', file=body)

    print('  return size;', file=body)
    print("}", file=body)
    print("", file=body)
    if entry["type"] == "enum":
        print(f'int {self.namespace}_inner_encode({self.namespace}_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {{', file=body)
        first = True
        for i, v in enumerate(entry["variants"]):
            if "type" in v:
              if first:
                  print('  int err;', file=body)
                  print('  switch (discriminant) {', file=body)
                  first = False
              print(f'  case {i}: {{', file=body)
              if v["type"] in fields_body_encode:
                  body.write("  ")
                  fields_body_encode[v["type"]](namespace, v)
              else:
                  print(f'    err = {namespace}_{v["type"]}_encode(&self->{v["name"]}, ctx);', file=body)
                  print('    if ( FD_UNLIKELY(err) ) return err;', file=body)
              print('    break;', file=body)
              print('  }', file=body)
        if not first:
            print('  }', file=body)
        print('  return FD_BINCODE_SUCCESS;', file=body)
        print("}", file=body)

        print(f'int {self.namespace}_encode({self.namespace}_t const * self, fd_bincode_encode_ctx_t * ctx) {{', file=body)
        print('  int err;', file=body)
        print('  err = fd_bincode_uint32_encode(&self->discriminant, ctx);', file=body)
        print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
        print(f'  return {namespace}_{entry["name"]}_inner_encode(&self->inner, self->discriminant, ctx);', file=body)
        print("}", file=body)
    else:
      print(f'int {self.namespace}_encode({self.namespace}_t const * self, fd_bincode_encode_ctx_t * ctx) {{', file=body)
      print('  int err;', file=body)
      if "fields" in entry:
        for f in entry["fields"]:
            if f["type"] in fields_body_encode:
                fields_body_encode[f["type"]](namespace, f)
            else:
                print(f'  err = {namespace}_{f["type"]}_encode(&self->{self.name}, ctx);', file=body)
                print('  if ( FD_UNLIKELY(err) ) return err;', file=body)
      print('  return FD_BINCODE_SUCCESS;', file=body)
      print("}", file=body)
    print("", file=body)

for (element_type,key) in map_element_types.items():
    mapname = element_type + "_map"
    nodename = element_type + "_mapnode_t"
    print(f'#define REDBLK_T {nodename}', file=body)
    print(f'#define REDBLK_NAME {mapname}', file=body)
    print(f'#define REDBLK_IMPL_STYLE 2', file=body)
    print(f'#include "../../util/tmpl/fd_redblack.c"', file=body)
    print(f'#undef REDBLK_T', file=body)
    print(f'#undef REDBLK_NAME', file=body)
    print(f'long {mapname}_compare({nodename} * left, {nodename} * right) {{', file=body)
    if key == "pubkey" or key == "account" or key == "key":
        print(f'  return memcmp(left->elem.{key}.uc, right->elem.{key}.uc, sizeof(right->elem.{key}));', file=body)
    else:
        print(f'  return (long)(left->elem.{key} - right->elem.{key});', file=body)
    print("}", file=body)

print("FD_PROTOTYPES_END", file=header)
print("", file=header)
print("#endif // HEADER_" + json_object["name"].upper(), file=header)
