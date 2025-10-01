import json
import sys


with open('fd_types.json', 'r') as json_file:
    json_object = json.load(json_file)

body = open(sys.argv[1], "w")

namespace = json_object["namespace"]
entries = json_object["entries"]

print("// This is an auto-generated file. To add entries, edit fd_types.json", file=body)
print("#ifndef HEADER_FUZZ_" + json_object["name"].upper(), file=body)
print("#define HEADER_FUZZ_" + json_object["name"].upper(), file=body)
print("", file=body)

print('#pragma GCC diagnostic ignored "-Wunused-parameter"', file=body)
print('#pragma GCC diagnostic ignored "-Wunused-variable"', file=body)

print('#define SOURCE_fd_src_flamenco_types_fd_types_c', file=body)
print('#include "fd_types.h"', file=body)
print('#include "fd_types_custom.h"', file=body)
print("", file=body)
print('size_t LLVMFuzzerMutate(uchar *data, size_t size, size_t max_size);', file=body)
print("", file=body)

preambletypes = set()
postambletypes = set()

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
    def __init__(self, json, **kwargs):
        if json is not None:
            self.name = json["name"]
        elif 'name' in kwargs:
            self.name = kwargs['name']
        else:
            raise ValueError(f"invalid arguments {kwargs} provided to TypeNode!")

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

    def string_generate(n, varint, indent):
        print(f'{indent}  ulong slen = fd_rng_ulong( rng ) % 256;', file=body)
        print(f'{indent}  char *buffer = (char *) *alloc_mem;', file=body)
        print(f'{indent}  *alloc_mem = (uchar *) *alloc_mem + slen;', file=body)
        print(f'{indent}  self->{n} = buffer;', file=body)
        print(f'{indent}  LLVMFuzzerMutate( (uchar *)self->{n}, slen, slen );', file=body)
        print(f"{indent}  self->{n}[slen] = '\\0';", file=body)

    def ushort_generate(n, varint, indent):
        print(f'{indent}  self->{n} = fd_rng_ushort( rng );', file=body)

    def ulong_generate(n, varint, indent):
        print(f'{indent}  self->{n} = fd_rng_ulong( rng );', file=body)

    emitGenerateMap = {
        "char" :      lambda n, varint, indent: print(f'{indent}  fd_bincode_uint8_decode_unsafe( (uchar *) &self->{n}, ctx );', file=body),
        "char*" :     lambda n, varint, indent: PrimitiveMember.string_generate(n, varint, indent),
        "char[32]" :  lambda n, varint, indent: print(f'{indent}  LLVMFuzzerMutate( &self->{n}[0], sizeof(self->{n}), sizeof(self->{n}) );', file=body),
        "double" :    lambda n, varint, indent: print(f'{indent}  self->{n} = fd_rng_double_o( rng );', file=body),
        "long" :      lambda n, varint, indent: print(f'{indent}  self->{n} = fd_rng_long( rng );', file=body),
        "uint" :      lambda n, varint, indent: print(f'{indent}  self->{n} = fd_rng_uint( rng );', file=body),
        "uint128" :   lambda n, varint, indent: print(f'{indent}  self->{n} = fd_rng_uint128( rng );', file=body),
        "bool" :      lambda n, varint, indent: print(f'{indent}  self->{n} = fd_rng_uchar( rng );', file=body),
        "uchar" :     lambda n, varint, indent: print(f'{indent}  self->{n} = fd_rng_uchar( rng );', file=body),
        "uchar[32]" : lambda n, varint, indent: print(f'{indent}  LLVMFuzzerMutate( &self->{n}[0], sizeof(self->{n}), sizeof(self->{n}) );', file=body),
        "uchar[128]" :lambda n, varint, indent: print(f'{indent}  LLVMFuzzerMutate( &self->{n}[0], sizeof(self->{n}), sizeof(self->{n}) );', file=body),
        "uchar[2048]":lambda n, varint, indent: print(f'{indent}  LLVMFuzzerMutate( &self->{n}[0], sizeof(self->{n}), sizeof(self->{n}) );', file=body),
        "ulong" :     lambda n, varint, indent: PrimitiveMember.ulong_generate(n, varint, indent),
        "ushort" :    lambda n, varint, indent: PrimitiveMember.ushort_generate(n, varint, indent),
    }

    def emitGenerate(self, indent=''):
        PrimitiveMember.emitGenerateMap[self.type](self.name, self.varint, indent)

# This is a member which IS a struct, NOT a member OF a struct
class StructMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.type = json["type"]
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def isFixedSize(self):
        return self.type in fixedsizetypes

    def fixedSize(self):
        return fixedsizetypes[self.type]

    def isFuzzy(self):
        return self.type in fuzzytypes

    def emitGenerate(self, indent=''):
        # FIXME: tower sync is the only known case, consider checking for other generators
        for entry in entries:
            if entry['name'] == self.name and 'encoders' in entry and entry['encoders'] is False:
                return
        print(f'{indent}  {namespace}_{self.type}_generate( &self->{self.name}, alloc_mem, rng );', file=body)


class VectorMember(TypeNode):
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

    def emitGenerate(self, indent=''):
        print(f'{indent}  self->{self.name}_len = fd_rng_ulong( rng ) % 8;', file=body)
        print(f'{indent}  if( self->{self.name}_len ) {{', file=body)
        el = f'{namespace}_{self.element}'

        if self.element == "uchar":
            print(f'{indent}    self->{self.name} = (uchar *) *alloc_mem;', file=body)
            print(f'{indent}    *alloc_mem = (uchar *) *alloc_mem + self->{self.name}_len;', file=body)
            print(f'{indent}    for( ulong i=0; i < self->{self.name}_len; ++i) {{ self->{self.name}[i] = fd_rng_uchar( rng ) % 0x80; }}', file=body)
        else:
            if self.element in simpletypes:
                print(f'{indent}    self->{self.name} = ({self.element} *) *alloc_mem;', file=body)
                print(f'{indent}    *alloc_mem = (uchar *) *alloc_mem + sizeof({self.element})*self->{self.name}_len;', file=body)
                print(f'{indent}    LLVMFuzzerMutate( (uchar *) self->{self.name}, sizeof({self.element})*self->{self.name}_len, sizeof({self.element})*self->{self.name}_len );', file=body)
            else:
                print(f'    self->{self.name} = ({namespace}_{self.element}_t *) *alloc_mem;', file=body)
                print(f'    *alloc_mem = (uchar *) *alloc_mem + sizeof({el}_t)*self->{self.name}_len;', file=body)
                print(f'    for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
                print(f'      {namespace}_{self.element}_new( self->{self.name} + i );', file=body)
                print(f'      {namespace}_{self.element}_generate( self->{self.name} + i, alloc_mem, rng );', file=body)
                print('    }', file=body)

        print(f'{indent}  }} else {{', file=body)
        print(f'{indent}    self->{self.name} = NULL;', file=body)
        print(f'{indent}  }}', file=body)

class BitVectorMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.vector_element = json["element"]
        self.vector_member = VectorMember(container, None, name=f"{self.name}_bitvec", element=self.vector_element)

    def emitGenerate(self, indent=''):
        print('  {', file=body)
        print(f'    self->has_{self.name} = fd_rng_uchar( rng ) % 2;', file=body)
        print(f'    if( self->has_{self.name} ) {{', file=body)
        self.vector_member.emitGenerate('    ')
        print(f'      self->{self.name}_len = self->{self.vector_member.name}_len;', file=body)
        print('    } else {', file=body)
        print(f'      self->{self.name}_len = 0UL;', file=body)
        print('    }', file=body)
        print('  }',file=body)

class StaticVectorMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.size = (json["size"] if "size" in json else None)
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def isFixedSize(self):
        return False

    def emitGenerate(self, indent=''):
        print(f'  self->{self.name}_len = fd_rng_ulong( rng ) % 8;', file=body)
        print(f'  self->{self.name}_size = {self.size};', file=body)
        print(f'  self->{self.name}_offset = 0;', file=body)

        if self.element == "uchar":
            print(f'  LLVMFuzzerMutate( self->{self.name}, self->{self.name}_len, self->{self.name}_len );', file=body)
            return

        if self.element in simpletypes:
            print(f'    LLVMFuzzerMutate( (uchar *) self->{self.name}, self->{self.name}_len*sizeof({self.element}), self->{self.name}_len*sizeof({self.element}) );', file=body)
        else:
            print(f'  for( ulong i=0; i<self->{self.name}_len; i++ ) {{', file=body)
            print(f'    {namespace}_{self.element}_generate( self->{self.name} + i, alloc_mem, rng );', file=body)
            print('  }', file=body)

class StringMember(VectorMember):
    def __init__(self, container, json):
        json["element"] = "uchar"
        super().__init__(container, json)
        self.compact = False
        self.ignore_underflow = False

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

    def emitGenerate(self, indent=''):
        print(f'  ulong {self.name}_len = fd_rng_ulong( rng ) % 8;', file=body)

        if self.min:
            print(f'  ulong {self.name}_max = fd_ulong_max( {self.name}_len, {self.min} );', file=body)
            print(f'  self->{self.name} = {self.prefix()}_join_new( alloc_mem, {self.name}_max );', file=body)
        else:
            print(f'  self->{self.name} = {self.prefix()}_join_new( alloc_mem, {self.name}_len );', file=body)

        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {self.elem_type()} * elem = {self.prefix()}_push_tail_nocopy( self->{self.name} );', file=body);

        if self.element in simpletypes:
            print(f'    LLVMFuzzerMutate( (uchar *) elem, sizeof({self.element}), sizeof({self.element}) );', file=body)
        else:
            print(f'    {namespace}_{self.element}_generate( elem, alloc_mem, rng );', file=body)

        print('  }', file=body)

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

    def emitGenerate(self, indent=''):
        element_type = self.elem_type()
        mapname = element_type + "_map"
        nodename = element_type + "_mapnode_t"

        print(f'  ulong {self.name}_len = fd_rng_ulong( rng ) % 8;', file=body)

        if self.minalloc > 0:
            print(f'  self->{self.name}_pool = {mapname}_join_new( alloc_mem, fd_ulong_max( {self.name}_len, {self.minalloc} ) );', file=body)
        else:
            print(f'  self->{self.name}_pool = {mapname}_join_new( alloc_mem, {self.name}_len );', file=body)

        print(f'  self->{self.name}_root = NULL;', file=body)
        print(f'  for( ulong i=0; i < {self.name}_len; i++ ) {{', file=body)
        print(f'    {nodename} * node = {mapname}_acquire( self->{self.name}_pool );', file=body)
        print(f'    {namespace}_{self.element}_generate( &node->elem, alloc_mem, rng );', file=body)
        print(f'    {mapname}_insert( self->{self.name}_pool, &self->{self.name}_root, node );', file=body)
        print('  }', file=body)

class PartitionMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.dlist_t = json["dlist_t"]
        self.dlist_n = json["dlist_n"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")
        self.dlist_max = (int(json["dlist_max"]) if "dlist_max" in json else 0)

    def emitGenerate(self, indent=''):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"

        print(f'  self->{self.name}_len = fd_rng_ulong( rng ) % 8;', file=body)
        print(f'  ulong total_count = 0UL;', file=body)
        print(f'  for( ulong i=0; i < {self.dlist_max}; i++ ) {{', file=body)
        print(f'    self->{self.name}_lengths[i] = fd_rng_ulong( rng ) % 8;', file=body)
        print(f'    total_count += self->{self.name}_lengths[ i ];', file=body)
        print('  }', file=body)

        print(f'  self->pool = {pool_name}_join_new( alloc_mem, total_count );', file=body)
        print(f'  self->{self.name} = {dlist_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)

        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
        # print(f'    fd_partitioned_stake_rewards_dlist_t * partition = {dlist_name}_join_new( alloc_mem, self->{self.name}_len );')
        # print(f'    self->{self.name}[ i ] = partition;', file=body)
        print(f'    {dlist_name}_new( &self->{self.name}[ i ] );', file=body)
        print(f'    for( ulong j=0; j < self->{self.name}_lengths[ i ]; j++ ) {{', file=body)
        print(f'      {dlist_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'      {dlist_t.rstrip("_t")}_new( ele );', file=body)
        print(f'      {dlist_t.rstrip("_t")}_generate( ele, alloc_mem, rng );', file=body)
        print(f'      {dlist_name}_ele_push_tail( &self->{self.name}[ i ], ele, self->pool );', file=body)
        print('    }', file=body)
        print('  }', file=body)

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

    def emitGenerate(self, indent=''):
        treap_name = self.name + '_treap'
        treap_t = self.treap_t
        pool_name = self.name + '_pool'

        print(f'  ulong {treap_name}_len = fd_rng_ulong( rng ) % 8;', file=body)

        print(f'  ulong {treap_name}_max = fd_ulong_max( {treap_name}_len, {self.min_name} );', file=body)
        print(f'  self->pool = {pool_name}_join_new( alloc_mem, {treap_name}_max );', file=body)
        print(f'  self->treap = {treap_name}_join_new( alloc_mem, {treap_name}_max );', file=body)
        print(f'  for( ulong i=0; i < {treap_name}_len; i++ ) {{', file=body)
        print(f'    {treap_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'    {treap_t.rstrip("_t")}_generate( ele, alloc_mem, rng );', file=body)

        if self.upsert:
            print(f'    {treap_t} * repeated_entry = {treap_name}_ele_query( self->treap, ele->epoch, self->pool );', file=body)
            print(f'    if( repeated_entry ) {{', file=body)
            print(f'        {treap_name}_ele_remove( self->treap, repeated_entry, self->pool ); // Remove the element before inserting it back to avoid duplication', file=body)
            print(f'        {pool_name}_ele_release( self->pool, repeated_entry );', file=body)
            print(f'    }}', file=body)

        print(f'    {treap_name}_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */', file=body)
        print('  }', file=body)

class OptionMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.element = json["element"]
        self.flat = json.get("flat", False)
        self.ignore_underflow = (bool(json["ignore_underflow"]) if "ignore_underflow" in json else False)

    def emitGenerate(self, indent=''):
        print('  {', file=body)
        if self.flat:
            print(f'    self->has_{self.name} = fd_rng_uchar( rng ) % 2;', file=body)
            print(f'    if( self->has_{self.name} ) {{', file=body)
            if self.element in simpletypes:
                print(f'      LLVMFuzzerMutate( (uchar *)&(self->{self.name}), sizeof({self.element}), sizeof({self.element}) );', file=body)
            else:
                el = f'{namespace}_{self.element}'
                el = el.upper()
                print(f'      {namespace}_{self.element}_generate( &self->{self.name}, alloc_mem, rng );', file=body)
            print('    }', file=body)
        else:
            print(f'    uchar is_null = fd_rng_uchar( rng ) % 2;', file=body)
            print(f'    if( !is_null ) {{', file=body)
            if self.element in simpletypes:
                print(f'      self->{self.name} = ({self.element} *) *alloc_mem;', file=body)
                print(f'      *alloc_mem = (uchar *) *alloc_mem + sizeof({self.element});', file=body)
                print(f'      LLVMFuzzerMutate( (uchar *)self->{self.name}, sizeof({self.element}), sizeof({self.element}) );', file=body)
            else:
                el = f'{namespace}_{self.element}'
                print(f'      self->{self.name} = ({namespace}_{self.element}_t *) *alloc_mem;', file=body)
                print(f'      *alloc_mem = (uchar *) *alloc_mem + sizeof({el}_t);', file=body)
                print(f'      {namespace}_{self.element}_new( self->{self.name} );', file=body)
                print(f'      {namespace}_{self.element}_generate( self->{self.name}, alloc_mem, rng );', file=body)
            print('    }', file=body)
            print(f'    else {{', file=body)
            print(f'    self->{self.name} = NULL;', file=body)
            print('    }', file=body)
        print('  }', file=body)

class DlistMember(TypeNode):
    def __init__(self, container, json):
        super().__init__(json)
        self.dlist_t = json["dlist_t"]
        self.dlist_n = json["dlist_n"]
        self.compact = ("modifier" in json and json["modifier"] == "compact")

    def emitGenerate(self, indent=''):
        dlist_name = self.dlist_n + "_dlist"
        dlist_t = self.dlist_t
        pool_name = self.dlist_n + "_pool"

        print(f'  self->{self.name}_len = fd_rng_ulong( rng ) % 8;', file=body)

        print(f'  self->pool = {pool_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)
        print(f'  self->{self.name} = {dlist_name}_join_new( alloc_mem, self->{self.name}_len );', file=body)
        print(f'  {dlist_name}_new( self->{self.name} );', file=body)
        print(f'  for( ulong i=0; i < self->{self.name}_len; i++ ) {{', file=body)
        print(f'    {dlist_t} * ele = {pool_name}_ele_acquire( self->pool );', file=body)
        print(f'    {dlist_t.rstrip("_t")}_new( ele );', file=body)
        print(f'    {dlist_t.rstrip("_t")}_generate( ele, alloc_mem, rng );', file=body)
        print(f'    {dlist_name}_ele_push_tail( self->{self.name}, ele, self->pool );', file=body)
        print('  }', file=body)

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

    def emitGenerate(self, indent=''):
        length = self.length

        if self.element == "uchar":
            print(f'  LLVMFuzzerMutate( self->{self.name}, {length}, {length} );', file=body)
            return

        if self.element in simpletypes:
            print(f'    LLVMFuzzerMutate( (uchar *)self->{self.name}, sizeof({self.element})*{length}, sizeof({self.element})*{length} );', file=body)
        else:
            print(f'  for( ulong i=0; i<{length}; i++ ) {{', file=body)
            print(f'    {namespace}_{self.element}_generate( self->{self.name} + i, alloc_mem, rng );', file=body)
            print('  }', file=body)

memberTypeMap = {
    "static_vector" :    StaticVectorMember,
    "vector" :    VectorMember,
    "string" :    StringMember,
    "deque" :     DequeMember,
    "array" :     ArrayMember,
    "option" :    OptionMember,
    "map" :       MapMember,
    "treap" :     TreapMember,
    "dlist" :     DlistMember,
    "partition" : PartitionMember,
    "bitvec":     BitVectorMember,
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

    def emitImpls(self):
        n = self.fullname

        print(f'void *{n}_generate(void *mem, void **alloc_mem, fd_rng_t * rng) {{', file=body)
        print(f'  *alloc_mem = (uchar *) *alloc_mem + sizeof({n}_t);', file=body)
        print(f'  {n}_new(mem);', file=body)
        print(f'  LLVMFuzzerMutate( (uchar *) mem, sizeof({n}_t), sizeof({n}_t));', file=body)
        print(f'  return mem;', file=body)
        print("}", file=body)

        print("", file=body)

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

    def emitGenerators(self):
        n = self.fullname
        self.emitGenerate(n)

    def emitGenerate(self, n):
        print(f'void *{n}_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {{', file=body)
        print(f'  {n}_t *self = ({n}_t *) mem;', file=body)
        print(f'  *alloc_mem = (uchar *) *alloc_mem + sizeof({n}_t);', file=body)
        print(f'  {n}_new(mem);', file=body)
        for f in self.fields:
            f.emitGenerate()
        print('  return mem;', file=body)
        print("}", file=body)

    def emitImpls(self):
        if self.encoders is not False:
            self.emitGenerators()

        print("", file=body)

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

    def emitImpls(self):
        n = self.fullname
        indent = '  '

        if not self.isFixedSize():
            print(f'void {n}_inner_generate( {n}_inner_t * self, void **alloc_mem, {self.repr} discriminant, fd_rng_t * rng ) {{', file=body)
            first = True
            for i, v in enumerate(self.variants):
                if not isinstance(v, str):
                    if first:
                        print('  switch (discriminant) {', file=body)
                        first = False
                    print(f'  case {i}: {{', file=body)
                    v.emitGenerate(indent)
                    print('    break;', file=body)
                    print('  }', file=body)
            if not first:
                print('  }', file=body)
            print("}", file=body)

        print(f'void *{n}_generate( void *mem, void **alloc_mem, fd_rng_t * rng ) {{', file=body)
        print(f'  {n}_t *self = ({n}_t *) mem;', file=body)
        print(f'  *alloc_mem = (uchar *) *alloc_mem + sizeof({n}_t);', file=body)
        print(f'  {n}_new(mem);', file=body)
        print(f'  self->discriminant = fd_rng_uint( rng ) % { len(self.variants) };', file=body)

        # FIXME: Annoying, but no other choice than to avoid generating a struct that uses them
        if 'vote_instruction' == self.name:
            print(f'  while( self->discriminant == 14 || self->discriminant == 15 ) {{ self->discriminant = fd_rng_uint( rng ) % { len(self.variants) }; }}', file=body)
        if not self.isFixedSize():
            print(f'  {n}_inner_generate( &self->inner, alloc_mem, self->discriminant, rng );', file=body)
        print(f'  return mem;', file=body)
        print("}", file=body)
        print("", file=body)

        indent = ''

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
        if hasattr(t, 'fullname'):
            nametypes[t.fullname] = t

    global fixedsizetypes
    global fuzzytypes
    for typeinfo in alltypes:
        if typeinfo.isFixedSize():
            fixedsizetypes[typeinfo.name] = typeinfo.fixedSize()
        if typeinfo.isFuzzy():
            fuzzytypes.add(typeinfo.name)

    for t in alltypes:
        t.emitImpls()

    print("#endif // HEADER_FUZZ_" + json_object["name"].upper(), file=body)

if __name__ == "__main__":
    main()
