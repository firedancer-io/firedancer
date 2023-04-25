# This stub generator is horrible...  the resulting code is horrible...  please... rewrite 

import json
import sys

with open('fd_types.json', 'r') as json_file:
    json_object = json.load(json_file)

header = open(sys.argv[1], "w")
body = open(sys.argv[2], "w")

namespace = json_object["namespace"]
entries = json_object["entries"]

print("#ifndef HEADER_" + json_object["name"].upper(), file=header)
print("#define HEADER_" + json_object["name"].upper(), file=header)
print("", file=header)
for extra in json_object["extra_header"]:
    print(extra, file=header)
print("", file=header)

print("#include \"" + sys.argv[1] + "\"", file=body)

print("#pragma GCC diagnostic ignored \"-Wunused-parameter\"", file=body)

type_map = {
    "int64_t": "long",
    "uint64_t": "unsigned long",
    "ulong": "unsigned long",
    "uchar": "unsigned char"
}

def do_vector_header(n, f):
    if "modifier" in f and f["modifier"] == "compact":
        print("  ushort " + f["name"] + "_len;", file=header)
    else:
        print("  ulong " + f["name"] + "_len;", file=header)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("  " + f["element"] + "* " + f["name"] + ";", file=header)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("  " + f["element"] + "* " + f["name"] + ";", file=header)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("  " + f["element"] + "* " + f["name"] + ";", file=header)
    else:
        print("  " + n + "_" + f["element"] + "_t* " + f["name"] + ";", file=header)

def vector_dynamic_elem_type(n, f):
  if f["element"] == "unsigned char" or f["element"] == "uchar":
    return "uchar"
  elif f["element"] == "ulong" or f["element"] == "unsigned long":
      return "ulong"
  elif f["element"] == "uint" or f["element"] == "unsigned int":
      return "uint"
  else:
      return n + "_" + f["element"] + "_t"
  
def vector_dynamic_prefix(n, f):
    return n + "_vec_" + vector_dynamic_elem_type(n, f)

def do_vector_dynamic_header(n, f):
    print("  " + vector_dynamic_prefix(n, f) + "_t " + f["name"] + ";", file=header)

def do_map_header(n, f):
    element_type = vector_dynamic_elem_type(n, f)
    nodename = element_type + "_mapnode_t"
    print("  " + nodename + "* " + f["name"] + "_pool;", file=header)
    print("  " + nodename + "* " + f["name"] + "_root;", file=header)
  
def do_option_header(n, f):
      if f["element"] == "ulong" or f["element"] == "unsigned long":
          print("  " + f["element"] + "* " + f["name"] + ";", file=header)
      elif f["element"] == "uint" or f["element"] == "unsigned int":
          print("  " + f["element"] + "* " + f["name"] + ";", file=header)
      else:
          print("  " + n + "_" + f["element"] + "_t* " + f["name"] + ";", file=header)

def do_array_header(n, f):
    print("  ulong " + f["name"] + "_len;", file=header)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("  " + f["element"] + "* " + f["name"] + ";", file=header)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("  " + f["element"] + "* " + f["name"] + ";", file=header)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("  " + f["element"] + "* " + f["name"] + ";", file=header)
    else:
        print("  " + n + "_" + f["element"] + "_t* " + f["name"] + ";", file=header)
    
fields_header = {
    "char" :              lambda n, f: print("  char " + f["name"] + ";",              file=header),
    "char*" :             lambda n, f: print("  char* " + f["name"] + ";",             file=header),
    "char[32]" :          lambda n, f: print("  char " + f["name"] + "[32];",          file=header),
    "char[7]" :           lambda n, f: print("  char " + f["name"] + "[7];",           file=header),
    "double" :            lambda n, f: print("  double " + f["name"] + ";",            file=header),
    "long" :              lambda n, f: print("  long " + f["name"] + ";",              file=header),
    "uint" :              lambda n, f: print("  uint " + f["name"] + ";",              file=header),
    "uint128" :           lambda n, f: print("  uint128 " + f["name"] + ";",           file=header),
    "unsigned char" :     lambda n, f: print("  unsigned char " + f["name"] + ";",     file=header),
    "unsigned char[32]" : lambda n, f: print("  unsigned char " + f["name"] + "[32];", file=header),
    "unsigned long" :     lambda n, f: print("  unsigned long " + f["name"] + ";",     file=header),
    "ushort" :            lambda n, f: print("  ushort " + f["name"] + ";",            file=header),
    "vector" :            lambda n, f: do_vector_header(n, f),
    "vector_dynamic":     lambda n, f: do_vector_dynamic_header(n, f),
    "array":              lambda n, f: do_array_header(n, f),
    "option" :            lambda n, f: do_option_header(n, f),
    "map" :               lambda n, f: do_map_header(n, f),
}

def do_vector_body_decode(n, f):
    if "modifier" in f and f["modifier"] == "compact":
        print("  fd_decode_short_u16(&self->" + f["name"] + "_len, data, dataend);", file=body)
    else:
        print("  fd_bincode_uint64_decode(&self->" + f["name"] + "_len, data, dataend);", file=body)
    print("  if (self->" + f["name"] + "_len != 0) {", file=body)
    el = n + "_" + f["element"]
    el = el.upper()

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("    self->" + f["name"] + " = (unsigned char*)(*allocf)(allocf_arg, 8, self->" + f["name"] + "_len);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    self->" + f["name"] + " = (ulong*)(*allocf)(allocf_arg, 8UL, sizeof(ulong)*self->" + f["name"] + "_len);", file=body)
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    self->" + f["name"] + " = (uint*)(*allocf)(allocf_arg, 8UL, sizeof(ulong)*self->" + f["name"] + "_len);", file=body)
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)
    else:
        print("    self->" + f["name"] + " = (" + n + "_" + f["element"] + "_t*)(*allocf)(allocf_arg, " + el + "_ALIGN, " + el + "_FOOTPRINT*self->" + f["name"] + "_len);", file=body)
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("fd_bincode_bytes_decode(self->" + f["name"] + ", self->" + f["name"] + "_len, data, dataend);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("fd_bincode_uint64_decode(self->" + f["name"] + " + i, data, dataend);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("fd_bincode_uint32_decode(self->" + f["name"] + " + i, data, dataend);", file=body)
    else:
        print("      " + n + "_" + f["element"] + "_decode(self->" + f["name"] + " + i, data, dataend, allocf, allocf_arg);", file=body)
    print("  } else", file=body)
    print("   self->" + f["name"] + " = NULL;", file=body)


def do_vector_dynamic_body_decode(n, f):
    print(vector_dynamic_prefix(n, f) + "_new(&self->" + f["name"] + ");", file=body)

    print("ulong " + f["name"] + "_len;", file=body)

    if "modifier" in f and f["modifier"] == "compact":
        print("  fd_decode_short_u16(&" + f["name"] + "_len, data, dataend);", file=body)
    else:
        print("  fd_bincode_uint64_decode(&" + f["name"] + "_len, data, dataend);", file=body)
    el = n + "_" + f["element"]
    el = el.upper()

    print("  for (ulong i = 0; i < " + f["name"] + "_len; ++i) {", file=body)
    print("    " + vector_dynamic_elem_type(n, f) + " elem;", file=body); 

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("    fd_bincode_bytes_decode(&elem, " + f["name"] + "_len, data, dataend);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    fd_bincode_uint64_decode(&elem, data, dataend);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    fd_bincode_uint32_decode(&elem, data, dataend);", file=body)
    else:
        print("    " + n + "_" + f["element"] + "_decode(&elem, data, dataend, allocf, allocf_arg);", file=body)
    print("    " + vector_dynamic_prefix(n, f) + "_push(&self->" + f["name"] + ", elem);", file=body)

    print("  }", file=body)

def do_map_body_decode(n, f):
    element_type = vector_dynamic_elem_type(n, f)
    mapname = element_type + "_map"
    nodename = element_type + "_mapnode_t"
    
    if "modifier" in f and f["modifier"] == "compact":
        print("  ushort " + f["name"] + "_len;", file=body)
        print("  fd_decode_short_u16(&" + f["name"] + "_len, data, dataend);", file=body)
    else:
        print("  ulong " + f["name"] + "_len;", file=body)
        print("  fd_bincode_uint64_decode(&" + f["name"] + "_len, data, dataend);", file=body)

    print("  void* " + f["name"] + "_mem = (*allocf)(allocf_arg, " + mapname + "_pool_align(), " + mapname + "_pool_footprint(" + f["name"] + "_len+1));", file=body)
    print("  self->" + f["name"] + "_pool = " + mapname + "_pool_join(" + mapname + "_pool_new(" + f["name"] + "_mem, " + f["name"] + "_len+1));", file=body)
    print("  self->" + f["name"] + "_root = NULL;", file=body)
    print("  for (ulong i = 0; i < " + f["name"] + "_len; ++i) {", file=body)
    print("    " + nodename + "* node = " + mapname + "_pool_allocate(self->" + f["name"] + "_pool);", file=body); 
    print("    " + n + "_" + f["element"] + "_decode(&node->elem, data, dataend, allocf, allocf_arg);", file=body)
    print("    " + mapname + "_insert(self->" + f["name"] + "_pool, &self->" + f["name"] + "_root, node);", file=body)
    print("  }", file=body)

def do_array_body_decode(n, f):

    el = n + "_" + f["element"]
    el = el.upper()

    length = f["length"]

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("    self->" + f["name"] + " = (unsigned char*)(*allocf)(allocf_arg, 8, " + length + ");", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    self->" + f["name"] + " = (ulong*)(*allocf)(allocf_arg, 8UL, sizeof(ulong)*" + length + ");", file=body)
        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    self->" + f["name"] + " = (uint*)(*allocf)(allocf_arg, 8UL, sizeof(ulong)*" + length + ");", file=body)
        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
    else:
        print("    self->" + f["name"] + " = (" + n + "_" + f["element"] + "_t*)(*allocf)(allocf_arg, " + el + "_ALIGN, " + el + "_FOOTPRINT*" + length + ");", file=body)
        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("fd_bincode_bytes_decode(self->" + f["name"] + ", " + length + ", data, dataend);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("fd_bincode_uint64_decode(self->" + f["name"] + " + i, data, dataend);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("fd_bincode_uint32_decode(self->" + f["name"] + " + i, data, dataend);", file=body)
    else:
        print("      " + n + "_" + f["element"] + "_decode(self->" + f["name"] + " + i, data, dataend, allocf, allocf_arg);", file=body)

def do_option_body_decode(n, f):
    print("  if (fd_bincode_option_decode(data, dataend)) {", file=body)
    if f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    self->" + f["name"] + " = (ulong*)(*allocf)(allocf_arg, 8, sizeof(ulong));", file=body)
        print("    fd_bincode_uint64_decode(self->" + f["name"] + ", data, dataend);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    self->" + f["name"] + " = (uint*)(*allocf)(allocf_arg, 8, sizeof(uint));", file=body)
        print("    fd_bincode_uint32_decode(self->" + f["name"] + ", data, dataend);", file=body)
    else:
        el = n + "_" + f["element"]
        el = el.upper()
        print("    self->" + f["name"] + " = (" + n + "_" + f["element"] + "_t*)(*allocf)(allocf_arg, " + el + "_ALIGN, " + el + "_FOOTPRINT);", file=body)
        print("    " + n + "_" + f["element"] + "_decode(self->" + f["name"] + ", data, dataend, allocf, allocf_arg);", file=body)
    print("  } else", file=body)
    print("    self->" + f["name"] + " = NULL;", file=body)

def do_string_decode(n, f):    
    print("  ulong slen;", file=body)
    print("  fd_bincode_uint64_decode(&slen, data, dataend);", file=body)
    print("  self->" + f["name"] + " = (char*)(*allocf)(allocf_arg, 1, slen + 1);", file=body)
    print("  fd_bincode_bytes_decode((uchar *) self->" + f["name"] + ", slen, data, dataend);", file=body)
    print("  self->" + f["name"] + "[slen] = '\\0';", file=body)

def do_ulong_decode(n, f):    
    if "modifier" in f and f["modifier"] == "varint":
        print("fd_decode_varint(&self->" + f["name"] + ", data, dataend);", file=body),
    else:
        print("fd_bincode_uint64_decode(&self->" + f["name"] + ", data, dataend);", file=body),

fields_body_decode = {
    "char" :              lambda n, f: print("fd_bincode_uint8_decode((unsigned char *) &self->" + f["name"] + ", data, dataend);", file=body),
    "char*" :             lambda n, f: do_string_decode(n, f),
    "char[32]" :          lambda n, f: print("fd_bincode_bytes_decode(&self->" + f["name"] + "[0], sizeof(self->" + f["name"] + "), data, dataend);", file=body),
    "char[7]" :           lambda n, f: print("fd_bincode_bytes_decode(&self->" + f["name"] + "[0], sizeof(self->" + f["name"] + "), data, dataend);", file=body),
    "double" :            lambda n, f: print("fd_bincode_double_decode(&self->" + f["name"] + ", data, dataend);", file=body),
    "long" :              lambda n, f: print("fd_bincode_uint64_decode((unsigned long *) &self->" + f["name"] + ", data, dataend);", file=body),
    "uint" :              lambda n, f: print("fd_bincode_uint32_decode(&self->" + f["name"] + ", data, dataend);", file=body),
    "uint128" :           lambda n, f: print("fd_bincode_uint128_decode(&self->" + f["name"] + ", data, dataend);", file=body),
    "unsigned char" :     lambda n, f: print("fd_bincode_uint8_decode(&self->" + f["name"] + ", data, dataend);", file=body),
    "unsigned char[32]" : lambda n, f: print("fd_bincode_bytes_decode(&self->" + f["name"] + "[0], sizeof(self->" + f["name"] + "), data, dataend);", file=body),
    "unsigned long" :     lambda n, f: do_ulong_decode(n, f),
    "ushort" :            lambda n, f: print("fd_bincode_uint16_decode(&self->" + f["name"] + ", data, dataend);", file=body),
    "vector" :            lambda n, f: do_vector_body_decode(n, f),
    "vector_dynamic":     lambda n, f: do_vector_dynamic_body_decode(n, f),
    "array":              lambda n, f: do_array_body_decode(n, f),
    "option" :            lambda n, f: do_option_body_decode(n, f),
    "map" :               lambda n, f: do_map_body_decode(n, f),
}
# encode

def do_vector_body_encode(n, f):
    if "modifier" in f and f["modifier"] == "compact":
        print("  fd_encode_short_u16(&self->" + f["name"] + "_len, (void **) data);", file=body)
    else:
        print("  fd_bincode_uint64_encode(&self->" + f["name"] + "_len, data);", file=body)
    print("  if (self->" + f["name"] + "_len != 0) {", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        pass
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)
    else:
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("fd_bincode_bytes_encode(self->" + f["name"] + ", self->" + f["name"] + "_len, data);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("fd_bincode_uint64_encode(self->" + f["name"] + " + i, data);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("fd_bincode_uint32_encode(self->" + f["name"] + " + i, data);", file=body)
    else:
        print("      " + n + "_" + f["element"] + "_encode(self->" + f["name"] + " + i, data);", file=body)
    print("  }", file=body)


def do_vector_dynamic_body_encode(n, f):
    if "modifier" in f and f["modifier"] == "compact":
        print("  fd_encode_short_u16(&self->" + f["name"] + ".cnt, (void **) data);", file=body)
    else:
        print("  fd_bincode_uint64_encode(&self->" + f["name"] + ".cnt, data);", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("    for (ulong i = 0; i < self->" + f["name"] + ".cnt; ++i)", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    for (ulong i = 0; i < self->" + f["name"] + ".cnt; ++i)", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    for (ulong i = 0; i < self->" + f["name"] + ".cnt; ++i)", file=body)
    else:
        print("    for (ulong i = 0; i < self->" + f["name"] + ".cnt; ++i)", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("fd_bincode_bytes_encode(&self->" + f["name"] + ".elems[i], 1, data);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("fd_bincode_uint64_encode(&self->" + f["name"] + ".elems[i], data);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("fd_bincode_uint32_encode(&self->" + f["name"] + ".elems[i], data);", file=body)
    else:
        print("      " + n + "_" + f["element"] + "_encode(&self->" + f["name"] + ".elems[i], data);", file=body)

def do_map_body_encode(n, f):
    element_type = vector_dynamic_elem_type(n, f)
    mapname = element_type + "_map"
    nodename = element_type + "_mapnode_t"
    
    if "modifier" in f and f["modifier"] == "compact":
        print("  ushort " + f["name"] + "_len = (ushort)" + mapname + "_size(self->" + f["name"] + "_pool, self->" + f["name"] + "_root);", file=body)
        print("  fd_encode_short_u16(&" + f["name"] + "_len, data);", file=body)
    else:
        print("  ulong " + f["name"] + "_len = " + mapname + "_size(self->" + f["name"] + "_pool, self->" + f["name"] + "_root);", file=body)
        print("  fd_bincode_uint64_encode(&" + f["name"] + "_len, data);", file=body)
    print("  for ( " + nodename + "* n = " + mapname + "_minimum(self->" + f["name"] + "_pool, self->" + f["name"] + "_root); n; n = " + mapname + "_successor(self->" + f["name"] + "_pool, n) ) {", file=body);
    print("      " + n + "_" + f["element"] + "_encode(&n->elem, data);", file=body)
    print("  }", file=body)
        
def do_array_body_encode(n, f):
    length = f["length"]

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        pass
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
    else:
        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("fd_bincode_bytes_encode(self->" + f["name"] + ", " + length + ", data);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("fd_bincode_uint64_encode(self->" + f["name"] + " + i, data);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("fd_bincode_uint32_encode(self->" + f["name"] + " + i, data);", file=body)
    else:
        print("      " + n + "_" + f["element"] + "_encode(self->" + f["name"] + " + i, data);", file=body)

def do_option_body_encode(n, f):
    print("  if (self->" + f["name"] + "!= NULL) {", file=body)
    print("    fd_bincode_option_encode(1, data);", file=body)

    if f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    fd_bincode_uint64_encode(self->" + f["name"] + ", data);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    fd_bincode_uint32_encode(self->" + f["name"] + ", data);", file=body)
    else:
        print("    " + n + "_" + f["element"] + "_encode(self->" + f["name"] + ", data);", file=body)
    print("  } else", file=body)
    print("    fd_bincode_option_encode(0, data);", file=body)

def do_string_encode(n, f):    
    print("  ulong slen = strlen((char *) self->" + f["name"]+");", file=body)
    print("  fd_bincode_uint64_encode(&slen, data);", file=body)
    print("  fd_bincode_bytes_encode((uchar *) self->" + f["name"] + ", slen, data);", file=body)

def do_ulong_encode(n, f):
    if "modifier" in f and f["modifier"] == "varint":
        print("fd_encode_varint(self->" + f["name"] + ", (uchar **) data);", file=body),
    else:
       print("fd_bincode_uint64_encode(&self->" + f["name"] + ", data);", file=body),

fields_body_encode = {
    "char" :              lambda n, f: print("fd_bincode_uint8_encode((unsigned char *) &self->" + f["name"] + ", data);", file=body),
    "char*" :             lambda n, f: do_string_encode(n, f),
    "char[32]" :          lambda n, f: print("fd_bincode_bytes_encode(&self->" + f["name"] + "[0], sizeof(self->" + f["name"] + "), data);", file=body),
    "char[7]" :           lambda n, f: print("fd_bincode_bytes_encode(&self->" + f["name"] + "[0], sizeof(self->" + f["name"] + "), data);", file=body),
    "double" :            lambda n, f: print("fd_bincode_double_encode(&self->" + f["name"] + ", data);", file=body),
    "long" :              lambda n, f: print("fd_bincode_uint64_encode((unsigned long *) &self->" + f["name"] + ", data);", file=body),
    "uint" :              lambda n, f: print("fd_bincode_uint32_encode(&self->" + f["name"] + ", data);", file=body),
    "uint128" :           lambda n, f: print("fd_bincode_uint128_encode(&self->" + f["name"] + ", data);", file=body),
    "unsigned char" :     lambda n, f: print("fd_bincode_uint8_encode(&self->" + f["name"] + ", data);", file=body),
    "unsigned char[32]" : lambda n, f: print("fd_bincode_bytes_encode(&self->" + f["name"] + "[0], sizeof(self->" + f["name"] + "), data);", file=body),
    "unsigned long" :     lambda n, f: do_ulong_encode(n, f),
    "ushort" :            lambda n, f: print("fd_bincode_uint16_encode(&self->" + f["name"] + ", data);", file=body),
    "vector" :            lambda n, f: do_vector_body_encode(n, f),
    "vector_dynamic" :    lambda n, f: do_vector_dynamic_body_encode(n, f),
    "array" :             lambda n, f: do_array_body_encode(n, f),
    "option" :            lambda n, f: do_option_body_encode(n, f),
    "map" :               lambda n, f: do_map_body_encode(n, f),
}

# size

def do_vector_body_size(n, f):
    print("  size += sizeof(ulong);", file=body)
    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("    size += self->" + f["name"] + "_len;", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    size += self->" + f["name"] + "_len * sizeof(ulong);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    size += self->" + f["name"] + "_len * sizeof(uint);", file=body)
    else:
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)
        print("      size += " + n + "_" + f["element"] + "_size(self->" + f["name"] + " + i);", file=body)

def do_vector_dynamic_body_size(n, f):
    print("  size += sizeof(ulong);", file=body)
    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("    size += self->" + f["name"] + ".cnt;", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    size += self->" + f["name"] + ".cnt * sizeof(ulong);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    size += self->" + f["name"] + ".cnt * sizeof(uint);", file=body)
    else:
        print("    for (ulong i = 0; i < self->" + f["name"] + ".cnt; ++i)", file=body)
        print("      size += " + n + "_" + f["element"] + "_size(&self->" + f["name"] + ".elems[i]);", file=body)

def do_map_body_size(n, f):
    element_type = vector_dynamic_elem_type(n, f)
    mapname = element_type + "_map"
    nodename = element_type + "_mapnode_t"
    
    if "modifier" in f and f["modifier"] == "compact":
        print("  size += sizeof(ushort);", file=body)
    else:
        print("  size += sizeof(ulong);", file=body)
    print("  for ( " + nodename + "* n = " + mapname + "_minimum(self->" + f["name"] + "_pool, self->" + f["name"] + "_root); n; n = " + mapname + "_successor(self->" + f["name"] + "_pool, n) ) {", file=body);
    print("      size += " + n + "_" + f["element"] + "_size(&n->elem);", file=body)
    print("  }", file=body)
        
def do_array_body_size(n, f):
    length = f["length"]

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("    size += " + length + ";", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    size += " + length + " * sizeof(ulong);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    size += " + length + " * sizeof(uint);", file=body)
    else:
        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
        print("      size += " + n + "_" + f["element"] + "_size(self->" + f["name"] + " + i);", file=body)

def do_option_body_size(n, f):
    print("  size += sizeof(char);", file=body)
    print("   if (NULL !=  self->" + f["name"] + ") {", file=body)

    if f["element"] == "ulong" or f["element"] == "unsigned long":
        print("    size += sizeof(ulong);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("    size += sizeof(uint);", file=body)
    else:
        el = n + "_" + f["element"]
        el = el.upper()
        print("    size += " + n + "_" + f["element"] + "_size(self->" + f["name"] + ");", file=body)
    print("  }", file=body)

def do_string_size(n, f):    
    print("  size += sizeof(ulong) + strlen(self->" + f["name"] + ");", file=body)

fields_body_size = {
    "char" :              lambda n, f: print("size += sizeof(char);", file=body),
    "char*" :             lambda n, f: do_string_size(n, f),
    "char[32]" :          lambda n, f: print("size += sizeof(char) * 32;", file=body),
    "char[7]" :           lambda n, f: print("size += sizeof(char) * 7;", file=body),
    "double" :            lambda n, f: print("size += sizeof(double);", file=body),
    "long" :              lambda n, f: print("size += sizeof(long);", file=body),
    "uint" :              lambda n, f: print("size += sizeof(uint);", file=body),
    "uint128" :           lambda n, f: print("size += sizeof(uint128);", file=body),
    "unsigned char" :     lambda n, f: print("size += sizeof(char);", file=body),
    "unsigned char[32]" : lambda n, f: print("size += sizeof(char) * 32;", file=body),
    "unsigned long" :     lambda n, f: print("size += sizeof(ulong);", file=body),
    "ushort" :            lambda n, f: print("size += sizeof(ushort);", file=body),
    "vector" :            lambda n, f: do_vector_body_size(n, f),
    "vector_dynamic" :    lambda n, f: do_vector_dynamic_body_size(n, f),
    "array" :             lambda n, f: do_array_body_size(n, f),
    "option" :            lambda n, f: do_option_body_size(n, f),
    "map" :               lambda n, f: do_map_body_size(n, f),
}

#

def do_vector_body_destroy(n, f):
    print("if (NULL != self->" + f["name"] + ") {", file=body)
    if f["element"] == "unsigned char" or f["element"] == "uchar":
        pass
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        pass
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        pass
    else:
        print("for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)
        print("    " + n + "_" + f["element"] + "_destroy(self->" + f["name"] + " + i, freef, freef_arg);", file=body)
    print("freef(freef_arg, self->" + f["name"] + ");", file=body)
    print("self->" + f["name"] + " = NULL;", file=body)
    print("}", file=body)


def do_vector_dynamic_body_destroy(n, f):
    print(vector_dynamic_prefix(n, f) + "_destroy(&self->" + f["name"] + ");", file=body)

def do_map_body_destroy(n, f):
    element_type = vector_dynamic_elem_type(n, f)
    mapname = element_type + "_map"
    nodename = element_type + "_mapnode_t"
    
    print("  for ( " + nodename + "* n = " + mapname + "_minimum(self->" + f["name"] + "_pool, self->" + f["name"] + "_root); n; n = " + mapname + "_successor(self->" + f["name"] + "_pool, n) ) {", file=body);
    print("      " + n + "_" + f["element"] + "_destroy(&n->elem, freef, freef_arg);", file=body)
    print("  }", file=body)
    print("  freef(freef_arg, " + mapname + "_pool_delete(" + mapname + "_pool_leave(self->" + f["name"] + "_pool)));", file=body)
    print("  self->" + f["name"] + "_pool = NULL;", file=body)
    print("  self->" + f["name"] + "_root = NULL;", file=body)
        
def do_array_body_destroy(n, f):
    length = f["length"]

    print("if (NULL != self->" + f["name"] + ") {", file=body)
    if f["element"] == "unsigned char" or f["element"] == "uchar":
        pass
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        pass
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        pass
    else:
        print("for (ulong i = 0; i < " + length + "; ++i)", file=body)
        print("    " + n + "_" + f["element"] + "_destroy(self->" + f["name"] + " + i,  freef, freef_arg);", file=body)
    print("freef(freef_arg, self->" + f["name"] + ");", file=body)
    print("self->" + f["name"] + " = NULL;", file=body)
    print("}", file=body)

def do_option_body_destroy(n, f):
    print("if (NULL != self->" + f["name"] + ") {", file=body)
    if f["element"] == "ulong" or f["element"] == "unsigned long":
        pass
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        pass
    else:
        print("    " + n + "_" + f["element"] + "_destroy(self->" + f["name"] + ",  freef, freef_arg);", file=body)

    print("freef(freef_arg, self->" + f["name"] + ");", file=body)
    print("self->" + f["name"] + " = NULL;", file=body)
    print("}", file=body)

def do_pass():
    pass

fields_body_vector_walk = {
    "double" :            lambda n, f: print("  fun(self->" + f["name"] + " + i, \"" + f["name"] + "\", 5, \"double\", level + 1);", file=body),
    "long" :              lambda n, f: print("  fun(self->" + f["name"] + " + i, \"" + f["name"] + "\", 6, \"long\", level + 1);", file=body),
    "uint" :              lambda n, f: print("  fun(self->" + f["name"] + " + i, \"" + f["name"] + "\", 7, \"uint\", level + 1);", file=body),
    "uint128" :           lambda n, f: print("  fun(self->" + f["name"] + " + i, \"" + f["name"] + "\", 8, \"uint128\", level + 1);", file=body),
    "unsigned long" :     lambda n, f: print("  fun(self->" + f["name"] + " + i, \"" + f["name"] + "\", 11, \"ulong\", level + 1);", file=body),
    "ushort" :            lambda n, f: print("  fun(self->" + f["name"] + " + i, \"" + f["name"] + "\", 12, \"ushort\", level + 1);", file=body),
}

def do_vector_body_walk(n, f):

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("      fun(self->" + f["name"] + ", \"" + f["name"] + "\", 2, \"" + f["element"] + "\", level + 1);", file=body),
        return
    else:
        print("  if (self->" + f["name"] + "_len != 0) {", file=body)
        print("  fun(NULL, NULL, 30, \""+f["name"]+"\", level++);", file=body)
        print("    for (ulong i = 0; i < self->" + f["name"] + "_len; ++i)", file=body)

    if f["element"] in fields_body_vector_walk:
        fields_body_vector_walk[f["element"]](namespace, f)
    else:
        print("      " + n + "_" + f["element"] + "_walk(self->" + f["name"] + " + i, fun, \"" + f["element"] + "\", level + 1);", file=body)

    print("  fun(NULL, NULL, 31, \""+f["name"]+"\", --level);", file=body)
    print("  }", file=body)

def do_vector_dynamic_body_walk(n, f):
    print("  fun(NULL, NULL, 30, \""+f["name"]+"\", level++);", file=body)
    print("    for (ulong i = 0; i < self->" + f["name"] + ".cnt; ++i)", file=body)

    if f["element"] == "unsigned char" or f["element"] == "uchar":
        print("; //fd_bincode_bytes_walk(&self->" + f["name"] + ".elems[i], 1, data);", file=body)
    elif f["element"] == "ulong" or f["element"] == "unsigned long":
        print("; //fd_bincode_uint64_walk(&self->" + f["name"] + ".elems[i], data);", file=body)
    elif f["element"] == "uint" or f["element"] == "unsigned int":
        print("; //fd_bincode_uint32_walk(&self->" + f["name"] + ".elems[i], data);", file=body)
    else:
        print("      " + n + "_" + f["element"] + "_walk(&self->" + f["name"] + ".elems[i], fun, \"" + f["name"] + "\", level + 1);", file=body)
    print("  fun(NULL, NULL, 31, \""+f["name"]+"\", --level);", file=body)

def do_map_body_walk(n, f):
    print("  //fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 17, \"map\");", file=body),

#    element_type = vector_dynamic_elem_type(n, f)
#    mapname = element_type + "_map"
#    nodename = element_type + "_mapnode_t"
#    
#    if "modifier" in f and f["modifier"] == "compact":
#        print("  ushort " + f["name"] + "_len = (ushort)" + mapname + "_size(self->" + f["name"] + "_pool, self->" + f["name"] + "_root);", file=body)
#        print("  fd_walk_short_u16(&" + f["name"] + "_len, data);", file=body)
#    else:
#        print("  ulong " + f["name"] + "_len = " + mapname + "_size(self->" + f["name"] + "_pool, self->" + f["name"] + "_root);", file=body)
#        print("  fd_bincode_uint64_walk(&" + f["name"] + "_len, data);", file=body)
#    print("  for ( " + nodename + "* n = " + mapname + "_minimum(self->" + f["name"] + "_pool, self->" + f["name"] + "_root); n; n = " + mapname + "_successor(self->" + f["name"] + "_pool, n) ) {", file=body);
#    print("      " + n + "_" + f["element"] + "_walk(&n->elem, data);", file=body)
#    print("  }", file=body)
        
def do_array_body_walk(n, f):
    print(" //  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 15, \"array\");", file=body),
#    length = f["length"]
#
#    if f["element"] == "unsigned char" or f["element"] == "uchar":
#        pass
#    elif f["element"] == "ulong" or f["element"] == "unsigned long":
#        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
#    elif f["element"] == "uint" or f["element"] == "unsigned int":
#        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
#    else:
#        print("    for (ulong i = 0; i < " + length + "; ++i)", file=body)
#
#    if f["element"] == "unsigned char" or f["element"] == "uchar":
#        print("fd_bincode_bytes_walk(self->" + f["name"] + ", " + length + ", data);", file=body)
#    elif f["element"] == "ulong" or f["element"] == "unsigned long":
#        print("fd_bincode_uint64_walk(self->" + f["name"] + " + i, data);", file=body)
#    elif f["element"] == "uint" or f["element"] == "unsigned int":
#        print("fd_bincode_uint32_walk(self->" + f["name"] + " + i, data);", file=body)
#    else:
#        print("      " + n + "_" + f["element"] + "_walk(self->" + f["name"] + " + i, data);", file=body)

fields_body_option_walk = {
    "char" :              lambda n, f: print("  //fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 1, \"char\", level + 1);", file=body),
    "char*" :             lambda n, f: print("  //fun(self->" + f["name"] + ", \"" + f["name"] + "\", 2, \"char*\", level + 1);", file=body),
    "char[32]" :          lambda n, f: print("  //fun(self->" + f["name"] + ", \"" + f["name"] + "\", 3, \"char[32]\", level + 1);", file=body),
    "char[7]" :           lambda n, f: print("  //fun(self->" + f["name"] + ", \"" + f["name"] + "\", 4, \"char[7]\", level + 1);", file=body),
    "double" :            lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 5, \"double\", level + 1);", file=body),
    "long" :              lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 6, \"long\", level + 1);", file=body),
    "uint" :              lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 7, \"uint\", level + 1);", file=body),
    "uint128" :           lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 8, \"uint128\", level + 1);", file=body),
    "unsigned char" :     lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 9, \"uchar\", level + 1);", file=body),
    "unsigned char[32]" : lambda n, f: print("  //fun(self->" + f["name"] + ", \"" + f["name"] + "\", 10, \"uchar[32]\", level + 1);", file=body),
    "unsigned long" :     lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 11, \"ulong\", level + 1);", file=body),
    "ushort" :            lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 12, \"ushort\", level + 1);", file=body),
}

def do_option_body_walk(n, f):
    if f["element"] in fields_body_option_walk:
        fields_body_option_walk[f["element"]](namespace, f)
    else:
        print(" // fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 16, \"option\", level + 1);", file=body),

fields_body_walk = {
    "char" :              lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 1, \"char\", level + 1);", file=body),
    "char*" :             lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 2, \"char*\", level + 1);", file=body),
    "char[32]" :          lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 3, \"char[32]\", level + 1);", file=body),
    "char[7]" :           lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 4, \"char[7]\", level + 1);", file=body),
    "double" :            lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 5, \"double\", level + 1);", file=body),
    "long" :              lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 6, \"long\", level + 1);", file=body),
    "uint" :              lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 7, \"uint\", level + 1);", file=body),
    "uint128" :           lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 8, \"uint128\", level + 1);", file=body),
    "unsigned char" :     lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 9, \"uchar\", level + 1);", file=body),
    "unsigned char[32]" : lambda n, f: print("  fun(self->" + f["name"] + ", \"" + f["name"] + "\", 10, \"uchar[32]\", level + 1);", file=body),
    "unsigned long" :     lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 11, \"ulong\", level + 1);", file=body),
    "ushort" :            lambda n, f: print("  fun(&self->" + f["name"] + ", \"" + f["name"] + "\", 12, \"ushort\", level + 1);", file=body),
    "vector" :            lambda n, f: do_vector_body_walk(n, f),
    "vector_dynamic" :    lambda n, f: do_vector_dynamic_body_walk(n, f),
    "array" :             lambda n, f: do_array_body_walk(n, f),
    "option" :            lambda n, f: do_option_body_walk(n, f),
    "map" :               lambda n, f: do_map_body_walk(n, f),
}

fields_body_destroy = {
    "char" :              lambda n, f: do_pass(),
    "char*" :             lambda n, f: print("if (NULL != self->" + f["name"] + ") {\nfreef(freef_arg, self->" + f["name"] + ");\nself->" + f["name"] + " = NULL;}", file=body),
    "char[32]" :          lambda n, f: do_pass(),
    "char[7]" :           lambda n, f: do_pass(),
    "double" :            lambda n, f: do_pass(),
    "long" :              lambda n, f: do_pass(),
    "uint" :              lambda n, f: do_pass(),
    "uint128" :           lambda n, f: do_pass(),
    "unsigned char" :     lambda n, f: do_pass(),
    "unsigned char[32]" : lambda n, f: do_pass(),
    "unsigned long" :     lambda n, f: do_pass(),
    "ushort" :            lambda n, f: do_pass(),
    "vector" :            lambda n, f: do_vector_body_destroy(n, f),
    "vector_dynamic" :    lambda n, f: do_vector_dynamic_body_destroy(n, f),
    "array" :             lambda n, f: do_array_body_destroy(n, f),
    "option" :            lambda n, f: do_option_body_destroy(n, f),
    "map" :               lambda n, f: do_map_body_destroy(n, f),
}

# Map different names for the same times into how firedancer knows them
for entry in entries:
    if "fields" in entry:
      for f in entry["fields"]:
          if f["type"] in type_map:
              f["type"] = type_map[f["type"]]
          if "element" in f:
              if f["element"] in type_map:
                  f["element"] = type_map[f["element"]]
    if "variants" in entry:
      for v in entry["variants"]:
          if "type" in v and v["type"] in type_map:
              v["type"] = type_map[v["type"]]

# Generate one instance of the fd_vector.h template for each unique element type.
vector_dynamic_element_types = set()

map_element_types = dict()

for entry in entries:
    # Create the dynamic vector types needed for this entry
    if "fields" in entry:
      for f in entry["fields"]:
          if f["type"] == "vector_dynamic":
              element_type = vector_dynamic_elem_type(namespace, f)
              if element_type in vector_dynamic_element_types:
                  continue

              print("#define VECT_NAME " + vector_dynamic_prefix(namespace, f), file=header)
              print("#define VECT_ELEMENT " + element_type, file=header)
              print("#include \"fd_vector.h\"", file=header)
              print("#undef VECT_NAME", file=header)
              print("#undef VECT_ELEMENT\n", file=header)

              vector_dynamic_element_types.add(element_type)

          if f["type"] == "map":
            element_type = vector_dynamic_elem_type(namespace, f)
            if element_type in map_element_types:
                continue
            
            mapname = element_type + "_map"
            nodename = element_type + "_mapnode"
            print(f"typedef struct {nodename} {nodename}_t;", file=header)
            print(f"#define REDBLK_T {nodename}_t", file=header)
            print(f"#define REDBLK_NAME {mapname}", file=header)
            print(f"#include \"../../util/tmpl/fd_redblack.h\"", file=header)
            print(f"#undef REDBLK_T", file=header)
            print(f"#undef REDBLK_NAME", file=header)
            print(f"struct {nodename} {{", file=header)
            print(f"    {element_type} elem;", file=header)
            print(f"    redblack_member_t redblack;", file=header)
            print(f"}};", file=header)
            print(f"typedef struct {nodename} {nodename}_t;", file=header)

            map_element_types[element_type] = f["key"]

    if "comment" in entry and "type" in entry and entry["type"] != "enum":
      print("/* " + entry["comment"] + " */", file=header)

    n = namespace + "_" + entry["name"]
    
    if "attribute" in entry:
        a = "__attribute__" + entry["attribute"] + " "
    else:
        a = ""

    if "type" in entry and entry["type"] == "struct":
      print("struct "+ a + n + " {", file=header)
      for f in entry["fields"]:
          if f["type"] in fields_header:
              fields_header[f["type"]](namespace, f)
          else:
               print("  " + namespace + "_" + f["type"] + "_t " + f["name"] + ";", file=header)

      print("};", file=header)
      print("typedef struct " + n + " " + n + "_t;", file=header)

    elif "type" in entry and entry["type"] == "enum":
      print("union "+ a + n + "_inner {", file=header)
      
      empty = True
      for v in entry["variants"]:
          if "type" in v:
            empty = False
            if v["type"] in fields_header:
                fields_header[v["type"]](namespace, v)
            else:
                print("  " + namespace + "_" + v["type"] + "_t " + v["name"] + ";", file=header)
      if empty:
          print("  uchar nonempty; /* Hack to support enums with no inner structures */ ", file=header)

      print("};", file=header)
      print("typedef union " + n + "_inner " + n + "_inner_t;\n", file=header)

      if "comment" in entry:
        print("/* " + entry["comment"] + " */", file=header)

      print("struct "+ a + n + " {", file=header)
      print("  uint discriminant;", file=header)
      print("  " + n + "_inner_t inner;", file=header)
      print("};", file=header)
      print("typedef struct " + n + " " + n + "_t;", file=header)

    print("#define " + n.upper() + "_FOOTPRINT sizeof(" + n+"_t)", file=header)
    print("#define " + n.upper() + "_ALIGN (8UL)", file=header)
    print("", file=header)

print("", file=header)
print("FD_PROTOTYPES_BEGIN", file=header)
print("", file=header)

for entry in entries:
    if "attribute" in entry:
        continue
    n = namespace + "_" + entry["name"]

    print("void " + n + "_decode(" + n + "_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg);", file=header)
    print("void " + n + "_encode(" + n + "_t* self, void const** data);", file=header)
    print("void " + n + "_destroy(" + n + "_t* self, fd_free_fun_t freef, void* freef_arg);", file=header)
    print("void " + n + "_copy_to(" + n + "_t* to, " + n + "_t* from, fd_alloc_fun_t freef, void* allocf_arg);", file=header)
    print("void " + n + "_walk(" + n + "_t* self, fd_walk_fun_t fun, const char *name, int level);", file=header)
    print("ulong " + n + "_size(" + n + "_t* self);", file=header)
    print("", file=header)

    if entry["type"] == "enum":
        for i, v in enumerate(entry["variants"]):
            print("uchar " + n + "_is_"+ v["name"] + "(" + n + "_t* self);", file=header)
            print("uchar " + n + "_is_"+ v["name"] + "(" + n + "_t* self) {", file=body)
            print("  return self->discriminant == " + str(i) + ";", file=body)
            print("}", file=body)
        print("", file=header)

    if entry["type"] == "enum":
        print("void " + n + "_inner_decode(" + n + "_inner_t* self, uint discriminant, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {", file=body)
        for i, v in enumerate(entry["variants"]):
            if "type" in v:
              print("  if (discriminant == "+ str(i) +") {", file=body)
              if v["type"] in fields_body_decode:
                  fields_body_decode[v["type"]](namespace, v)
              else:
                  print("  " + namespace + "_" + v["type"] + "_decode(&self->" + v["name"] + ", data, dataend, allocf, allocf_arg);", file=body)
              print("   }", file=body)

        print("}", file=body)

        print("void " + n + "_decode(" + n + "_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {", file=body)
        print("  fd_bincode_uint32_decode(&self->discriminant, data, dataend);", file=body)
        print("  " + namespace + "_" + entry["name"] + "_inner_decode(&self->inner" + ", self->discriminant, data, dataend, allocf, allocf_arg);", file=body)
        print("}", file=body)
    else:
      print("void " + n + "_decode(" + n + "_t* self, void const** data, void const* dataend, fd_alloc_fun_t allocf, void* allocf_arg) {", file=body)
      for f in entry["fields"]:
          if f["type"] in fields_body_decode:
              fields_body_decode[f["type"]](namespace, f)
          else:
              print("  " + namespace + "_" + f["type"] + "_decode(&self->" + f["name"] + ", data, dataend, allocf, allocf_arg);", file=body)
      print("}", file=body)
      
    
    if entry["type"] == "enum":
      print("void " + n + "_inner_destroy(" + n + "_inner_t* self, uint discriminant, fd_free_fun_t freef, void* freef_arg) {", file=body)
      for i, v in enumerate(entry["variants"]):
          if "type" in v:
            print("  if (discriminant == "+ str(i) +") {", file=body)
            if v["type"] in fields_body_destroy:
                 fields_body_destroy[v["type"]](namespace, v)
            else:
                print("  " + namespace + "_" + v["type"] + "_destroy(&self->" + v["name"] + ", freef, freef_arg);", file=body)
            print("   }", file=body)
      print("}", file=body)

      print("void " + n + "_destroy(" + n + "_t* self, fd_free_fun_t freef, void* freef_arg) {", file=body)
      print("  " + namespace + "_" + entry["name"] + "_inner_destroy(&self->inner" + ", self->discriminant, freef, freef_arg);", file=body)
      print("}", file=body)
    else:
      print("void " + n + "_destroy(" + n + "_t* self, fd_free_fun_t freef, void* freef_arg) {", file=body)
      for f in entry["fields"]:
          if f["type"] in fields_body_destroy:
              fields_body_destroy[f["type"]](namespace, f)
          else:
              print("  " + namespace + "_" + f["type"] + "_destroy(&self->" + f["name"] + ", freef, freef_arg);", file=body)
      print("}", file=body)
    print("", file=body)

    print("void " + n + "_walk(" + n + "_t* self, fd_walk_fun_t fun, const char *name, int level) {", file=body)
    print("  fun(self, name, 32, \""+n+"\", level++);", file=body)

    if entry["type"] == "enum":
        print(" // enum " + namespace + "_" + f["type"] + "_walk(&self->" + f["name"] + ", fun, \"" + f["name"] + "\", level + 1);", file=body)
    else:
        for f in entry["fields"]:
            if f["type"] in fields_body_walk:
                fields_body_walk[f["type"]](namespace, f)
            else:
                print("  " + namespace + "_" + f["type"] + "_walk(&self->" + f["name"] + ", fun, \"" + f["name"] + "\", level + 1);", file=body)

    print("  fun(self, name, 33, \""+n+"\", --level);", file=body)
    print("}", file=body)

    print("void " + n + "_copy_to(" + n + "_t* to, " + n + "_t* from, fd_alloc_fun_t allocf, void* allocf_arg) {", file=body)

    print("  unsigned char *enc = fd_alloca( 1, " + n + "_size(from) );", file=body)
    print("  void const *ptr = (void const *) enc;", file=body)
    print("  " + n + "_encode( from, &ptr );", file=body)
    print("  void *input = (void *) enc;", file=body)
    print("  " + n + "_decode( to, (const void **) &input, ptr, allocf, allocf_arg );", file=body)
    print("}", file=body)
    print("ulong " + n + "_size(" + n + "_t* self) {", file=body)
    
    if entry["type"] == "enum":
      print("  ulong size = 0;", file=body)
      print("  size += sizeof(uint);", file=body)
      for i, v in enumerate(entry["variants"]):
          if "type" in v:
            print("  if (self->discriminant == "+ str(i) +") {", file=body)
            if v["type"] in fields_body_size:
                 fields_body_size[v["type"]](namespace, v)
            else:
                print("  size += " + namespace + "_" + v["type"] + "_size(&self->inner." + v["name"] + ");", file=body)
            print("   }", file=body)

    else:
      print("  ulong size = 0;", file=body)
      for f in entry["fields"]:
          if f["type"] in fields_body_size:
              fields_body_size[f["type"]](namespace, f)
          else:
              print("  size += " + namespace + "_" + f["type"] + "_size(&self->" + f["name"] + ");", file=body)

    print("  return size;", file=body)
    print("}", file=body)
    print("", file=body)
    if entry["type"] == "enum":
        print("void " + n + "_inner_encode(" + n + "_inner_t* self, uint discriminant, void const** data) {", file=body)
        for i, v in enumerate(entry["variants"]):
            if "type" in v:
              print("  if (discriminant == "+ str(i) +") {", file=body)
              if v["type"] in fields_body_encode:
                  fields_body_encode[v["type"]](namespace, v)
              else:
                  print("  " + namespace + "_" + v["type"] + "_encode(&self->" + v["name"] + ", data);", file=body)
              print("   }", file=body)
        print("}", file=body)

        print("void " + n + "_encode(" + n + "_t* self, void const** data) {", file=body)
        print("  fd_bincode_uint32_encode(&self->discriminant, data);", file=body)
        print("  " + namespace + "_" + entry["name"] + "_inner_encode(&self->inner" + ", self->discriminant, data);", file=body)
        print("}", file=body)
    else:
      print("void " + n + "_encode(" + n + "_t* self, void const** data) {", file=body)
      if "fields" in entry:
        for f in entry["fields"]:
            if f["type"] in fields_body_encode:
                fields_body_encode[f["type"]](namespace, f)
            else:
                print("  " + namespace + "_" + f["type"] + "_encode(&self->" + f["name"] + ", data);", file=body)
      print("}", file=body)
    print("", file=body)

for (element_type,key) in map_element_types.items():
    mapname = element_type + "_map"
    nodename = element_type + "_mapnode_t"
    print(f"#define REDBLK_T {nodename}", file=body)
    print(f"#define REDBLK_NAME {mapname}", file=body)
    print(f"#include \"../../util/tmpl/fd_redblack.c\"", file=body)
    print(f"long {mapname}_compare({nodename} * left, {nodename} * right) {{", file=body)
    print(f"  return (long)(left->elem.{key} - right->elem.{key});", file=body)
    print(f"}}", file=body)
    
print("FD_PROTOTYPES_END", file=header)
print("", file=header)
print("#endif // HEADER_" + json_object["name"].upper(), file=header)
