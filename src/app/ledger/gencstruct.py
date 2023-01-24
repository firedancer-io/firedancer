#!/jump/software/rhel8/Python-3.10/bin/python3
#
# Convert a json dump of debug info from a rust executable to C structures
#
#  /home/jsiegel/repos/dwarf2json/dwarf2json  linux --elf ~/repos/solana/target/debug/solana-ledger-tool > ~/output.json
#
#  ./gencstruct.py --json ~jsiegel/output.json --roottype BankFieldsToDeserialize --output x.h
#

import sys
import argparse
import json

parser = argparse.ArgumentParser(prog='getcstruct',description='convert rust debug info to C structures')
parser.add_argument('-j', '--json', help='Input json', default=None)
parser.add_argument('-r', '--roottype', help='Root data type', default=None)
parser.add_argument('-o', '--output', help='Output C header', default=None)
args = parser.parse_args()

with open(args.json, 'r') as fd:
    data = json.load(fd)

base_type_map = {
    'bool' : 'char',
    'f64' : 'double',
    'i64' : 'long',
    'u128' : 'uint128',
    'u32' : 'unsigned int',
    'u64' : 'unsigned long',
    'u8' : 'unsigned char',
    'usize' : 'size_t',
}

user_types = data['user_types']
if args.roottype not in user_types:
    raise Exception(f'cannot find {args.roottype} in user_types')
root = user_types[args.roottype]

alltypes = { }
depends = { }

def discover_types(name, value):
    if name in alltypes:
        return

    if name[:8] == 'HashMap<':
        # Special hackery for hash tables
        comma1 = name.find(',')
        if name[comma1+2] == '(':
            comma2 = name.find(',', name.find(')', comma1+1))
        else:
            comma2 = name.find(',', comma1+1)
        keytype = name[8:comma1].strip()
        valtype = name[comma1+1:comma2].strip()
        user_types['HashMapEntry<' + name[8:]] = {
            'fields': {
                'key': {'type': {'kind': ('base' if (keytype in base_type_map) else 'struct'), 'name': keytype}, 'offset': 0, 'order': 0},
                'value': {'type': {'kind': ('base' if (valtype in base_type_map) else 'struct'), 'name': valtype}, 'offset': 1, 'order': 1}},
            'kind': 'struct'}
        value = {
            'fields': {
                'len': {'type': {'kind': 'base', 'name': 'usize'}, 'offset': 0, 'order': 0},
                'table': {'type': {'kind': 'pointer', 'subtype': {'kind': 'struct', 'name': ('HashMapEntry<' + name[8:])}}, 'offset': 1, 'order': 1}},
            'kind': 'struct'}

    if name[:7] == 'Option<':
        # Special hackery for optional values
        valtype = name[7:-1].strip()
        value = {
            'fields': {
                'ptr': {'type': {'kind': 'pointer', 'subtype': {
                    'kind': ('base' if (valtype in base_type_map) else 'struct'), 'name': valtype}},
                        'offset': 1, 'order': 1}},
            'kind': 'struct'}

    if name[:4] == 'Vec<':
        # Peel away layers of vector crap
        a = value['fields']['buf']['type']['name']
        b = user_types[a] # RawVec
        c = b['fields']['ptr']['type']['name']
        d = user_types[c] # Unique
        e = d['fields']['pointer']['type']['name']
        f = user_types[e] # NonNull
        g = f['fields']['pointer']['type']['subtype']['name']
        value = {
            'fields': {
                'len': {'type': {'kind': 'base', 'name': 'usize'}, 'offset': 0, 'order': 0},
                'list': {'type': {'kind': 'pointer', 'subtype': {
                    'kind': ('base' if (g in base_type_map) else 'struct'), 'name': g}},
                         'offset': 1, 'order': 1}},
            'kind': 'struct'}
    
    alltypes[name] = value
    depends[name] = [ ]

    kind = value['kind']
    if kind == 'struct':
        for fname, fvalue in list(value['fields'].items()):
            ftype = fvalue['type']
            while True:
                fkind = ftype['kind']
                if fkind == 'base':
                    break
                
                elif fkind == 'struct':
                    name2 = ftype['name']
                    if name2 not in user_types:
                        print(f'missing type {name2}')
                        del value['fields'][fname]
                        break
                    discover_types(name2, user_types[name2])
                    depends[name].append(name2)
                    break
                    
                elif fkind == 'pointer' or fkind == 'array':
                    ftype = ftype['subtype']
                    # Loop and try again
                    continue

                else:
                    print(fvalue)
                    raise Exception(f'unknown kind: {fkind}')

    else:
        print(value)
        raise Exception(f'unknown kind: {kind}')

discover_types(args.roottype, root)

def mangle_name(name):
    for c in name:
        if (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_':
            continue
        hash1 = hash(name)
        if hash1 < 0:
            hash1 = -hash1
        hash2 = hash(name + ' ')
        if hash2 < 0:
            hash2 = -hash2
        return f'T_{hash1:x}_{hash2:x}'
    return name

def field_decl(fname, ftype):
    fkind = ftype['kind']
    if fkind == 'base':
        return base_type_map[ftype['name']] + ' ' + fname
    
    elif fkind == 'struct':
        return 'struct ' + mangle_name(ftype['name']) + ' ' + fname
    
    elif fkind == 'pointer':
        s = field_decl(fname, ftype['subtype'])
        i = s.rfind(' ')
        return s[0:i] + '*' + s[i:]
        
    elif fkind == 'array':
        s = field_decl(fname, ftype['subtype'])
        return s + '[' + str(ftype['count']) + ']'

done = set()
    
def translate_type(fd, name):
    if name in done:
        return
    done.add(name)

    # Depth-first order
    for d in depends[name]:
        translate_type(fd, d)
    
    value = alltypes[name]
    fd.write(f'// {name}\n')
    fd.write(f'// {value}\n')
    fd.write(f'struct {mangle_name(name)} {{\n')

    assert value['kind'] == 'struct'
    
    for fname, fvalue in sorted(value['fields'].items(), key=lambda item: item[1]['order']):
        fd.write('  {};\n'.format(field_decl(fname, fvalue['type'])))

    fd.write('};\n\n')

with open(args.output, 'w') as fd:
    for name in alltypes:
        translate_type(fd, name)
