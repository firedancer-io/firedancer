# Sadly, the code this produces is too gross to acutally use, but it's
# still useful to diff

# Compile agave with split-debuginfo=off, then use `ar` to extract the
# object files from the .a file

GLOB_DIR = "/tmp/*agave_validator*.o"

from elftools import *
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo
import glob
import re

base_type = None
for opath in glob.glob(GLOB_DIR):
    with open(opath, 'rb') as f:
        elffile = ELFFile(f)
        if elffile.has_dwarf_info():
            dwarf = elffile.get_dwarf_info()
            found = False
            for cu in dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag == 'DW_TAG_structure_type' and b'RuntimeTransaction' in die.attributes['DW_AT_name'].value:
                        base_type = die
                if base_type:
                    break
            if base_type:
                break


offset_to_typename = {}
offset_to_struct_members = {}
offset_union_info = {}
offset_to_type_sz = {}

visited = set()
bfs = set([base_type.offset])
bfs_next = set()

primitive_ints = {(7,1): 'uchar', (5,1): 'schar', (7,2): 'ushort', (5,2): 'short', (7,4): 'uint', (5,4): 'int', (7,8): 'ulong', (5,8):'long', (2,1): 'uchar'}

while bfs:
    for offset in bfs:
        visited.add(offset)

        die = cu.get_DIE_from_refaddr(offset)

        if die.tag == 'DW_TAG_base_type':
            offset_to_typename[offset] = primitive_ints[ die.attributes['DW_AT_encoding'].value,  die.attributes['DW_AT_byte_size'].value]
            continue
        if die.tag == 'DW_TAG_array_type':
            offset_to_typename[offset] = cu.get_DIE_from_refaddr(die.attributes['DW_AT_type'].value).attributes['DW_AT_name'].value + b'[' + str(list(die.iter_children())[0].attributes['DW_AT_count'].value).encode('ascii') + b']'
            bfs_next.add(die.attributes['DW_AT_type'].value)
            continue
        if die.tag == 'DW_TAG_pointer_type':
            offset_to_typename[offset] = cu.get_DIE_from_refaddr(die.attributes['DW_AT_type'].value).attributes['DW_AT_name'].value + b'*'
            bfs_next.add(die.attributes['DW_AT_type'].value)
            continue


        offset_to_typename[offset] = die.attributes['DW_AT_name'].value
        offset_to_struct_members[offset] = list()
        offset_union_info[offset] = [None]
        offset_to_type_sz[offset] = (die.attributes['DW_AT_byte_size'].value, die.attributes['DW_AT_alignment'].value)

        # print( die.attributes['DW_AT_name'].value, die.tag )
        is_union = 0
        for child in die.iter_children():
            if child.tag == 'DW_TAG_template_type_param':
                bfs_next.add(child.attributes['DW_AT_type'].value)
            elif child.tag == 'DW_TAG_subprogram' or child.tag == 'DW_TAG_formal_parameter':
                continue
            elif child.tag == 'DW_TAG_member':
                assert is_union <= 0
                is_union = -1
                offset_to_struct_members[offset].append( (
                    child.attributes['DW_AT_name'].value,
                    child.attributes['DW_AT_type'].value,
                    child.attributes['DW_AT_alignment'].value,
                    child.attributes['DW_AT_data_member_location'].value ))
                bfs_next.add(child.attributes['DW_AT_type'].value)
            elif child.tag == 'DW_TAG_variant_part':
                assert is_union >= 0
                is_union = 1
                c2 = cu.get_DIE_from_refaddr(child.attributes['DW_AT_discr'].value)
                offset_union_info[offset][0] = ( b'discr',
                    c2.attributes['DW_AT_type'].value,
                    c2.attributes['DW_AT_alignment'].value,
                    c2.attributes['DW_AT_data_member_location'].value,
                    None)
                bfs_next.add(c2.attributes['DW_AT_type'].value)

                union_child_info = {}
                for c2 in child.iter_children():
                    if c2.tag == 'DW_TAG_variant':
                        if 'DW_AT_discr_value' in c2.attributes:
                            discr = c2.attributes['DW_AT_discr_value'].value
                        else:
                            discr = None
                        union_child_info[ list(c2.iter_children())[0].attributes['DW_AT_name'].value] = discr
            elif child.tag == 'DW_TAG_structure_type':
                assert is_union >= 0
                is_union = 1
                j = 0
                for c3 in child.iter_children():
                    if c3.tag == 'DW_TAG_template_type_param':
                        continue
                    j += 1
                    offset_union_info[offset].append( (
                        child.attributes['DW_AT_name'].value,
                        c3.attributes['DW_AT_type'].value,
                        child.attributes['DW_AT_alignment'].value,
                        c3.attributes['DW_AT_data_member_location'].value,
                        # child.attributes['DW_AT_byte_size'].value,
                        union_child_info[child.attributes['DW_AT_name'].value] ))
                    bfs_next.add(c3.attributes['DW_AT_type'].value)
                assert j<=1
            else:
                print(child)
                raise child
    bfs = bfs_next - visited
    bfs_next = set()

def c_escape(t, istype):
    if str(t)==t:
        return t
    start = t.decode('ascii')
    start = re.sub('[^0-9a-zA-Z]', '_', start)
    if istype:
        start += "_t"
    return start

for offset, t in offset_to_typename.items():
    if str(t)==t: continue
    if not offset in offset_union_info:
        print(f"\n/* Skipping {t} */\n")
        continue

    if len(offset_union_info[offset])>1:
        print(f"/* t.decode('ascii') */")
        print(f"typedef union {{")
        for name, t_i, align, off, discr in offset_union_info[offset]:
            if discr:
                print(f"\t/* when discr=={discr} */")
            elif name!=b"discr":
                print(f"\t/* else */")
            if off>0:
                print(f"\tstruct {{ uchar _padding[{off}];")
            print(f"\t{c_escape(offset_to_typename[t_i],1)} {c_escape(name,0)};")
            if off>0: print("\t};")
        print(f"}} {c_escape(t,1)};")
        print(f"FD_STATIC_ASSERT( sizeof({c_escape(t,1)})=={offset_to_type_sz[offset][0]}UL, bank_abi );")
        print(f"FD_STATIC_ASSERT( alignof({c_escape(t,1)})=={offset_to_type_sz[offset][1]}UL, bank_abi );")
        print()
        continue

    print(f"/* t.decode('ascii') */")
    print(f"typedef struct {{")
    for name, t_i, al, off in sorted(offset_to_struct_members[offset], key=lambda r: r[3]):
        print(f"\t{c_escape(offset_to_typename[t_i],1)} {c_escape(name,0)};")
    print(f"}} {c_escape(t,1)};")
    for name, t_i, al, off in sorted(offset_to_struct_members[offset], key=lambda r: r[3]):
        print(f"FD_STATIC_ASSERT( offsetof({c_escape(t,1)}, {c_escape(name,0)})=={off}, bank_abi );")
    print(f"FD_STATIC_ASSERT( sizeof({c_escape(t,1)})=={offset_to_type_sz[offset][0]}UL, bank_abi );")
    print(f"FD_STATIC_ASSERT( alignof({c_escape(t,1)})=={offset_to_type_sz[offset][1]}UL, bank_abi );")
    print()
