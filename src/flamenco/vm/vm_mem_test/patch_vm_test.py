import struct
import sys

in_path = sys.argv[1]
out_path = sys.argv[2]
data = bytearray(open(in_path, "rb").read())
assert data[:6] == b"\x7fELF\x02\x01", "expected ELF64 little-endian"

sh_off, sh_ent_size, sh_num, sh_strndx = struct.unpack_from("<16x2x2x4x8x8xQ4x2x2x2xHHH", data)
# sh_off - section header table file offset
# sh_ent_size - section header table entry size
# sh_num - section header table entry count
# sh_strndx - section header string table index

assert sh_num and sh_strndx < sh_num

string_table_off, string_table_sz = struct.unpack_from("<4x4x8x8xQQ", data, sh_off+sh_strndx*sh_ent_size)
names = data[string_table_off:string_table_off+string_table_sz]

for i in range(sh_num):
    hdr = sh_off + i * sh_ent_size
    name_off = struct.unpack_from("<I", data, hdr)[0]
    name = names[name_off:].split(b"\0", 1)[0]
    if b"fd_vm_mem_test_region" in name:
        struct.pack_into("<Q", data, hdr + 48, 1 << 31)  # sh_addralign

open(out_path, "wb").write(data)
