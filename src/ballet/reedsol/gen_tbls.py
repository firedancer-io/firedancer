import galois
import numpy as np
import struct

out_dir = "constants/"

GF=galois.GF(2**8)
data_shreds  = 32
total_shreds = 64
rust_matrix1 =  GF([ [ GF(i)**j for j in range(0,data_shreds)] for i in range(0,total_shreds)])
full_matrix = rust_matrix1[data_shreds:,:] @ np.linalg.inv(rust_matrix1[:data_shreds,:])

# Write out the GFNI constant table
def gen_vgf2p8affineqb_matrix(c):
    out_t = []
    for j in range(8):
        out_t.append(c * GF(1<<j))
    out_w = 0
    for i in range(64):
        if out_t[i%8] & (1<<(7-i//8)):
            out_w |= (1 << i)
    return out_w
bytes_to_multiply = range(256)
encoded = []
for b in bytes_to_multiply:
    intv = gen_vgf2p8affineqb_matrix(GF(b))
    encoded.append(struct.pack('<Q', intv)*4)
with open(out_dir + 'gfni_constants.bin', 'wb') as bin_file:
    bin_file.write(b''.join(encoded))

# Write out the AVX constant table
shuffle_idx = np.tile(np.arange(0, 16, dtype=np.int32), (1,2))
encoded = GF(np.reshape(np.arange(0, 256, dtype=np.int32), (256,1))) @ GF(shuffle_idx)
with open(out_dir + 'avx2_constants.bin', 'wb') as bin_file:
    bin_file.write(encoded.tobytes())
    bin_file.write((GF(16) * encoded).tobytes())

# Write out the generic constant tables
# We want to be able to do multiplication with just 3 loads and one add,
# covering all the special cases: 
# 1. multiplication by 0 should automatically give 0, so we map log[0] =
#    -256, then invlog[x] = 0 for x in [-512, 0).
# 2. When the sum of the logs is greater than 255, we don't want to do
#    the mod, so we map invlog[x] = invlog[x-255] for x in [255, 512).
logtbl = [0]*256
invlogtbl = [0]*1024 # indx offset by 512
pe = GF.primitive_element
logtbl[0] = -256
for j in range(255):
    logtbl[ int(pe**j) ] = j
    invlogtbl[ 512+j ] = int(pe**j)
for j in range(255,512):
    invlogtbl[ 512+j ] = int(pe**j)
gf_log = np.vectorize( lambda v: logtbl[v] )
log_matrix = GF(gf_log(full_matrix))
with open(out_dir + 'generic_constants.bin', 'wb') as bin_file:
    bin_file.write(struct.pack('<256h', *logtbl))
    bin_file.write(struct.pack('<1024B', *invlogtbl))
    bin_file.write(bytes(full_matrix.flatten()))
