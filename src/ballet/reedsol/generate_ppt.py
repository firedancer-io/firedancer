import galois
import numpy as np
import numpy.linalg

# file 1: fd_reedsol_ppt.h
header = """/* Note: This file is auto generated. */
#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_ppt_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_ppt_h

#include "fd_reedsol_fft.h"

/* This file implements the Principal Pivot Transform for the Reed
   Solomon FFT operator as described in:
     S. -J. Lin, A. Alloum and T. Al-Naffouri, "Principal pivot
     transforms on radix-2 DFT-type matrices," 2017 IEEE International
     Symposium on Information Theory (ISIT), Aachen, Germany, 2017, pp.
     2358-2362, doi: 10.1109/ISIT.2017.8006951

   The main macro this file provides is FD_REEDSOL_GENERATE_PPT.  The
   rest of this file is auto-generated implementation details.

   When the number of data shreds we have is not a power of 2, the
   approach used in the 32-32 case doesn't apply.  I found the paper
   extending it to the general case uninterpretable.  So we use the
   principal pivot transform as an alternative with similar
   computational complexity.

   The goal of the first step of the 32-32 case is to find a polynomial
   of degree < 32 that interpolates the data shreds.  If we only have k
   data shreds, where k<32, then instead we need a polynomial P of
   degree <k that passes through the k data shreds that we have.  If we
   could somehow determine P(k), P(k+1), ... P(31), then we could just
   use the 32-32 fast case.  The principal pivot transform gives us a
   way to do exactly that.

   In the 32-32 case, we have:
                  ( m_0  )      ( y_0  )
                  ( m_1  )      ( y_1  )
       F^{-1} *   ( ...  )   =  ( ...  )
                  ( m_30 )      ( y_30 )
                  ( m_31 )      ( y_31 )

   where m is in the evaluation domain (i.e. P(i) = m_i) and y is in the
   coefficient domain (coefficients of the special basis elements).
   Now, we don't know the last 32-k elements of the m vector, i.e.

                  ( m_0  )      ( y_0  )
                  ( m_1  )      ( y_1  )
       F^{-1} *   ( ...  )   =  ( ...  )
                  ( ???  )      ( y_30 )
                  ( ???  )      ( y_31 )

   but what we do know is that the last 32-k elements of the y vector
   must be 0 in order for P to have the right order. I.e.

                  ( m_0  )      ( y_0  )
                  ( m_1  )      ( y_1  )
       F^{-1} *   ( ...  )   =  ( ...  )
                  ( ???  )      (   0  )
                  ( ???  )      (   0  )

   The principal pivot transform solves this type of problem, and for
   certain operators F (including the one we care about here) has a
   complexity of O(n log n), where F is an nxn matrix.  To keep
   consistent with the paper, we multiply through by F and name the
   unknowns, actually solving

                  ( y_0  )      ( m_0  )
                  ( y_1  )      ( m_1  )
            F *   ( ...  )   =  ( ...  )
                  (   0  )      ( x_30 )
                  (   0  )      ( x_31 )

   Once we've solved this, x_k gives us P(k), i.e. the first parity
   shred. If we need more than 32-k parity shreds, then we can just use
   the same strategy as the 32-32 case and use the shifted FFT operation
   to go back from the coefficient domain to the evaluation domain with
   an offset of 32, giving us P(32), P(33), ... P(63) cheaply.

   The paper describes a more general case than what we need, since we
   always know the first k elements of the product vector, and not an
   arbitrary subset of them.  This file only implements the specific
   case. */

/* FD_REEDSOL_GENERATE_PPT: Inserts code to compute the principal pivot
   transform of size n (must be a power of 2, currently 16, 32, 64, and
   128 are emitted by the code generator) and when you have k known
   elements of the evaluation domain (i.e. k data shreds).  k must be
   less than n, but the code generator adds the additional restrictions
   that k<=67 and only the smallest n is chosen for each k.
   Additionally, The remaining n arguments should be vector variables of
   type gf_t (which is a typedef for wb_t in the AVX case).  These are
   used as input and output, since there's no other good way to return n
   vector values.  As such, this macro is not robust.

   As explained above, the PPT computes the k non-zero elements of the
   coefficient domain, followed by the first n-k parity elements.  If
   the last n-k return values are replaced with zero, they can then be
   used with FD_REEDSOL_GENERATE_FFT and the appropriate shift to
   compute many more parity elements.  The PPT is computed in a
   vectorized fashion, i.e. the PPT of the ith byte is computed and
   stored in the ith byte of the output for each i independently. */

#define FD_REEDSOL_GENERATE_PPT(n, k, ...) FD_REEDSOL_PPT_IMPL_##n##_##k( __VA_ARGS__ )

/* For n>=32, this header also declares
          void fd_reedsol_ppt_n_k( gf_t *, ... )
   that takes n gf_t elements by reference.  The arguments are used for
   input and output, and it performs the same operation as the similarly
   named macro, but this signature allows the function to be defined in
   a different compilation unit to speed up compile times. */
"""

outf = open('fd_reedsol_ppt.h', "wt")
print(header, file=outf)

GF=galois.GF(2**8)

def reverse_bits(i, l):
    out = 0
    for z in range(l):
        if i & (1<<z):
            out |= 1<<(l-1-z)
    return out

svals = {}
sbar = {}
for j in range(7):
    for x in range(128):
        if j == 0:
            svals[ 0, x ] = GF(x)
        else:
            svals[ j, x ] = svals[ j-1, x ] * svals[ j-1, x ^ (1<<(j-1)) ]
    for x in range(128):
        sbar[ j, x ] = svals[ j, x ] / svals[ j, 1<<j ]

def m_fft( lg_h, beta ):
    h = 2**lg_h
    to_return = []
    for i_round in range(lg_h):
        matrA = np.zeros( (h,h), dtype = np.uint8 )
        matrB = np.zeros( (h,h), dtype = np.uint8 )
        half_len = h//2**(i_round+1)
        for rr in range(2**i_round):
            r = reverse_bits(rr, i_round)
            for j in range(half_len):
                omega_ = j*2**(i_round+1)
                idx = r + omega_
                offset = 2**i_round
                # print(f"Round {i_round} (offset {offset}), idx={idx} (paired with {idx+offset}): j = {j}")
                s = GF(4)
                matrA[ idx,        idx        ] = 1
                matrA[ idx,        idx+offset ] = GF(sbar[i_round, omega_ + beta])
                matrA[ idx+offset, idx+offset ] = 1
                matrB[ idx,        idx        ] = 1
                matrB[ idx+offset, idx        ] = 1
                matrB[ idx+offset, idx+offset ] = 1
        to_return.append(GF(matrB))
        to_return.append(GF(matrA))
    return to_return

def m_ifft( lg_h, beta ):
    h = 2**lg_h
    to_return = []
    for i_round in range(lg_h):
        matrA = np.zeros( (h,h), dtype = np.uint8 )
        matrB = np.zeros( (h,h), dtype = np.uint8 )
        half_len = h//2**(i_round+1)
        for rr in range(2**i_round):
            r = reverse_bits(rr, i_round)
            for j in range(half_len):
                omega_ = j*2**(i_round+1)
                idx = r + omega_
                offset = 2**i_round
                # print(f"Round {i_round} (offset {offset}), idx={idx} (paired with {idx+offset}): j = {j}")
                matrA[ idx+offset, idx        ] = 1
                matrA[ idx+offset, idx+offset ] = 1
                matrA[ idx,        idx        ] = 1
                matrB[ idx,        idx        ] = 1
                matrB[ idx,        idx+offset ] = sbar[i_round, omega_ + beta]
                matrB[ idx+offset, idx+offset ] = 1
        to_return = [ GF(matrB), GF(matrA) ] + to_return
    return to_return

def fft_matrix( lg_h, beta ):
    prod = GF(np.eye(2**lg_h, dtype=int))
    for m in m_fft(lg_h,beta):
        prod =  prod @ GF(m)
    return prod
def ifft_matrix( lg_h, beta ):
    prod = GF(np.eye(2**lg_h, dtype=int))
    for m in m_ifft(lg_h,beta):
        prod =  prod @ GF(m)
    return prod

def Bmatr(lg_sz, shift):
    D = np.linalg.inv(GF(np.block( [
        [ fft_matrix(lg_sz-1,shift), np.zeros((2**(lg_sz-1), 2**(lg_sz-1)), dtype=np.uint8)],
        [np.zeros((2**(lg_sz-1), 2**(lg_sz-1)), dtype=np.uint8), fft_matrix(lg_sz-1,shift+2**(lg_sz-1)) ]] ))
        ) @ fft_matrix(lg_sz,shift)
    return GF(D[(0,2**(lg_sz-1)),:][:,(0,2**(lg_sz-1))])

def principal_pivot_transform_k_no_x(lg_sz, k, alpha_offset):
    n = 2**lg_sz

    # alpha is [0, min(k - alpha_offset, n))
    if n>=4:
        if k-alpha_offset >= n:
            return [ ("IFFT", n, alpha_offset) ]
        elif k-alpha_offset <= 0:
            return [ ("FFT", n, alpha_offset) ]

    if n == 2:
        f = fft_matrix(1, alpha_offset)
        if k-alpha_offset <= 0:
            matrix = f
        elif k-alpha_offset >= 2:
            matrix = ifft_matrix(1, alpha_offset)
        else:
            matrix = GF(np.array([[GF(1)/f[0,0], f[0,1]/f[0,0]], [ f[1,0]/f[0,0], f[1,1]-f[1,0]*f[0,1]/f[0,0]]]))
        return [ ("MM22",  alpha_offset, alpha_offset+1, matrix) ]

    B = Bmatr(lg_sz, alpha_offset)
    Bupper = np.linalg.inv(B)
    Blower = GF(np.array([[GF(1)/B[0,0], B[0,1]/B[0,0]],[B[1,0]/B[0,0], B[1,1] - B[1,0]*B[0,1]/B[0,0]]]))

    operations = []
    n2 = n//2
    for j in range(n2):
        in_alpha1 = (j+alpha_offset < k)
        in_alpha2 = (j+alpha_offset+n2 < k)
        if in_alpha1 and in_alpha2:
            # Do nothing
            pass
        elif in_alpha1 and not in_alpha2:
            operations.append( ("COPY_SCRATCH", j+n2+alpha_offset, j+n2) ) # We need this later in the last step
            # No need to do anything to the left half. We need U1 to update the right half, but we'll defer that. We can do the Blower[1,1] part though
            operations.append( ("SCALE", j+n2+alpha_offset, Blower[1,1]) )
        else:
            operations.append( ("MM22", j+alpha_offset, j+alpha_offset+n2, B))

    operations.extend( principal_pivot_transform_k_no_x(lg_sz-1, k, alpha_offset) )

    # Fixup the part of J2 that needs U1
    for j in range(n2):
        in_alpha1 = (j+alpha_offset < k)
        in_alpha2 = (j+alpha_offset+n2 < k)
        if in_alpha1 and not in_alpha2:
            operations.append( ("MULACC", j+n2+alpha_offset, j+alpha_offset, Blower[1,0]) )

    operations.extend( principal_pivot_transform_k_no_x(lg_sz-1, k, alpha_offset+n//2) )

    for j in range(n2):
        in_alpha1 = (j+alpha_offset < k)
        in_alpha2 = (j+alpha_offset+n2 < k)
        if in_alpha2:
            operations.append( ("MM22", j+alpha_offset, j+alpha_offset+n2, Bupper))
            # Do nothing
            pass
        elif in_alpha1 and not in_alpha2:
            # No need to do anything to the right half
            operations.append( ("SCALE", j+alpha_offset, B[0,0]) )
            operations.append( ("MULACC_SCRATCH", j+alpha_offset, j+n2,  B[0,1]) )
        else: # in neither
            pass
    return operations

def print_macro(macro_name, args, lines, indent=2):
    line1 = "#define " + macro_name + "( " + args[0]
    maxwidth = max( map(len, lines)) + indent + 16
    for arg in args[1:]:
        if len(line1 + arg)+3 < maxwidth:
            line1 += ", " + arg
        else:
            line1 += " "*(maxwidth - len(line1)-3) + ", \\"
            print(line1, file=outf)
            line1 = " "*(2*indent) + arg
    line1 += ") "
    print(line1 + " "*(maxwidth-len(line1)-1) + "\\", file=outf)

    line2 = " "*indent + "do {"
    line2 += " "*(maxwidth-len(line2)-1) + "\\"
    print(line2, file=outf)
    for line in lines:
        print(" "*(2*indent) + line + " "*(maxwidth-len(line)-1-2*indent) + "\\", file=outf)
    print(" "*indent + "} while( 0 )", file=outf)
    print("", file=outf)

print_macro("GF_MUL22", ["inout0", "inout1", "c00", "c01", "c10", "c11"], [
    "gf_t temp = GF_ADD( GF_MUL( inout0, c00 ), GF_MUL( inout1, c01 ) );",
    "inout1 = GF_ADD( GF_MUL( inout0, c10 ), GF_MUL( inout1, c11 ) );",
    "inout0 = temp;"
    ])

for mink,maxk, N in ((1,16,16), (17,32,32), (33,64,64), (65,69,128)):
    for k in range(mink, maxk):
        inputs = [f"in{j:02}" for j in range(N)]

        macro_lines = [ ]
        operations = principal_pivot_transform_k_no_x(int(np.log2(N)), k, 0)

        scratch_to_declare = set()

        for op in operations:
            if op[0] == "IFFT":
                n, shift = op[1:]
                macro_lines.append(f"FD_REEDSOL_GENERATE_IFFT( {n}, {shift}, {', '.join(inputs[shift:shift+n])} );")
            if op[0] == "FFT":
                n, shift = op[1:]
                macro_lines.append(f"FD_REEDSOL_GENERATE_FFT( {n}, {shift}, {', '.join(inputs[shift:shift+n])} );")
            if op[0] == "COPY_SCRATCH":
                src, dest = op[1:]
                scratch_to_declare.add(f"scratch_{dest}")
                macro_lines.append(f"scratch_{dest} = {inputs[src]};")
            if op[0] == "SCALE":
                srcdest, const = op[1:]
                macro_lines.append(f"{inputs[srcdest]} = GF_MUL( {inputs[srcdest]}, {int(const)} );")
            if op[0] == "MM22":
                srcdest0, srcdest1, matr = op[1:]
                macro_lines.append(f"GF_MUL22( {inputs[srcdest0]}, {inputs[srcdest1]}, {int(matr[0,0])}, {int(matr[0,1])}, {int(matr[1,0])}, {int(matr[1,1])} );")
            if op[0] == "MULACC":
                dest, src, const = op[1:]
                macro_lines.append(f"{inputs[dest]} = GF_ADD( GF_MUL( {inputs[src]}, {int(const)} ), {inputs[dest]} );")
            if op[0] == "MULACC_SCRATCH":
                dest, src_scratch, const = op[1:]
                assert f"scratch_{src_scratch}" in scratch_to_declare
                macro_lines.append(f"{inputs[dest]} = GF_ADD( GF_MUL( scratch_{src_scratch}, {int(const)} ), {inputs[dest]} );")

        scratch_lines = []
        scratch_to_declare = sorted(list(scratch_to_declare))
        while scratch_to_declare:
            scratch_lines.append("gf_t " + ", ".join(scratch_to_declare[:16]) + ";")
            scratch_to_declare = scratch_to_declare[16:]
        macro_lines = scratch_lines + macro_lines

        if N>=32:
            print(f"void fd_reedsol_ppt_{N}_{k}( { ', '.join(['gf_t*']*N) } );", file=outf)
        print_macro(f"FD_REEDSOL_PPT_IMPL_{N}_{k}", inputs, macro_lines)

        if False: #debug
            first_bytes = GF([0]*1 + [1] +[0]*30)
            scratch_first_bytes = GF([0]*32)
            for op in operations:
                if op[0] == "IFFT":
                    n, shift = op[1:]
                    first_bytes[shift:shift+n] = ifft_matrix(int(np.log2(n)), shift) @ GF(first_bytes[shift:shift+n])
                if op[0] == "FFT":
                    n, shift = op[1:]
                    first_bytes[shift:shift+n] = fft_matrix(int(np.log2(n)), shift) @ GF(first_bytes[shift:shift+n])
                if op[0] == "COPY_SCRATCH":
                    src, dest = op[1:]
                    scratch_first_bytes[dest] = first_bytes[src]
                if op[0] == "SCALE":
                    srcdest, const = op[1:]
                    first_bytes[srcdest] = first_bytes[srcdest] * const
                if op[0] == "MM22":
                    srcdest0, srcdest1, matr = op[1:]
                    first_bytes[srcdest0], first_bytes[srcdest1] = matr @ GF(np.array([[first_bytes[srcdest0]], [first_bytes[srcdest1]]]))
                if op[0] == "MULACC":
                    dest, src, const = op[1:]
                    first_bytes[dest] += first_bytes[src] * const
                if op[0] == "MULACC_SCRATCH":
                    dest, src_scratch, const = op[1:]
                    first_bytes[dest] += scratch_first_bytes[src_scratch] * const

print("#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_ppt_h */", file=outf)


# file 2..n
batches = (17, 25, 33, 40, 45, 50, 55, 60, 65, 68)
for j in range(len(batches)-1):
    start = batches[j]
    end = batches[j+1] # exclusive
    with open(f'wrapped_impl/fd_reedsol_ppt_impl_{start}.c', "wt") as outf:
        print('#include "../fd_reedsol_ppt.h"', file=outf)
        for k in range(start, end):
            N = 1<<(k-1).bit_length() # Round to next power of 2
            if k==N:
                continue # Skip powers of 2 because we don't use PPT in those cases
            print('\nvoid', file=outf)
            fn_name = f"fd_reedsol_ppt_{N}_{k}( "
            print(fn_name + "gf_t * _in00,", file=outf)
            for l in range(1, N):
                if l<N-1:
                    _next = ","
                else:
                    _next = " ) {"
                print(" "*len(fn_name) + f"gf_t * _in{l:02}{_next}", file=outf)

            for l in range(0, N):
                print(f"  gf_t in{l:02} = *_in{l:02};", file=outf)

            print("", file=outf)

            print(f"  FD_REEDSOL_GENERATE_PPT( {N:2}, {k:2}, {', '.join([f'in{l:02}' for l in range(N) ])} );", file=outf)

            for l in range(0, N):
                print(f"  *_in{l:02} = in{l:02};", file=outf)

            print("}", file=outf)
