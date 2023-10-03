import galois
import numpy as np
import numpy.linalg

header = """/* Note: This file is auto generated. */
#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_fft_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_fft_h

#include "fd_reedsol_private.h"

/* This file implements the FFT-like operator described in:
     S. -J. Lin, T. Y. Al-Naffouri, Y. S. Han and W. -H. Chung, "Novel
     Polynomial Basis With Fast Fourier Transform and Its Application to
     Reed–Solomon Erasure Codes," in IEEE Transactions on Information
     Theory, vol. 62, no. 11, pp. 6284-6299, Nov. 2016, doi:
     10.1109/TIT.2016.2608892.

   The main macros this file provides are FD_REEDSOL_GENERATE_FFT and
   FD_REEDSOL_GENERATE_IFFT.  The rest of this file is auto-generated
   implementation details.

   Like the normal FFT and IFFT, the operator implemented in this file
   (and henceforward referred to as FFT and IFFT) transforms between one
   basis and another.  Rather than transformations of a signal between
   the frequency domain and the time domain, these operators transform a
   polynomial between domains we call the "evaluation basis" and the
   "coefficient basis".

   In the evaluation basis, a polynomial is represented by its value at
   subsequent points.  Equivalently, the polynomial is represented as a
   linear combination of the Lagrange basis polynomials (briefly, e_i(i)
   = 1, e_i(j)=0 when j != i) . In the coefficient basis, a polynomial
   is represented as a linear combination of basis polynomials for a
   specific, carefully chosen basis fully described in the paper and
   summarized below.

   Let N, a power of 2, be the size of the transform. To define the
   coefficient basis, we first define s_j(x) for j=0, ..., lg(N)
        s_j(x) = x*(x+1)*(x+2)* .. (x+ (2^j-1))
    where the multiplication and addition are GF(2^8) operations, but
    2^j-1 is computed as an integer.  This is equivalent to taking the
    GF product of all elements that are identical to x in all but the
    last j bits.  s_j(x) has order 2^j.

    Now, we define a normalized version, S_j(x) (called s bar in the
    paper):
        S_j(x) = s_j(x) / s_j( 2^j )
    Again, the division is a field operation, but 2^j is an integer
    operation.

    Finally, the basis elements X_i(x) for i=0, ..., N-1 are defined by
    interpreting i as a bitmask and taking the product of the
    corresponding S_j(x) where the bit is set.  For example:
       X_0(x) = 1,
       X_3(x) = S_0(x) * S_1(x),
       X_6(x) = S_1(x) * S_2(x).
    The multiplication happens in GF(2^8) of course.  X_i(x) is a
    polynomial of order i.

   */

/* FD_REEDSOL_GENERATE_FFT: Inserts code to transform n input values from the
   coefficient basis to the evaluation basis, i.e.  evaluating the
   polynomial described by the input at points b, b+1, b+2, ...  b+n-1
   (where this arithmetic on b is integer arithmetic, not GF(2^8)
   arithmetic).

   FD_REEDSOL_GENERATE_IFFT: Inserts code to transform n input values
   from the evaluation basis to the coefficient basis, describing a
   polynomial P(x) of degree no more than n such that P(b) = in0,
   P(b+1)=in1, ... P(b+n-1)=in_{n-1} (where this arithmetic on b is
   integer arithmetic, not GF(2^8) arithmetic).

   For both macros, n must be a power of 2 (4, 8, 16, 32, 64, 128, and
   256 are emitted by the code generator at the moment), and b must be a
   non-negative multiple of n no more than 134.  Both b and n must be
   literal integer values.

   The remaining n arguments should be vector variables of type gf_t.
   These are used as input and output, since there's no other good way
   to return n vector values.  As such, this macro is not robust.

   The FFT and IFFT are computed in a vectorized fashion, i.e. the
   transform of the ith byte is computed and stored in the ith byte of
   the output for each i independently. */

#define FD_REEDSOL_PRIVATE_EXPAND( M, ... ) M(  __VA_ARGS__ )

#define FD_REEDSOL_GENERATE_FFT(  n, b, ...) FD_REEDSOL_PRIVATE_EXPAND( FD_REEDSOL_FFT_IMPL_##n,   FD_CONCAT4(FD_REEDSOL_FFT_CONSTANTS_,  n, _, b),  __VA_ARGS__ )
#define FD_REEDSOL_GENERATE_IFFT( n, b, ...) FD_REEDSOL_PRIVATE_EXPAND( FD_REEDSOL_IFFT_IMPL_##n,  FD_CONCAT4(FD_REEDSOL_IFFT_CONSTANTS_, n, _, b),  __VA_ARGS__ )

/* For n>=64, this header also declares
          void fd_reedsol_{fft,ifft}_n_b( gf_t *, ... )
   that takes n gf_t elements by reference.  The arguments are used for
   input and output, and it performs the same operation as the similarly
   named macro, but this signature allows the function to be defined in
   a different compilation unit to speed up compile times. */
"""

outf = open('fd_reedsol_fft.h', "wt")
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
for j in range(8):
    for x in range(256):
        if j == 0:
            svals[ 0, x ] = GF(x)
        else:
            svals[ j, x ] = svals[ j-1, x ] * svals[ j-1, x ^ (1<<(j-1)) ]
    for x in range(256):
        sbar[ j, x ] = svals[ j, x ] / svals[ j, 1<<j ]

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

def op_fft( h, beta, i_round, r_offset ):
    # print(f"Calling a_fft( {h}, {beta}, {i_round}, {r_offset} )")
    if 2**i_round==h:
        return []
    to_return = []
    to_return.extend(op_fft( h, beta, i_round+1, r_offset,           ))
    to_return.extend(op_fft( h, beta, i_round+1, r_offset+2**i_round ))
    half_len = h//2**(i_round+1)

    for j in range(half_len):
        omega_ = j*2**(i_round+1)
        # print(f"delta({r_offset}, {i_round}, {j*(2**(i_round+1))}) = delta({r_offset}, {i_round+1}, {j*(2**(i_round+1))}) + sbar({i_round},{j*(2**(i_round+1))}) * delta({r_offset+2**i_round}, {i_round+1}, {j*(2**(i_round+1))})")

        to_return.append((0, r_offset+omega_, r_offset+2**i_round+omega_, ( i_round, omega_ , beta), (r_offset, i_round+1, omega_), (r_offset+2**i_round, i_round+1, omega_), (r_offset, i_round, omega_), (r_offset, i_round, omega_+2**i_round ) ))
    # print(f"a_fft( {h}, {beta}, {i_round}, {r_offset} ) = {delta}")
    return to_return

def op_ifft( h, beta, i_round, r_offset ):
    # print(f"Calling a_ifft( {h}, {beta}, {i_round}, {r_offset} )")
    if 2**i_round==h:
        return [ ]
    butterflies = []
    half_len = h//2**(i_round+1)
    for j in range(half_len):
        omega_ = j*2**(i_round+1)
        # print(f"ifft_butterfly {r_offset+omega_:2}, {r_offset+2**i_round+omega_:2}, {sbar[ i_round, omega_ ^ beta ]:3} # {(r_offset, i_round, omega_)} and {(r_offset, i_round, omega_ + 2**i_round)} => {(r_offset, i_round+1, omega_)} and {(r_offset+2**i_round, i_round+1, omega_ )}")
        butterflies.append((1, r_offset+omega_, r_offset+2**i_round+omega_, ( i_round, omega_ , beta ), (r_offset, i_round, omega_), (r_offset, i_round, omega_ + 2**i_round), (r_offset, i_round+1, omega_), (r_offset+2**i_round, i_round+1, omega_ ) ))

    butterflies.extend(op_ifft(h, beta, i_round+1, r_offset))
    butterflies.extend(op_ifft(h, beta, i_round+1, r_offset+2**i_round))
    return butterflies

print_macro("FD_REEDSOL_PRIVATE_FFT_BUTTERFLY", ["inout0", "inout1", "c"], [
    "inout0 = GF_ADD( inout0, GF_MUL( inout1, c ) );",
    "inout1 = GF_ADD( inout1, inout0 );"
    ])
print_macro("FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY", ["inout0", "inout1", "c"], [
    "inout1 = GF_ADD( inout1, inout0 );",
    "inout0 = GF_ADD( inout0, GF_MUL( inout1, c ) );",
    ])

for N in (256, 128, 64, 32, 16, 8, 4):
    inputs = [f"in{j:02}" for j in range(N)]
    macro_lines = [ ]

    current_vars = [ (0,0,i) for i in range(N) ]

    butterflies = op_ifft(N, 0, 0, 0)
    const_to_cidx = {}
    for idx, (t, i0, i1, c, fi0, fi1, fo0, fo1) in enumerate(butterflies):
        if not c in const_to_cidx:
            const_to_cidx[c] = len(const_to_cidx)

    consts_array = [None]*len(const_to_cidx)
    for k,v in const_to_cidx.items():
        consts_array[v] = k

    for shift in range(0, 67*2, N):
        shift_specific = [ f'{(int(sbar[ c[0], c[1]^shift ])):3}' for c in consts_array ]
        print(f"#define FD_REEDSOL_IFFT_CONSTANTS_{N}_{shift:<2} " + ', '.join(shift_specific), file=outf)

    for t, i0, i1, c, fi0, fi1, fo0, fo1 in butterflies:
        assert t==1
        assert current_vars[i0] == fi0
        assert current_vars[i1] == fi1
        macro_lines.append(f"FD_REEDSOL_PRIVATE_IFFT_BUTTERFLY( {inputs[i0]}, {inputs[i1]}, c_{const_to_cidx[c]:02} );") # {fi0} and {fi1} => {fo0} and {fo1}")
        current_vars[i0] = fo0
        current_vars[i1] = fo1
    print_macro(f"FD_REEDSOL_IFFT_IMPL_{N}", [f"c_{j:02}" for j in range(len(const_to_cidx))] + inputs, macro_lines)

    if N>=64:
        for shift in range(0, 67*2, N):
            print(f"void fd_reedsol_ifft_{N}_{shift:<2}( " + ', '.join(['gf_t*']*N) + " );", file=outf)

    macro_lines = [ ]
    butterflies = op_fft(N, shift, 0, 0)

    const_to_cidx = {}
    for idx, (t, i0, i1, c, fi0, fi1, fo0, fo1) in enumerate(butterflies):
        if not c in const_to_cidx:
            const_to_cidx[c] = len(const_to_cidx)

    consts_array = [None]*len(const_to_cidx)
    for k,v in const_to_cidx.items():
        consts_array[v] = k

    for shift in range(0, 67*2, N):
        shift_specific = [ f'{int(sbar[ c[0], (c[1]^shift)&0xFF ]):3}' for c in consts_array ]
        print(f"#define FD_REEDSOL_FFT_CONSTANTS_{N}_{shift:<2} " + ', '.join(shift_specific), file=outf)

    for t, i0, i1, c, fi0, fi1, fo0, fo1 in butterflies:
        assert t==0
        assert current_vars[i0] == fi0
        assert current_vars[i1] == fi1
        macro_lines.append(f"FD_REEDSOL_PRIVATE_FFT_BUTTERFLY( {inputs[i0]}, {inputs[i1]}, c_{const_to_cidx[c]:02} );")  # {fi0} and {fi1} => {fo0} and {fo1}")
        current_vars[i0] = fo0
        current_vars[i1] = fo1
    print_macro(f"FD_REEDSOL_FFT_IMPL_{N}", [f"c_{j:02}" for j in range(len(const_to_cidx))] + inputs, macro_lines)

    if N>=64:
        for shift in range(0, 67*2, N):
            print(f"void fd_reedsol_fft_{N}_{shift:<2}( " + ', '.join(['gf_t*']*N) + " );", file=outf)

print("#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_fft_h */", file=outf)

for N in (256, 128, 64):
    for shift in range(0, 67*2, N):
        with open(f'wrapped_impl/fd_reedsol_fft_impl_{N}_{shift}.c', "wt") as outf:
            print('#include "../fd_reedsol_fft.h"', file=outf)
            print('\nvoid', file=outf)
            fn_name = f"fd_reedsol_fft_{N}_{shift}( "
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

            print(f"  FD_REEDSOL_GENERATE_FFT( {N:2}, {shift:2}, {', '.join([f'in{l:02}' for l in range(N) ])} );", file=outf)

            for l in range(0, N):
                print(f"  *_in{l:02} = in{l:02};", file=outf)

            print("}", file=outf)

            print('\nvoid', file=outf)
            fn_name = f"fd_reedsol_ifft_{N}_{shift}( "
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

            print(f"  FD_REEDSOL_GENERATE_IFFT( {N:2}, {shift:2}, {', '.join([f'in{l:02}' for l in range(N) ])} );", file=outf)

            for l in range(0, N):
                print(f"  *_in{l:02} = in{l:02};", file=outf)

            print("}", file=outf)
