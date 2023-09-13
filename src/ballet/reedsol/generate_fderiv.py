import galois
import numpy as np

header = """
/* Note: This file is auto generated. */
#ifndef HEADER_fd_src_ballet_reedsol_fd_reedsol_fderiv_h
#define HEADER_fd_src_ballet_reedsol_fd_reedsol_fderiv_h

#include "fd_reedsol_private.h"

/* This file implements the formal derivative computation of a
   polynomial stored in the coefficient basis.  The computation is
   described in section IV of the Lin, et al. paper, and especially part
   IV.B.

   The main macro this file provides is FD_REEDSOL_GEN_FDERIV.  The rest
   of this file is auto-generated implementation details.

   The formal derivative of a polynomial P(x) over a finite field comes
   from treating the x as if it were a real value, taking the
   derivative, and then re-interpreting the resulting polynomial back as
   being over the original finite field.  More precisely, it's the
   linear operator on polynomials that maps x^n to
        x^(n-1) + x^(n-1) + ... + x^(n-1)
        |-------------------------------|
                n terms

   Since our finite field is GF(2^8), then x^n maps to 0 if n is even
   and x^(n-1) if n is odd.

   Basically, this operator is useful because it obeys the formal
   equivalent of the product rule. */

/* FD_REEDSOL_GEN_FDERIV: Inserts code to compute the formal derivative
   of a polynomial of length n, where both the input and output
   polynomial are in the coefficient basis.

   n must be a power of 2 (only 16, 32, 64, 128 are emitted by the code
   generator at the moment).

   The n arguments that follow the first should be vector variables of
   type gf_t.  These are used as input and output, since there's no
   other good way to return n vector values.  As such, this macro is not
   robust.

   The formal derivative is computed in a vectorized fashion, i.e. the
   transform of the ith byte is computed and stored in the ith byte of
   the output for each i independently. */

#define FD_REEDSOL_PRIVATE_EXPAND( M, ... ) M(  __VA_ARGS__ )

#define FD_REEDSOL_GENERATE_FDERIV(  n, ...) FD_REEDSOL_PRIVATE_EXPAND( FD_REEDSOL_FDERIV_IMPL_##n,  __VA_ARGS__ )
"""

outf = open('fd_reedsol_fderiv.h', "wt")
print(header, file=outf)

GF=galois.GF(2**8)

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

sbarprime = [1]
for l in range(1,8):
    sprimek = np.prod(GF(list(range(1, 1<<l)))) / svals[l, 1<<l]
    sbarprime.append(sprimek)

B = []
for i in range(256):
    prod = GF(1)
    for j in range(8):
        if i & (1<<j):
            prod *= sbarprime[j]
    B.append(prod)

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
    print("\n\n", file=outf)

for N in (16, 32, 64, 128, 256):
    inputs = [ f"in{j:02}" for j in range(N) ]
    macro_lines = []
    for j in range(N):
        macro_lines.append( f"{inputs[j]} = GF_MUL( {inputs[j]}, {B[j]} );")
        for l in range(8):
            if j & (1<<l):
                macro_lines.append( f"{inputs[j ^ (1<<l)]} = GF_ADD( {inputs[j ^ (1<<l)]}, {inputs[j]} );" )
        macro_lines.append( f"{inputs[j]} = gf_zero();" )
    for j in range(N):
        macro_lines.append( f"{inputs[j]} = GF_MUL( {inputs[j]}, {GF(1)/B[j]} );")

    print_macro(f"FD_REEDSOL_FDERIV_IMPL_{N}", inputs, macro_lines)

print("#endif /* HEADER_fd_src_ballet_reedsol_fd_reedsol_fderiv_h */", file=outf)
