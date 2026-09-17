/* Second unity TU (see fd_blst_curve.c): keygen, the fp/fr exports and
   rb_tree.  The only static they need from the other TU is
   reciprocal_fr; blst_fr_inverse is its export. */

#include "src/fields.h"

void blst_fr_inverse(vec256 out, const vec256 inp);

static void reciprocal_fr(vec256 out, const vec256 inp)
{   blst_fr_inverse(out, inp);   }

#include "src/keygen.c"
#include "src/exports.c"
#ifndef __BLST_CGO__
# include "src/rb_tree.c"
#endif
