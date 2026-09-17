/* Unity TU replacing upstream server.c (README.txt).  point.h and
   fields.h forward-declare the e1/e2, sqrt/recip and fp12 helpers
   static, so everything reaching them shares this TU. bulk_addition.c
   and multi_scalar.c (blst_p1s_ and blst_p2s_, unused here) are left
   out; a new use fails at link time, add both here.  Order as in
   server.c. */

#include "src/point.h"
#include "src/hash_to_field.c"
#include "src/e1.c"
#include "src/map_to_g1.c"
#include "src/e2.c"
#include "src/map_to_g2.c"
#include "src/fp12_tower.c"
#include "src/pairing.c"
#include "src/aggregate.c"
#include "src/exp.c"
#include "src/sqrt.c"
#include "src/recip.c"
#include "src/consts.c"
#include "src/vect.c"
#ifndef __BLST_NO_CPUID__
# include "src/cpuid.c"
#endif
