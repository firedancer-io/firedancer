/* Unity TU replacing upstream server.c (README.txt).  point.h and
   fields.h forward-declare the e1/e2, sqrt/recip and fp12 helpers
   static, so everything reaching them shares this TU. */

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
#include "src/bulk_addition.c"
#include "src/multi_scalar.c"
#include "src/consts.c"
#include "src/vect.c"
#ifndef __BLST_NO_CPUID__
# include "src/cpuid.c"
#endif
