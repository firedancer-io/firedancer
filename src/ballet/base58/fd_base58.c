#include "fd_base58.h"

#if FD_HAS_AVX
#include "fd_base58_avx.h"
#endif

/* base58_chars maps [0, 58) to the base58 character.  In the AVX case,
   this lookup table is contained implicitly in raw_to_base58 */

#if !FD_HAS_AVX
static char const base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
#endif

#define BASE58_INVALID_CHAR           ((uchar)255)
#define BASE58_INVERSE_TABLE_OFFSET   ((uchar)'1')
#define BASE58_INVERSE_TABLE_SENTINEL ((uchar)(1UL + (uchar)('z')-BASE58_INVERSE_TABLE_OFFSET))

/* base58_inverse maps (character value - '1') to [0, 58).  Invalid
   base58 characters map to BASE58_INVALID_CHAR.  The character after
   what 'z' would map to also maps to BASE58_INVALID_CHAR to facilitate
   branchless lookups.  Don't make it static so that it can be used from
   tests. */

#define BAD BASE58_INVALID_CHAR

uchar const base58_inverse[] = {
  (uchar)  0, (uchar)  1, (uchar)  2, (uchar)  3, (uchar)  4, (uchar)  5, (uchar)  6, (uchar)  7, (uchar)  8, (uchar)BAD,
  (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar)  9, (uchar) 10, (uchar) 11, (uchar) 12,
  (uchar) 13, (uchar) 14, (uchar) 15, (uchar) 16, (uchar)BAD, (uchar) 17, (uchar) 18, (uchar) 19, (uchar) 20, (uchar) 21,
  (uchar)BAD, (uchar) 22, (uchar) 23, (uchar) 24, (uchar) 25, (uchar )26, (uchar) 27, (uchar) 28, (uchar) 29, (uchar) 30,
  (uchar) 31, (uchar) 32, (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar)BAD, (uchar) 33, (uchar) 34,
  (uchar) 35, (uchar) 36, (uchar) 37, (uchar) 38, (uchar) 39, (uchar) 40, (uchar) 41, (uchar) 42, (uchar) 43, (uchar)BAD,
  (uchar) 44, (uchar) 45, (uchar) 46, (uchar) 47, (uchar) 48, (uchar) 49, (uchar) 50, (uchar) 51, (uchar) 52, (uchar) 53,
  (uchar) 54, (uchar) 55, (uchar) 56, (uchar) 57, (uchar)BAD
};

#undef BAD

#define N                32
#define INTERMEDIATE_SZ (9UL) /* Computed by ceil(log_(58^5) (256^32-1)) */
#define BINARY_SZ       ((ulong)N/4UL)

/* Contains the unique values less than 58^5 such that:
     2^(32*(7-j)) = sum_k table[j][k]*58^(5*(7-k))

   The second dimension of this table is actually ceil(log_(58^5)
   (2^(32*(BINARY_SZ-1))), but that's almost always INTERMEDIATE_SZ-1 */

static uint const enc_table_32[BINARY_SZ][INTERMEDIATE_SZ-1UL] = {
  {   513735U,  77223048U, 437087610U, 300156666U, 605448490U, 214625350U, 141436834U, 379377856U},
  {        0U,     78508U, 646269101U, 118408823U,  91512303U, 209184527U, 413102373U, 153715680U},
  {        0U,         0U,     11997U, 486083817U,   3737691U, 294005210U, 247894721U, 289024608U},
  {        0U,         0U,         0U,      1833U, 324463681U, 385795061U, 551597588U,  21339008U},
  {        0U,         0U,         0U,         0U,       280U, 127692781U, 389432875U, 357132832U},
  {        0U,         0U,         0U,         0U,         0U,        42U, 537767569U, 410450016U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         6U, 356826688U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         1U}
};

/* Contains the unique values less than 2^32 such that:
     58^(5*(8-j)) = sum_k table[j][k]*2^(32*(7-k)) */

static uint const dec_table_32[INTERMEDIATE_SZ][BINARY_SZ] = {
  {      1277U, 2650397687U, 3801011509U, 2074386530U, 3248244966U,  687255411U, 2959155456U,          0U},
  {         0U,       8360U, 1184754854U, 3047609191U, 3418394749U,  132556120U, 1199103528U,          0U},
  {         0U,          0U,      54706U, 2996985344U, 1834629191U, 3964963911U,  485140318U, 1073741824U},
  {         0U,          0U,          0U,     357981U, 1476998812U, 3337178590U, 1483338760U, 4194304000U},
  {         0U,          0U,          0U,          0U,    2342503U, 3052466824U, 2595180627U,   17825792U},
  {         0U,          0U,          0U,          0U,          0U,   15328518U, 1933902296U, 4063920128U},
  {         0U,          0U,          0U,          0U,          0U,          0U,  100304420U, 3355157504U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,  656356768U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          1U}
};

#include "fd_base58_tmpl.c"

#define N                64
#define INTERMEDIATE_SZ (18UL) /* Computed by ceil(log_(58^5) (256^64-1)) */
#define BINARY_SZ       ((ulong)N/4UL)

/* Contains the unique values less than 58^5 such that
   2^(32*(15-j)) = sum_k table[j][k]*58^(5*(16-k)) */

static uint const enc_table_64[BINARY_SZ][INTERMEDIATE_SZ-1UL] = {
  {     2631U, 149457141U, 577092685U, 632289089U,  81912456U, 221591423U, 502967496U, 403284731U, 377738089U, 492128779U,    746799U, 366351977U, 190199623U,  38066284U, 526403762U, 650603058U, 454901440U},
  {        0U,       402U,  68350375U,  30641941U, 266024478U, 208884256U, 571208415U, 337765723U, 215140626U, 129419325U, 480359048U, 398051646U, 635841659U, 214020719U, 136986618U, 626219915U,  49699360U},
  {        0U,         0U,        61U, 295059608U, 141201404U, 517024870U, 239296485U, 527697587U, 212906911U, 453637228U, 467589845U, 144614682U,  45134568U, 184514320U, 644355351U, 104784612U, 308625792U},
  {        0U,         0U,         0U,         9U, 256449755U, 500124311U, 479690581U, 372802935U, 413254725U, 487877412U, 520263169U, 176791855U,  78190744U, 291820402U,  74998585U, 496097732U,  59100544U},
  {        0U,         0U,         0U,         0U,         1U, 285573662U, 455976778U, 379818553U, 100001224U, 448949512U, 109507367U, 117185012U, 347328982U, 522665809U,  36908802U, 577276849U,  64504928U},
  {        0U,         0U,         0U,         0U,         0U,         0U, 143945778U, 651677945U, 281429047U, 535878743U, 264290972U, 526964023U, 199595821U, 597442702U, 499113091U, 424550935U, 458949280U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,  21997789U, 294590275U, 148640294U, 595017589U, 210481832U, 404203788U, 574729546U, 160126051U, 430102516U,  44963712U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,   3361701U, 325788598U,  30977630U, 513969330U, 194569730U, 164019635U, 136596846U, 626087230U, 503769920U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,    513735U,  77223048U, 437087610U, 300156666U, 605448490U, 214625350U, 141436834U, 379377856U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,     78508U, 646269101U, 118408823U,  91512303U, 209184527U, 413102373U, 153715680U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,     11997U, 486083817U,   3737691U, 294005210U, 247894721U, 289024608U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,      1833U, 324463681U, 385795061U, 551597588U,  21339008U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,       280U, 127692781U, 389432875U, 357132832U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,        42U, 537767569U, 410450016U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         6U, 356826688U},
  {        0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         0U,         1U}
};

static uint const dec_table_64[INTERMEDIATE_SZ][BINARY_SZ] = {
  {    249448U, 3719864065U,  173911550U, 4021557284U, 3115810883U, 2498525019U, 1035889824U,  627529458U, 3840888383U, 3728167192U, 2901437456U, 3863405776U, 1540739182U, 1570766848U,          0U,          0U},
  {         0U,    1632305U, 1882780341U, 4128706713U, 1023671068U, 2618421812U, 2005415586U, 1062993857U, 3577221846U, 3960476767U, 1695615427U, 2597060712U,  669472826U,  104923136U,          0U,          0U},
  {         0U,          0U,   10681231U, 1422956801U, 2406345166U, 4058671871U, 2143913881U, 4169135587U, 2414104418U, 2549553452U,  997594232U,  713340517U, 2290070198U, 1103833088U,          0U,          0U},
  {         0U,          0U,          0U,   69894212U, 1038812943U, 1785020643U, 1285619000U, 2301468615U, 3492037905U,  314610629U, 2761740102U, 3410618104U, 1699516363U,  910779968U,          0U,          0U},
  {         0U,          0U,          0U,          0U,  457363084U,  927569770U, 3976106370U, 1389513021U, 2107865525U, 3716679421U, 1828091393U, 2088408376U,  439156799U, 2579227194U,          0U,          0U},
  {         0U,          0U,          0U,          0U,          0U, 2992822783U,  383623235U, 3862831115U,  112778334U,  339767049U, 1447250220U,  486575164U, 3495303162U, 2209946163U,  268435456U,          0U},
  {         0U,          0U,          0U,          0U,          0U,          4U, 2404108010U, 2962826229U, 3998086794U, 1893006839U, 2266258239U, 1429430446U,  307953032U, 2361423716U,  176160768U,          0U},
  {         0U,          0U,          0U,          0U,          0U,          0U,         29U, 3596590989U, 3044036677U, 1332209423U, 1014420882U,  868688145U, 4264082837U, 3688771808U, 2485387264U,          0U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,        195U, 1054003707U, 3711696540U,  582574436U, 3549229270U, 1088536814U, 2338440092U, 1468637184U,          0U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,       1277U, 2650397687U, 3801011509U, 2074386530U, 3248244966U,  687255411U, 2959155456U,          0U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,       8360U, 1184754854U, 3047609191U, 3418394749U,  132556120U, 1199103528U,          0U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,      54706U, 2996985344U, 1834629191U, 3964963911U,  485140318U, 1073741824U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,     357981U, 1476998812U, 3337178590U, 1483338760U, 4194304000U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,    2342503U, 3052466824U, 2595180627U,   17825792U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,   15328518U, 1933902296U, 4063920128U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,  100304420U, 3355157504U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,  656356768U},
  {         0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          0U,          1U}
};

#include "fd_base58_tmpl.c"

