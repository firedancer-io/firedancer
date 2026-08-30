/* Checks that C floating point evaluates bit-for-bit like Rust.

   Each case is printed as a line and folded into an FNV-1a hash.
   contrib/test/rust-float generates the same corpus from Rust and diffs
   the two streams; GOLDEN_HASH is the hash both of them print.

   References:

     IEEE 754-2019.  Does not specify which nan payload an operation
     propagates.
     https://standards.ieee.org/ieee/754/6210/

     f64::min, f64::max: "If the inputs compare equal (such as for the
     case of +0.0 and -0.0), either input may be returned
     non-deterministically."
     https://doc.rust-lang.org/std/primitive.f64.html#method.min

     f64::mul_add: "guaranteed to be the rounded infinite-precision
     result".  a*b+c rounds twice instead, so the two differ; the
     mul_add_scaled and muladd_scaled cases disagree on 93 of the 163
     values and fail under -ffp-contract=fast.
     https://doc.rust-lang.org/std/primitive.f64.html#method.mul_add

     f64::powf: "The precision of this function is non-deterministic."
     The powf cases agree only because both languages reach the same
     glibc pow.
     https://doc.rust-lang.org/std/primitive.f64.html#method.powf

     Float to integer `as` saturates at the bound crossed and maps nan to
     0, which fd_cast.h reimplements.
     https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast

     Berkeley TestFloat, for harder operand sets.
     http://www.jhauser.us/arithmetic/TestFloat.html */

#include "../fd_flamenco.h"
#include "../../util/bits/fd_float.h"
#include "fd_cast.h"

#include <math.h>
#include <stdio.h>

/* Result of contrib/test/rust-float, rustc 1.92.0, x86_64 glibc. */
#define GOLDEN_HASH (0xd975358e3e7e4914UL)

/* splitmix64, so both languages walk the same pseudo random corpus. */

static ulong
rng_next( ulong * state ) {
  *state += 0x9e3779b97f4a7c15UL;
  ulong z = *state;
  z = (z ^ (z>>30)) * 0xbf58476d1ce4e5b9UL;
  z = (z ^ (z>>27)) * 0x94d049bb133111ebUL;
  return z ^ (z>>31);
}

/* Rust and IEEE 754 define floating-point division by zero. */
#if FD_HAS_UBSAN
__attribute__((no_sanitize("float-divide-by-zero")))
#endif
static inline double rust_f64_div( double x, double y ) { return x/y; }

/* Bit patterns worth hitting exactly: zeros, subnormals, the normal
   boundaries, the integer-exactness boundary at 2^53, the u64 cast
   boundary at 2^64, infinities and both nan kinds. */

static ulong const specials[] = {
  0x0000000000000000UL, /* +0                        */
  0x8000000000000000UL, /* -0                        */
  0x0000000000000001UL, /* + smallest subnormal      */
  0x8000000000000001UL, /* - smallest subnormal      */
  0x000fffffffffffffUL, /* + largest subnormal       */
  0x800fffffffffffffUL, /* - largest subnormal       */
  0x0010000000000000UL, /* + smallest normal         */
  0x8010000000000000UL, /* - smallest normal         */
  0x3ff0000000000000UL, /* +1                        */
  0xbff0000000000000UL, /* -1                        */
  0x3fe0000000000000UL, /* +0.5                      */
  0x4000000000000000UL, /* +2                        */
  0x4008000000000000UL, /* +3                        */
  0x400921fb54442d18UL, /* +pi                       */
  0x3fb999999999999aUL, /* +0.1                      */
  0x4330000000000000UL, /* 2^52                      */
  0x4340000000000000UL, /* 2^53                      */
  0x4340000000000001UL, /* 2^53 + 1ulp               */
  0x43e0000000000000UL, /* 2^63                      */
  0x43f0000000000000UL, /* 2^64                      */
  0x43efffffffffffffUL, /* just below 2^64           */
  0xc3e0000000000000UL, /* -2^63                     */
  0x7fefffffffffffffUL, /* +max normal               */
  0xffefffffffffffffUL, /* -max normal               */
  0x7ff0000000000000UL, /* +inf                      */
  0xfff0000000000000UL, /* -inf                      */
  0x7ff8000000000000UL, /* +qnan                     */
  0xfff8000000000000UL, /* -qnan                     */
  0x7ff0000000000001UL, /* +snan                     */
  0xfff0000000000001UL, /* -snan                     */
  0x7ff8000deadbeef0UL, /* +qnan, non trivial payload*/
  0x3fefffffffffffffUL, /* just below 1              */
  0x3ff0000000000001UL, /* just above 1              */
  0x4059000000000000UL, /* 100                       */
  0xc059000000000000UL, /* -100                      */
};

/* Mantissa of a double, and the bits of 1.0. */
#define FD_MANT_MASK (0x000fffffffffffffUL)
#define FD_ONE_BITS  (0x3ff0000000000000UL)

#define N_SPECIAL (sizeof(specials)/sizeof(specials[0]))
#define N_RANDOM  (128UL)
#define N_VALUE   (N_SPECIAL+N_RANDOM)

static ulong hash = 0xcbf29ce484222325UL;
static int   dump = 0;

/* Lines are printed raw, nan payloads and zero signs included, so a diff
   against the Rust stream names the operation and operands that
   disagree.  The hash folds a normalised form instead, in which a nan
   result is "nan" and a zero result from min or max is "zero".  Those
   are the results the standards leave open; gcc and clang disagree on 20
   of them, so hashing the raw form would pin the compiler rather than
   the arithmetic. */

static void
emit2( char const * raw,
       char const * norm ) {
  for( char const * p=norm; *p; p++ ) {
    hash ^= (ulong)(uchar)*p;
    hash *= 0x100000001b3UL;
  }
  hash ^= (ulong)'\n';
  hash *= 0x100000001b3UL;
  if( dump ) puts( raw );
}

static void
emit( char const * line ) {
  emit2( line, line );
}

static void
emit_f64( char const * op,
          ulong        a,
          double       r ) {
  char raw[ 128 ]; char norm[ 128 ];
  sprintf( raw, "%s %016lx -> %016lx", op, a, fd_dblbits( r ) );
  if( isnan( r ) ) sprintf( norm, "%s %016lx -> nan", op, a );
  else             strcpy ( norm, raw );
  emit2( raw, norm );
}

static void
emit_f64_2( char const * op,
            ulong        a,
            ulong        b,
            double       r ) {
  char raw[ 128 ]; char norm[ 128 ];
  sprintf( raw, "%s %016lx %016lx -> %016lx", op, a, b, fd_dblbits( r ) );
  if( isnan( r ) ) sprintf( norm, "%s %016lx %016lx -> nan", op, a, b );
  else             strcpy ( norm, raw );
  emit2( raw, norm );
}

/* min and max additionally leave the sign of a zero result open. */

static void
emit_f64_2_z( char const * op,
              ulong        a,
              ulong        b,
              double       r ) {
  if( r==0.0 ) {
    char raw[ 128 ]; char norm[ 128 ];
    sprintf( raw,  "%s %016lx %016lx -> %016lx", op, a, b, fd_dblbits( r ) );
    sprintf( norm, "%s %016lx %016lx -> zero",   op, a, b );
    emit2( raw, norm );
    return;
  }
  emit_f64_2( op, a, b, r );
}

static void
emit_u64( char const * op,
          ulong        a,
          ulong        r ) {
  char line[ 128 ];
  sprintf( line, "%s %016lx -> %016lx", op, a, r );
  emit( line );
}

static void
emit_bool( char const * op,
           ulong        a,
           ulong        b,
           int          r ) {
  char line[ 128 ];
  sprintf( line, "%s %016lx %016lx -> %d", op, a, b, !!r );
  emit( line );
}

/* Results the corpus does not compare.

   No fd_ helper is here.  Every fd_ helper is fully specified -- a bit
   test, a field extract, a sign clear, a bit compare, a select, or a
   saturating cast -- so none can diverge.  The open results are all in
   the raw operators and libm calls.

   Neither language pins them down, and neither is self consistent: the
   answer depends on whether the compiler folded the expression or
   emitted an instruction, and it moves with compiler and with inlining.
   Only the guaranteed property is asserted.  For what a given build
   produces, run contrib/test/rust-float and read out/diff.txt.

   volatile keeps the operands opaque; folded, these results change
   again.  Rust needs std::hint::black_box for the same reason. */

static void
test_known_divergences( void ) {
  volatile ulong pqnan = 0x7ff8000000000000UL;
  volatile ulong nqnan = 0xfff8000000000000UL;
  volatile ulong psnan = 0x7ff0000000000001UL;
  volatile ulong pzero = 0x0000000000000000UL;
  volatile ulong nzero = 0x8000000000000000UL;
  volatile ulong pinf  = 0x7ff0000000000000UL;
  volatile ulong ninf  = 0xfff0000000000000UL;

  /* Two nan operands: x86 keeps whichever one register allocation put in
     the destination. */
  FD_TEST( isnan( fd_double( pqnan ) + fd_double( nqnan ) ) );

  /* A signaling nan may or may not come back quieted. */
  FD_TEST( isnan( floor( fd_double( psnan ) ) ) );

  /* Either sign of zero. */
  FD_TEST( fmin( fd_double( pzero ), fd_double( nzero ) )==0.0 );
  FD_TEST( fmax( fd_double( pzero ), fd_double( nzero ) )==0.0 );

  /* fd_double_eq and fd_float_eq compare bit patterns.  They are not
     IEEE ==, however much the name reads like it:

       fd_double_eq( nan,  nan  )  1     nan  == nan   0
       fd_double_eq( +0,   -0   )  0     +0   == -0    1
       fd_double_eq( +inf, +inf )  1     +inf == +inf  1
       fd_double_eq( +inf, -inf )  0     +inf == -inf  0

     The two notions part exactly where bit patterns and values do not
     correspond one to one: nan, which has many patterns and equals
     nothing, and zero, which has two patterns and one value.  Infinity
     is one to one, so it is not a trap.

     All of it is stable and Rust draws the same distinction, so these
     are pinned exactly.  The Rust counterpart of fd_double_eq is
     to_bits(), never ==.  Reach for it only to ask "are these the same
     bits", for instance to tell two nans apart by payload or sign. */
  double nanv = fd_double( pqnan );
  double pz   = fd_double( pzero );
  double nz   = fd_double( nzero );
  double pi   = fd_double( pinf  );
  double ni   = fd_double( ninf  );
  FD_TEST(  fd_double_eq( nanv, nanv ) );  FD_TEST( !(nanv==nanv) );
  FD_TEST( !fd_double_eq( pz,   nz   ) );  FD_TEST(  pz==nz       );
  FD_TEST(  fd_double_eq( pi,   pi   ) );  FD_TEST(  pi==pi       );
  FD_TEST( !fd_double_eq( pi,   ni   ) );  FD_TEST( !(pi==ni)     );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_known_divergences();

  for( int i=1; i<argc; i++ ) if( !strcmp( argv[i], "--dump" ) ) dump = 1;

  ulong vals[ N_VALUE ];
  for( ulong i=0UL; i<N_SPECIAL; i++ ) vals[ i ] = specials[ i ];
  ulong state = 0x0123456789abcdefUL;
  for( ulong i=0UL; i<N_RANDOM; i++ ) vals[ N_SPECIAL+i ] = rng_next( &state );

  for( ulong i=0UL; i<N_VALUE; i++ ) {
    ulong  ab = vals[ i ];
    double a  = fd_double( ab );

    emit_f64( "sqrt",  ab, sqrt ( a ) );
    emit_f64( "abs",   ab, fabs ( a ) );
    emit_f64( "floor", ab, floor( a ) );
    emit_f64( "ceil",  ab, ceil ( a ) );
    emit_f64( "trunc", ab, trunc( a ) );
    emit_f64( "round", ab, round( a ) );
    emit_f64( "rint",  ab, rint ( a ) );
    emit_f64( "ln",    ab, log  ( a ) );
    emit_f64( "log2",  ab, log2 ( a ) );
    emit_f64( "log10", ab, log10( a ) );
    emit_f64( "exp",   ab, exp  ( a ) );
    emit_f64( "exp2",  ab, exp2 ( a ) );
    emit_f64( "recip", ab, rust_f64_div( 1.0, a ) );
    emit_f64( "neg",   ab, -a );

    /* `as` saturates; a plain C cast would be undefined behaviour. */
    emit_u64( "as_u64", ab, fd_rust_cast_double_to_ulong( a ) );
    emit_u64( "as_i64", ab, (ulong)fd_rust_cast_double_to_long( a ) );
    emit_u64( "as_u32", ab, (ulong)fd_rust_cast_double_to_uint( a ) );
    emit_u64( "as_i32", ab, (ulong)(uint)fd_rust_cast_double_to_int( a ) );
    emit_u64( "f32_as_u64", ab, fd_rust_cast_float_to_ulong( (float)a ) );
    emit_u64( "f32_as_u32", ab, (ulong)fd_rust_cast_float_to_uint( (float)a ) );
    emit_u64( "as_f32", ab, (ulong)fd_fltbits( (float)a ) );
    /* u64 -> f64 rounds to nearest, ties to even. */
    emit_f64( "u64_as_f64", ab, (double)ab );
    emit_f64( "i64_as_f64", ab, (double)(long)ab );

    ulong  bb = vals[ (i+1UL) % N_VALUE ];
    ulong  cb = vals[ (i+2UL) % N_VALUE ];
    double b  = fd_double( bb );
    double c  = fd_double( cb );

    emit_f64_2( "add",      ab, bb, a+b );
    emit_f64_2( "sub",      ab, bb, a-b );
    emit_f64_2( "mul",      ab, bb, a*b );
    emit_f64_2( "div",      ab, bb, rust_f64_div( a, b ) );
    emit_f64_2( "rem",      ab, bb, fmod    ( a, b ) );
    emit_f64_2_z( "min",    ab, bb, fmin    ( a, b ) );
    emit_f64_2_z( "max",    ab, bb, fmax    ( a, b ) );
    emit_f64_2( "powf",     ab, bb, pow     ( a, b ) );
    emit_f64_2( "copysign", ab, bb, copysign( a, b ) );
    emit_f64_2( "hypot",    ab, bb, hypot   ( a, b ) );

    /* fma rounds once, a*b+c rounds twice. */
    emit_f64_2( "mul_add", ab, bb, fma( a, b, c ) );
    emit_f64_2( "muladd",  ab, bb, a*b+c );

    /* Random patterns give operands of wildly different scale, so a*b+c
       is dominated by one term and the two roundings never differ.
       Rescaling the mantissas into [1,2) makes them differ often. */
    double as = fd_double( (ab & FD_MANT_MASK) | FD_ONE_BITS );
    double bs = fd_double( (bb & FD_MANT_MASK) | FD_ONE_BITS );
    double cs = -fd_double( (cb & FD_MANT_MASK) | FD_ONE_BITS );
    emit_f64_2( "mul_add_scaled", ab, bb, fma( as, bs, cs ) );
    emit_f64_2( "muladd_scaled",  ab, bb, as*bs+cs );

    /* fd_ helpers against the Rust they stand in for. */
    emit_bool( "fd_is_nan",    ab, 0UL, fd_dblbits_is_nan   ( ab ) );
    emit_bool( "fd_is_inf",    ab, 0UL, fd_dblbits_is_inf   ( ab ) );
    emit_bool( "fd_is_zero",   ab, 0UL, fd_dblbits_is_zero  ( ab ) );
    emit_bool( "fd_is_denorm", ab, 0UL, fd_dblbits_is_denorm( ab ) );
    emit_bool( "fd_is_normal", ab, 0UL, fd_dblbits_is_normal( ab ) );
    emit_u64 ( "fd_sign",      ab, fd_dblbits_sign( ab ) );
    emit_u64 ( "fd_bexp",      ab, fd_dblbits_bexp( ab ) );
    emit_u64 ( "fd_mant",      ab, fd_dblbits_mant( ab ) );
    emit_u64 ( "fd_pack",      ab, fd_dblbits_pack( fd_dblbits_sign( ab ),
                                                    fd_dblbits_bexp( ab ),
                                                    fd_dblbits_mant( ab ) ) );
    emit_u64 ( "fd_roundtrip", ab, fd_dblbits( fd_double( ab ) ) );
    emit_f64 ( "fd_abs",       ab, fd_double_abs( a ) );
    emit_bool( "fd_eq",        ab, bb, fd_double_eq( a, b ) );
    /* Against itself, which separates the two notions of equality: bits
       say a nan equals itself, IEEE == says it equals nothing. */
    emit_bool( "fd_eq_self",   ab, ab, fd_double_eq( a, a ) );
    emit_bool( "eq_self",      ab, ab, a==a );

    /* The two notions coincide except where bit patterns and values are
       not one to one, so for every value: bit equality is pattern
       equality, == parts from it on itself only for a nan, and on a
       distinct pattern only for the two zeros. */
    FD_TEST( fd_double_eq( a, a )                );
    FD_TEST( fd_double_eq( a, b )==(ab==bb)      );
    FD_TEST( (a==a)==!fd_dblbits_is_nan( ab )    );
    if( ab!=bb )
      FD_TEST( (a==b)==( fd_dblbits_is_zero( ab ) && fd_dblbits_is_zero( bb ) ) );
    emit_f64 ( "fd_if_t",      ab, fd_double_if( 1, a, b ) );
    emit_f64 ( "fd_if_f",      ab, fd_double_if( 0, a, b ) );

    /* f32 helpers, against the same value narrowed to f32. */
    uint fb = (uint)fd_fltbits( (float)a );
    emit_bool( "fd_f32_is_nan",    ab, 0UL, fd_fltbits_is_nan   ( fb ) );
    emit_bool( "fd_f32_is_inf",    ab, 0UL, fd_fltbits_is_inf   ( fb ) );
    emit_bool( "fd_f32_is_zero",   ab, 0UL, fd_fltbits_is_zero  ( fb ) );
    emit_bool( "fd_f32_is_denorm", ab, 0UL, fd_fltbits_is_denorm( fb ) );
    emit_bool( "fd_f32_is_normal", ab, 0UL, fd_fltbits_is_normal( fb ) );

    emit_bool( "eq", ab, bb, a==b );
    emit_bool( "lt", ab, bb, a< b );
    emit_bool( "le", ab, bb, a<=b );
    emit_bool( "ne", ab, bb, a!=b );
  }

  FD_LOG_NOTICE(( "%lu values, hash %016lx", N_VALUE, hash ));
  FD_TEST( hash==GOLDEN_HASH );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
