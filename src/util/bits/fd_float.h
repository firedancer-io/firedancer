#ifndef HEADER_fd_src_util_math_fd_float_h
#define HEADER_fd_src_util_math_fd_float_h

#include "fd_bits.h"

/* IEEE-754 crash course:

   "float" / single precision:

            biased    unbiased
     sign  exponent   exponent     mantissa
        0         0       -127            0 -> zero              / +0.f
        1         0       -127            0 -> signed zero       / -0.f
        s         0       -127     non-zero -> denorm            / (-1)^s 2^-126 m/2^23
        0       255        128            0 -> positive infinity / +inf
        1       255        128            0 -> negative infinity / -inf
        s       255        128  (   0,2^22) -> signaling nan     / snan (bits 0:21 theoretically encode diagnostic conditions, 0 not allowed for bits 0:21 here)
        s       255        128  [2^22,2^23) -> quiet nan         / qnan (", 0 allowed for bits 0:21 here)
        s         b   e==b-127            m -> normal            / (-1)^s 2^e (1 + m/2^23)

   "double" / double precision

            biased    unbiased
     sign  exponent   exponent     mantissa
        0         0      -1023            0 -> zero              / +0.
        1         0      -1023            0 -> signed zero       / -0.
        s         0      -1023     non-zero -> denorm            / (-1)^s 2^-1022 m/2^52
        0      2047       1024            0 -> positive infinity / +inf
        1      2047       1024            0 -> negative infinity / -inf
        s      2047       1024  (   0,2^51) -> signaling nan     / snan (bits 0:50 theoretically encode diagnostic conditions, 0 not allowed for bits 0:50 here)
        s      2047       1024  [2^51,2^52) -> quiet nan         / qnan (", 0 allowed for bits 0:50 here)
        s         b  e==b-1023            m -> normal            / (-1)^s 2^e (1 + m/2^52)

   Some architectures have a notion of a "canonical nan" (such that nan
   producing operations will not have the sign bit set and will always
   have the same diagnostic condition).  */

FD_PROTOTYPES_BEGIN

/* fd_float                  treats a 32-bit unsigned int to a float
   fd_fltbits                treats a float as a 32-bit unsigned ints ("fltbits")
   fd_fltbits_sign           extracts the sign from a fltbits
   fd_fltbits_biasedexponent extracts the biased exponents of a fltbits
   fd_fltbits_mantissa       extracts the mantissa
   fd_fltbits_pack           packs a sign, biased exponent and mantissa
                             into a fltbits
   fd_fltbits_unbias         return the exponent for a biased exponent
   fd_fltbits_bias           return the biased exponent for an exponent

   As these don't do any interpretation of the bits, these in principle
   are just linguistic operations as opposed to an actual operation
   (e.g. in FPGA synthesis, these amount to reinterpretation of the
   meaning of some voltages on some wires).  But because of the way
   languages and hardware dubiously treat floating point as a somehow
   weirdly different realm from the rest of the world (e.g. separate CPU
   register files for integers and floats under the hood), this might
   require some operations on the target (generally fast O(1)
   operations).

   The APIs below use ulong for bit fields in general (even in cases
   where 32-bit might be sufficient) to avoid unnecessary assembly ops
   under the hood. */

/* FIXME: CHECK X86 CODE QUALITY / USE SSE HACK */

FD_FN_CONST static inline ulong /* 32-bit */
fd_fltbits( float f ) {
  union { uint u[1]; float f[1]; } tmp;
  tmp.f[0] = f;
  return (ulong)tmp.u[0];
}

FD_FN_CONST static inline ulong /*  1-bit */ fd_fltbits_sign( ulong u /* 32-bit */ ) { return  u >> 31;              }
FD_FN_CONST static inline ulong /*  8-bit */ fd_fltbits_bexp( ulong u /* 32-bit */ ) { return (u >> 23) &     255UL; }
FD_FN_CONST static inline ulong /* 23-bit */ fd_fltbits_mant( ulong u /* 32-bit */ ) { return  u        & 8388607UL; }

FD_FN_CONST static inline long  /* [-127,128] */ fd_fltbits_unbias( ulong b /* 8-bit      */ ) { return ((long)b)-127L;  }
FD_FN_CONST static inline ulong /* 8-bit      */ fd_fltbits_bias  ( long  e /* [-127,128] */ ) { return (ulong)(e+127L); }

FD_FN_CONST static inline ulong /* 32-bit */
fd_fltbits_pack( ulong s,    /*  1-bit */
                 ulong b,    /*  8-bit */
                 ulong m ) { /* 23-bit */
  return (s << 31) | (b << 23) | m;
}

FD_FN_CONST static inline float
fd_float( ulong u ) { /* 32-bit */
  union { uint u[1]; float f[1]; } tmp;
  tmp.u[0] = (uint)u;
  return tmp.f[0];
}

#if FD_HAS_DOUBLE /* These are 64-bit / double precision counterparts to the above */

FD_FN_CONST static inline ulong
fd_dblbits( double f ) {
  union { ulong u[1]; double f[1]; } tmp;
  tmp.f[0] = f;
  return tmp.u[0];
}

FD_FN_CONST static inline ulong /*  1-bit */ fd_dblbits_sign( ulong u ) { return  u >> 63;                       }
FD_FN_CONST static inline ulong /* 11-bit */ fd_dblbits_bexp( ulong u ) { return (u >> 52) &             2047UL; }
FD_FN_CONST static inline ulong /* 52-bit */ fd_dblbits_mant( ulong u ) { return  u        & 4503599627370495UL; }

FD_FN_CONST static inline long  /* [-1023,1024] */ fd_dblbits_unbias( ulong b /* 11-bit       */ ) { return ((long)b)-1023L;  }
FD_FN_CONST static inline ulong /* 11-bit       */ fd_dblbits_bias  ( long  e /* [-1023,1024] */ ) { return (ulong)(e+1023L); }

FD_FN_CONST static inline ulong
fd_dblbits_pack( ulong s,    /*  1-bit */
                 ulong b,    /* 11-bit */
                 ulong m ) { /* 52-bit */
  return (s << 63) | (b << 52) | m;
}

FD_FN_CONST static inline double
fd_double( ulong u ) {
  union { ulong u[1]; double d[1]; } tmp;
  tmp.u[0] = u;
  return tmp.d[0];
}

#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_math_fd_float_h */
