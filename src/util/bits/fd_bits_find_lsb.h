/* Included by fd_bits.h */
/* DO NOT INCLUDE DIRECTLY */

/* find_lsb */

#if FD_HAS_X86 && __BMI__

/* __builtin_ctz(l)( x ) has proven to be faster than
   __builtin_ffs{l}(x)-1, the only numerical difference being the return
   value when x = 0 (U.B.).  For X86 targets, __builtin_ctz(l)
   translates into tzcnt, which may not be supported in very old ones.
   In this case it is only used if the compiler defines __BMI__ too. */

FD_FN_CONST static inline int fd_uchar_find_lsb ( uchar  x ) { return __builtin_ctz ( (uint)x ); }
FD_FN_CONST static inline int fd_ushort_find_lsb( ushort x ) { return __builtin_ctz ( (uint)x ); }
FD_FN_CONST static inline int fd_uint_find_lsb  ( uint   x ) { return __builtin_ctz (       x ); }
FD_FN_CONST static inline int fd_ulong_find_lsb ( ulong  x ) { return __builtin_ctzl(       x ); }

#else /* all other architectures */

FD_FN_CONST static inline int fd_uchar_find_lsb ( uchar  x ) { return __builtin_ffs ( (int )x )-1; }
FD_FN_CONST static inline int fd_ushort_find_lsb( ushort x ) { return __builtin_ffs ( (int )x )-1; }
FD_FN_CONST static inline int fd_uint_find_lsb  ( uint   x ) { return __builtin_ffs ( (int )x )-1; }
FD_FN_CONST static inline int fd_ulong_find_lsb ( ulong  x ) { return __builtin_ffsl( (long)x )-1; }

#endif

#if FD_HAS_INT128

#if FD_HAS_X86

FD_FN_CONST static inline int
fd_uint128_find_lsb( uint128 x ) {
  ulong xl  = (ulong) x;
  ulong xh  = (ulong)(x>>64);
  int   _64 = 64;
  int   c   = 0;
  __asm__( "testq %1, %1   # cc.zf = !xl;\n\t"                
           "cmovz %3, %0   # if( !xl ) c = 64;\n\t"
           "cmovz %2, %1   # if( !xl ) xl = xh;"
         : "+&r" (c), "+&r" (xl) : "r" (xh), "r" (_64) : "cc" );
  return c + fd_ulong_find_lsb( xl );
}

#else /* all other architectures */ 

FD_FN_CONST static inline int
fd_uint128_find_lsb( uint128 x ) {
  ulong xl = (ulong) x;
  ulong xh = (ulong)(x>>64);
  int   c  = !xl;
  return (((c)<<6)-1) + __builtin_ffsl( (long)fd_ulong_if( c, xh, xl ) );
}

#endif

#endif

/* find_lsb_w_default */

#if FD_HAS_X86

/* FIXME: WHY UINT -> INT CAST THROUGH UNION? */

/* find_lsb_w_default has been optimized for both tzcnt and bsf.  Note
   that in older Intel architectures (before Skylake) tzcnt has a false
   dependency on the destination register (this is true for bsf, but
   should not be the case for tzcnt).  Instead of using the typical xor
   operation on the output register (to break the dependency), the code
   below reuses the input register to that end, without affecting the
   performance on newer architectures. */

FD_FN_CONST static inline int 
fd_uchar_find_lsb_w_default( uchar x,
                             int   d ) { 
  union { int i; uint u; } r, c;
  c.i = d;
  r.u = (uint)x;  
# if __BMI__
  __asm__( " tzcnt %0, %0 # cc.cf = !x;\n\t" 
           " cmovb %1, %0 # move if cf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# else
  __asm__( " bsf   %0, %0 # cc.zf = !x;\n\t" 
           " cmovz %1, %0 # move if zf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# endif
  return r.i;
}

FD_FN_CONST static inline int 
fd_ushort_find_lsb_w_default( ushort x,
                              int    d ) {
  union { int i; uint u; } r, c;
  c.i = d;
  r.u = (uint)x;  
# if __BMI__
  __asm__( " tzcnt %0, %0 # cc.cf = !x;\n\t" 
           " cmovb %1, %0 # move if cf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# else
  __asm__( " bsf   %0, %0 # cc.zf = !x;\n\t" 
           " cmovz %1, %0 # move if zf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# endif
  return r.i;
}

FD_FN_CONST static inline int 
fd_uint_find_lsb_w_default( uint x,
                            int  d ) {
  union { int i; uint u; } r, c;
  c.i = d;
  r.u = x;  
# if __BMI__
  __asm__(  " tzcnt %0, %0 # cc.cf = !x;\n\t" 
            " cmovb %1, %0 # move if cf is set;"
          : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# else
  __asm__(  " bsf   %0, %0 # cc.zf = !x;\n\t" 
            " cmovz %1, %0 # move if zf is set;"
          : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# endif
  return r.i;
}

FD_FN_CONST static inline int 
fd_ulong_find_lsb_w_default( ulong x,
                             int   d ) {
  union { long l; ulong u; } r, c;
  c.l = (long)d;
  r.u = x;
# if __BMI__
  __asm__( " tzcnt %0, %0 # cc.cf = !x;\n\t" 
           " cmovb %1, %0 # move if cf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# else
  __asm__( " bsf   %0, %0 # cc.zf = !x;\n\t" 
           " cmovz %1, %0 # move if zf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
# endif
  return (int)r.l;
}

#else /* other architectures */

FD_FN_CONST static inline int fd_uchar_find_lsb_w_default ( uchar   x, int d ) { return (!x) ? d : fd_uchar_find_lsb ( x ); }
FD_FN_CONST static inline int fd_ushort_find_lsb_w_default( ushort  x, int d ) { return (!x) ? d : fd_ushort_find_lsb( x ); }
FD_FN_CONST static inline int fd_uint_find_lsb_w_default  ( uint    x, int d ) { return (!x) ? d : fd_uint_find_lsb  ( x ); }
FD_FN_CONST static inline int fd_ulong_find_lsb_w_default ( ulong   x, int d ) { return (!x) ? d : fd_ulong_find_lsb ( x ); }

#endif

#if FD_HAS_INT128

#if FD_HAS_X86

FD_FN_CONST static inline int 
fd_uint128_find_lsb_w_default( uint128 x,
                               int     d ) { 
  ulong xl  = (ulong) x;
  ulong xh  = (ulong)(x>>64);
  int   c   = 0;
  int   _64 = 64;
  __asm__( "testq  %2, %2  # cc.zf = !xl;\n\t"
           "cmovz  %3, %0  # if( !xl ) c = 64;\n\t"
           "cmovnz %2, %1  # if(!!xl ) xh = xl;"
           : "+&r" (c), "+&r" (xh) : "r" (xl), "r" (_64) : "cc" );
  int r = c + fd_ulong_find_lsb( xh );
  __asm__( "testq  %1, %1  # cc.zf = !xh;\n\t"
           "cmovz  %2, %0  # if( !xl ) c = d;"
           : "+&r" (r) : "r" (xh), "r" (d) : "cc" );
  return r;
}

#else /* other architectures */ 

FD_FN_CONST static inline int fd_uint128_find_lsb_w_default( uint128 x, int d ) { return (!x) ? d : fd_uint128_find_lsb( x ); }

#endif

#endif

