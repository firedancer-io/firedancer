/* Included by fd_bits.h */
/* DO NOT INCLUDE DIRECTLY */

FD_FN_CONST static inline int fd_uchar_find_msb ( uchar  x ) { return 31 - __builtin_clz ( (uint)x ); }
FD_FN_CONST static inline int fd_ushort_find_msb( ushort x ) { return 31 - __builtin_clz ( (uint)x ); }
FD_FN_CONST static inline int fd_uint_find_msb  ( uint   x ) { return 31 - __builtin_clz (       x ); }
FD_FN_CONST static inline int fd_ulong_find_msb ( ulong  x ) { return 63 - __builtin_clzl(       x ); }

#if FD_HAS_INT128

#if FD_HAS_X86

FD_FN_CONST static inline int 
fd_uint128_find_msb( uint128 x ) {
  ulong xl = (ulong) x;
  ulong xh = (ulong)(x>>64);
  int   _0 = 0;
  int   c  = 64;
  __asm__( "testq %1, %1   # cc.zf = !xh;\n\t"                
           "cmovz %3, %0   # if( !xh ) c = 0;\n\t"
           "cmovz %2, %1   # if( !xh ) xh = xl;"
         : "+&r" (c), "+&r" (xh) : "r" (xl), "r" (_0) : "cc" );
  return c + fd_ulong_find_msb( xh );
}

#else /* other architectures */ 

FD_FN_CONST static inline int 
fd_uint128_find_msb( uint128 x ) {
  ulong xl = (ulong) x;
  ulong xh = (ulong)(x>>64);
  int   c  = !xh;
  return (127-((c)<<6)) - __builtin_clzl( fd_ulong_if( c, xl, xh ) );
}

#endif

#endif

/* find_msb_w_default */

#if FD_HAS_X86

/* find_msb_w_default has been optimized for both lzcnt and bsr.  Note
   that in older Intel architectures (before Skylake) lzcnt has a false
   dependency on the destination register (this is true for bsr, but
   should not be the case for lzcnt).  Instead of using the typical xor
   operation on the output register (to break the dependency), the code
   below reuses the input register to that end, without affecting the
   performance on newer architectures. */

FD_FN_CONST static inline int 
fd_uchar_find_msb_w_default( uchar x,
                             int   d ) { 
  union { int i; uint u; } r, c;
# if __LZCNT__
  c.i = 31-d;
  r.u = (uint)x;
  __asm__( " lzcnt %0, %0 # cc.cf = !x;\n\t" 
           " cmovb %1, %0 # move if cf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
  return 31 - r.i;
# else
  c.i = d;
  r.u = (uint)x;
  __asm__( " bsr   %0, %0 # cc.zf = !x;\n\t" 
           " cmovz %1, %0 # move if zf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" );  
  return r.i;
# endif
}

FD_FN_CONST static inline int 
fd_ushort_find_msb_w_default( ushort x,
                              int    d ) { 
  union { int i; uint u; } r, c;
# if __LZCNT__
  c.i = 31-d;
  r.u = (uint)x;
  __asm__( " lzcnt %0, %0 # cc.cf = !x;\n\t" 
           " cmovb %1, %0 # move if cf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
  return 31 - r.i;
# else
  c.i = d;
  r.u = (uint)x;
  __asm__( " bsr   %0, %0 # cc.zf = !x;\n\t" 
           " cmovz %1, %0 # move if zf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" );  
  return r.i;
# endif
}

FD_FN_CONST static inline int 
fd_uint_find_msb_w_default( uint x,
                            int  d ) {  
  union { int i; uint u; } r, c;
# if __LZCNT__
  c.i = 31-d;
  r.u = x;
  __asm__( " lzcnt %0, %0 # cc.cf = !x;\n\t" 
           " cmovb %1, %0 # move if cf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
  return 31 - r.i;
# else
  c.i = d;
  r.u = x;
  __asm__( " bsr   %0, %0 # cc.zf = !x;\n\t" 
           " cmovz %1, %0 # move if zf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" );  
  return r.i;
# endif
}

FD_FN_CONST static inline int 
fd_ulong_find_msb_w_default( ulong x,
                             int   d ) { 
  union { long l; ulong u; } r, c;
# if __LZCNT__
  c.l = (long)(63L-d);
  r.u = x;
  __asm__( " lzcnt %0, %0 # cc.cf = !x;\n\t" 
           " cmovb %1, %0 # move if cf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" ); 
  return (int) (63L - r.l);
# else
  c.l = (long)d;
  r.u = x;
  __asm__( " bsr   %0, %0 # cc.zf = !x;\n\t" 
           " cmovz %1, %0 # move if zf is set;"
           : "+&r" (r.u) : "r" (c.u) : "cc" );  
  return (int)r.l;
# endif
}

#else /* other architectures */

FD_FN_CONST static inline int fd_uchar_find_msb_w_default ( uchar  x, int d ) { return (!x) ? d : fd_uchar_find_msb  ( x ); }
FD_FN_CONST static inline int fd_ushort_find_msb_w_default( ushort x, int d ) { return (!x) ? d : fd_ushort_find_msb ( x ); }
FD_FN_CONST static inline int fd_uint_find_msb_w_default  ( uint   x, int d ) { return (!x) ? d : fd_uint_find_msb   ( x ); }
FD_FN_CONST static inline int fd_ulong_find_msb_w_default ( ulong  x, int d ) { return (!x) ? d : fd_ulong_find_msb  ( x ); }

#endif

#if FD_HAS_INT128

#if FD_HAS_X86

FD_FN_CONST static inline int 
fd_uint128_find_msb_w_default( uint128 x,
                               int     d ) { 
  ulong xl = (ulong) x;
  ulong xh = (ulong)(x>>64);
  int   c  = 64;
  int   _0 = 0;
  __asm__( "testq %2, %2   # cc.zf = !xh;\n\t"
           "cmovz %3, %0   # if( !xh ) c = 0;\n\t"
           "cmovnz %2, %1  # if(!!xh ) xl = xh;"
           : "+&r" (c), "+&r" (xl) : "r" (xh), "r" (_0) : "cc" );
  return c + fd_ulong_find_msb_w_default( xl, d );
}

#else /* other architectures */  

FD_FN_CONST static inline int fd_uint128_find_msb_w_default( uint128 x, int d ) { return (!x) ? d : fd_uint128_find_msb( x ); }

#endif

#endif

