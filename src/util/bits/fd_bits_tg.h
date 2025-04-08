/* Included by fd_bits.h */
/* DO NOT INCLUDE DIRECTLY */

/* fd_bits_tg.h provides type generic versions of the most of the
   functionality in fd_bits in that they infer the type from the
   argument).  E.g. Unless otherwise explicitly noted, fd_foo( expr )
   will behave functionally and linguistically identical to fd_int_foo(
   expr ) if expr returns an int, fd_ulong_foo( expr ) if x returns a
   ulong and so forth.  These macros are robust and should compile to to
   comparably fast O(1) assembly as the type explicit equivalents. */

/* fd_tg_* are implement various bit and arithmetic operators that patch
   over various linguistic faults.  These are meant for internal use to
   implement the actual bits tg functionality below.

   These are necessary because, as ranted about elsewhere, C and C++
   don't _meaningfully_ have char, short, uchar and ushort types.
   Operations on these are dubiously silently promoted to int.  There is
   _almost_ a reasonable historical argument for this behavior for char
   and short.  And this argument would be valid for uchar and ushort if
   those were promoted to uint.  But, in a fit of complete utter
   linguistic insanity, uchar and ushort are promoted to a _signed_ int.

   This is a subtle underappreciated and all too common source of
   security bugs, data corruption and portability issues.  As an
   example, this can cause great surprise and many a lost weekend
   debugging when things like ~(ulong)0 produce the ulong value
   ULONG_MAX and ~(uint)0 produce the uint value UINT_MAX but ~(uchar)0
   produces the 32-bit signed integer value -1.

   This (plus the lexical irregularities introduced by dubiously
   treating char's sign as implementation defined), makes writing robust
   code much harder than it should be and makes writing robust fast
   portable type generic code even more obtuse.  Sigh ... */

#define fd_tg_neg(x)              ((__typeof__((x)))-(x)       ) /* -x    with type of x guaranteed */
#define fd_tg_add(x,y)            ((__typeof__((x)))((x) + (y))) /* x + y " */
#define fd_tg_sub(x,y)            ((__typeof__((x)))((x) - (y))) /* x - y " */
#define fd_tg_not(x)              ((__typeof__((x)))~(x)       ) /* ~x    "  */
#define fd_tg_and(x,y)            ((__typeof__((x)))((x) & (y))) /* x & y " */
#define fd_tg_or(x,y)             ((__typeof__((x)))((x) | (y))) /* x | y " */
#define fd_tg_xor(x,y)            ((__typeof__((x)))((x) ^ (y))) /* x ^ y " */

#define fd_tg_msb_idx(T)          (8UL*sizeof(T)-1UL)            /* Returns the index of the most significant bit for type T */
#define fd_tg_is_unsigned_type(T) (((T)-(T)1)>(T)0)              /* Returns 1 if T is an unsigned type, 0 otherwise */

/* fd_tg_select will emit the expression e8, e16, e32, e64, or e128
   as appropriate for the width the integral type Tin (Tin can be a
   signed or unsigned type).  The output will have the type Tout.  This
   expression is selected at compile time (hopefully).  This is to brute
   force cases where the low level language faults are just too great to
   workaround with the above.

   Two implementations are provided.  One implementation uses the
   (widely supported) compiler extension __builtin_choose_expr.  If we
   don't want to use a compiler extension (e.g. portability concerns /
   auditing tool chain support concerns / etc), there is a second
   implementation based on the ternary operator.

   In both implementations, the compiler will parse all the expressions
   before it selects the matching expression.  Thus all the expressions
   have to be valid expressions for all x but only the matching
   expression has to be functionally correct for a particular x.  (This
   is an inherent limitation for the ternary implementation.
   Unfortunately, this limitation also exists for the builtin
   implementation for current compilers.)

   That is, while this makes it possible to write truly type generic
   implementations for a much broader range of cases, we still need to
   jump through hoops.  One hoop is that we only emit the 128-bit wide
   expression on targets with FD_HAS_INT128.

   Another hoop is due to the subtle difference between the builtin and
   the ternary operator: the builtin gives stronger guarantees that the
   selection will be done at compile time and it doesn't do type
   promotions of the individual expressions.  So we cast the expressions
   to Tout to keep both implementations of fd_tg_select functionally
   identical. */

#ifndef FD_BITS_TG_USE_BUILTIN
#ifdef __cplusplus
#define FD_BITS_TG_USE_BUILTIN 0
#else
#define FD_BITS_TG_USE_BUILTIN 1
#endif
#endif

#if FD_BITS_TG_USE_BUILTIN
#if FD_HAS_INT128
#define fd_tg_select(Tin,Tout,e8,e16,e32,e64,e128) __builtin_choose_expr( sizeof(Tin)==1UL, (Tout)(e8),  \
                                                   __builtin_choose_expr( sizeof(Tin)==2UL, (Tout)(e16), \
                                                   __builtin_choose_expr( sizeof(Tin)==4UL, (Tout)(e32), \
                                                   __builtin_choose_expr( sizeof(Tin)==8UL, (Tout)(e64), \
                                                                                            (Tout)(e128) ) ) ) )
#else
#define fd_tg_select(Tin,Tout,e8,e16,e32,e64,e128) __builtin_choose_expr( sizeof(Tin)==1UL, (Tout)(e8),  \
                                                   __builtin_choose_expr( sizeof(Tin)==2UL, (Tout)(e16), \
                                                   __builtin_choose_expr( sizeof(Tin)==4UL, (Tout)(e32), \
                                                                                            (Tout)(e64)  ) ) )
#endif
#else
#if FD_HAS_INT128
#define fd_tg_select(Tin,Tout,e8,e16,e32,e64,e128) ( ((sizeof(Tin)==1UL) ? (Tout)(e8)   : \
                                                     ((sizeof(Tin)==2UL) ? (Tout)(e16)  : \
                                                     ((sizeof(Tin)==4UL) ? (Tout)(e32)  : \
                                                     ((sizeof(Tin)==8UL) ? (Tout)(e64)  : \
                                                                           (Tout)(e128) ) ) ) ) )
#else
#define fd_tg_select(Tin,Tout,e8,e16,e32,e64,e128) ( ((sizeof(Tin)==1UL) ? (Tout)(e8)   : \
                                                     ((sizeof(Tin)==2UL) ? (Tout)(e16)  : \
                                                     ((sizeof(Tin)==4UL) ? (Tout)(e32)  : \
                                                                           (Tout)(e64)  ) ) ) )
#endif
#endif

/* Actual type generic bits implementations. */

#define fd_is_pow2( x ) (__extension__({                                                      \
    __typeof__((x)) _fd_bits_x = (x);                                                         \
    ((!!_fd_bits_x) & !fd_tg_and( _fd_bits_x, fd_tg_sub( _fd_bits_x, (__typeof__((x)))1 ) )); \
  }))

#define fd_pow2(        T, b       ) fd_shift_left( (T)1, (b) )

#define fd_mask_bit(    T, b       ) fd_shift_left( (T)1, (b) )
#define fd_clear_bit(   x, b       ) fd_tg_and( (x), fd_tg_not( fd_mask_bit( __typeof__((x)), (b) ) ) )
#define fd_set_bit(     x, b       ) fd_tg_or ( (x),            fd_mask_bit( __typeof__((x)), (b) )   )
#define fd_flip_bit(    x, b       ) fd_tg_xor( (x),            fd_mask_bit( __typeof__((x)), (b) )   )
#define fd_extract_bit( x, b       ) (((int)fd_shift_right( (x), (b) )) & 1)
#define fd_insert_bit(  x, b, y    ) (__extension__({                                                 \
    int _fd_bits_b = (b);                                                                             \
    fd_tg_or( fd_clear_bit( (x), _fd_bits_b ), fd_shift_left( (__typeof__((x)))!!(y), _fd_bits_b ) ); \
  }))

#define fd_mask_lsb(    T, n       ) fd_tg_sub( fd_shift_left( (T)1, (n) ), (T)1 )
#define fd_clear_lsb(   x, n       ) fd_tg_and( (x), fd_tg_not( fd_mask_lsb( __typeof__((x)), (n) ) ) )
#define fd_set_lsb(     x, n       ) fd_tg_or ( (x),            fd_mask_lsb( __typeof__((x)), (n) )   )
#define fd_flip_lsb(    x, n       ) fd_tg_xor( (x),            fd_mask_lsb( __typeof__((x)), (n) )   )
#define fd_extract_lsb( x, n       ) fd_tg_and( (x),            fd_mask_lsb( __typeof__((x)), (n) )   )
#define fd_insert_lsb(  x, n, y    ) fd_tg_or ( fd_clear_lsb( (x), (n) ), (y) )

#define fd_mask(        T, l, h    ) fd_tg_sub( fd_shift_left( (T)1, (h)+1 ), fd_shift_left( (T)1, (l) ) )
#define fd_clear(       x, l, h    ) fd_tg_and( (x), fd_tg_not( fd_mask( __typeof__((x)), (l), (h) ) ) )
#define fd_set(         x, l, h    ) fd_tg_or(  (x),            fd_mask( __typeof__((x)), (l), (h) )   )
#define fd_flip(        x, l, h    ) fd_tg_xor( (x),            fd_mask( __typeof__((x)), (l), (h) )   )
#define fd_extract(     x, l, h    ) (__extension__({                                                 \
    int _fd_bits_l = (l);                                                                             \
    fd_tg_and( fd_shift_right( (x), _fd_bits_l ), fd_mask_lsb( __typeof__((x)), (h)-_fd_bits_l+1 ) ); \
  }))
#define fd_insert(      x, l, h, y ) (__extension__({                               \
    int _fd_bits_l = (l);                                                           \
    fd_tg_or( fd_clear( (x), _fd_bits_l, (h) ), fd_shift_left( (y), _fd_bits_l ) ); \
  }))

#define fd_lsb( x ) (__extension__({                                                               \
    __typeof__((x)) _fd_bits_x = (x);                                                              \
    fd_tg_xor( _fd_bits_x, fd_tg_and( _fd_bits_x, fd_tg_sub( _fd_bits_x, (__typeof__((x)))1 ) ) ); \
  }))

#define fd_pop_lsb( x ) (__extension__({                                  \
    __typeof__((x)) _fd_bits_x = (x);                                     \
    fd_tg_and( _fd_bits_x, fd_tg_sub( _fd_bits_x, (__typeof__((x)))1 ) ); \
  }))

#define fd_mask_align(  T, a       ) fd_tg_sub( (T)(a), (T)1 )
#define fd_is_aligned(  x, a       ) (!fd_tg_and( (x),            fd_mask_align( __typeof__((x)), (a) )   ))
#define fd_alignment(   x, a       )   fd_tg_and( (x),            fd_mask_align( __typeof__((x)), (a) )   )
#define fd_align_dn(    x, a       )   fd_tg_and( (x), fd_tg_not( fd_mask_align( __typeof__((x)), (a) ) ) )
#define fd_align_up(    x, a       ) (__extension__({                   \
    __typeof__((x)) _fd_bits_m = fd_mask_align( __typeof__((x)), (a) ); \
    fd_tg_and( fd_tg_add( (x), _fd_bits_m ), fd_tg_not( _fd_bits_m ) ); \
  }))

#define fd_blend( m, x, y ) (__extension__({                                             \
    __typeof__((x)) _fd_bits_m = (m);                                                    \
    fd_tg_or( fd_tg_and( _fd_bits_m, (x) ), fd_tg_and( fd_tg_not( _fd_bits_m ), (y) ) ); \
  }))

#define fd_if(c,x,y) (__extension__({                                                                      \
    __typeof__((x)) _fd_bits_x = (x), _fd_bits_y = (y); /* Note: critical to eval first and then select */ \
    (c) ? _fd_bits_x : _fd_bits_y; /* cmov */                                                              \
  }))

#define fd_store_if(c,p,x) do {                     \
    __typeof__((x)) _fd_bits_dummy[1];              \
    *((c) ? (p) : _fd_bits_dummy) /* cmov */ = (x); \
  } while(0)

/* Note: fd_int_abs has a return type of uint.  This allows the edge
   case fd_int_abs(INT_MIN) to produce value of |INT_MIN| (which is not
   representable in an int but is in a uint).  Similarly for the other
   signed integer types.

   For the type general implementation below, the return type is the
   same as the input type.  As a result, the edge case has
   fd_abs(INT_MIN) == INT_MIN.  But, if we cast the result to a uint, we
   have the desired (uint)fd_abs(INT_MIN) == |INT_MIN|.

   Unfortunately, compilers don't support constructs like "unsigned
   __typeof__((x))" to get this to output the unsigned version of the
   input type in a straightforward way.  It would be possible to have
   fd_abs produce the correct unsigned variant of the input type by
   using __builtin_choose_expr.  Unfortunately, this will not work with
   the ternary type promotion rules.  Until we are willing to require
   toolchain support for __builtin_choose_expr, we stick with fd_abs
   returning the same type as the input. */

#define fd_abs( x ) (__extension__({                                                                        \
    __typeof__((x)) _fd_bits_x = (x), _fd_bits_nx = fd_tg_neg( _fd_bits_x );                                \
    (fd_tg_is_unsigned_type(__typeof__((x))) | (_fd_bits_x>((__typeof__(x))0))) ? _fd_bits_x : _fd_bits_nx; \
  }))

#define fd_min(x,y)  (__extension__({                              \
    __typeof__((x)) _fd_bits_x = (x), _fd_bits_y = (y);            \
    _fd_bits_x <= _fd_bits_y ? _fd_bits_x : _fd_bits_y; /* cmov */ \
  }))

#define fd_max(x,y)  (__extension__({                              \
    __typeof__((x)) _fd_bits_x = (x), _fd_bits_y = (y);            \
    _fd_bits_x >= _fd_bits_y ? _fd_bits_x : _fd_bits_y; /* cmov */ \
  }))

/* Note: this implementation assumes zero padding left shift behavior on
   target. */

#define fd_shift_left(x,n) (__extension__({                                                                       \
    int _fd_bits_m = (int)fd_tg_msb_idx( __typeof__((x)) );                           /* compile time */          \
    int _fd_bits_n = (n);                                                             /* compile time (mostly) */ \
    int _fd_bits_c = _fd_bits_n>_fd_bits_m;                                           /* compile time (mostly) */ \
    (__typeof__((x)))(((x) << (_fd_bits_c ? _fd_bits_m : _fd_bits_n)) << _fd_bits_c); /* compile time (mostly) */ \
  }))

/* Note: assumes zero padding unsigned / sign extending signed right
   shift behavior on target. */

#define fd_shift_right(x,n) (__extension__({                                                                      \
    int _fd_bits_m = (int)fd_tg_msb_idx( __typeof__((x)) );                           /* compile time */          \
    int _fd_bits_n = (n);                                                             /* compile time (mostly) */ \
    int _fd_bits_c = _fd_bits_n>_fd_bits_m;                                           /* compile time (mostly) */ \
    (__typeof__((x)))(((x) >> (_fd_bits_c ? _fd_bits_m : _fd_bits_n)) >> _fd_bits_c); /* compile time (mostly) */ \
  }))

/* Note: rotates use fd_tg_select because the implementation requires
   a zero padding signed right shift when operating on a signed type.
   If we are willing to restrict rotates to unsigned types only, these
   can be implemented type generic without fd_tg_select. */

#define fd_rotate_left(x,n) (__extension__({                                                              \
    __typeof__((x)) _fd_bits_x = (x);                                                                     \
    int             _fd_bits_n = (n);                                                                     \
    fd_tg_select( __typeof__((x)), __typeof__((x)),                                                       \
      (((uchar  )_fd_bits_x) << (_fd_bits_n &   7)) | (((uchar  )_fd_bits_x) >> ((-_fd_bits_n) &   7)),   \
      (((ushort )_fd_bits_x) << (_fd_bits_n &  15)) | (((ushort )_fd_bits_x) >> ((-_fd_bits_n) &  15)),   \
      (((uint   )_fd_bits_x) << (_fd_bits_n &  31)) | (((uint   )_fd_bits_x) >> ((-_fd_bits_n) &  31)),   \
      (((ulong  )_fd_bits_x) << (_fd_bits_n &  63)) | (((ulong  )_fd_bits_x) >> ((-_fd_bits_n) &  63)),   \
      (((uint128)_fd_bits_x) << (_fd_bits_n & 127)) | (((uint128)_fd_bits_x) >> ((-_fd_bits_n) & 127)) ); \
  }))

#define fd_rotate_right(x,n) (__extension__({                                                             \
    __typeof__((x)) _fd_bits_x = (x);                                                                     \
    int             _fd_bits_n = (n);                                                                     \
    fd_tg_select( __typeof__((x)), __typeof__((x)),                                                       \
      (((uchar  )_fd_bits_x) >> (_fd_bits_n &   7)) | (((uchar  )_fd_bits_x) << ((-_fd_bits_n) &   7)),   \
      (((ushort )_fd_bits_x) >> (_fd_bits_n &  15)) | (((ushort )_fd_bits_x) << ((-_fd_bits_n) &  15)),   \
      (((uint   )_fd_bits_x) >> (_fd_bits_n &  31)) | (((uint   )_fd_bits_x) << ((-_fd_bits_n) &  31)),   \
      (((ulong  )_fd_bits_x) >> (_fd_bits_n &  63)) | (((ulong  )_fd_bits_x) << ((-_fd_bits_n) &  63)),   \
      (((uint128)_fd_bits_x) >> (_fd_bits_n & 127)) | (((uint128)_fd_bits_x) << ((-_fd_bits_n) & 127)) ); \
  }))

/* Note: we use 4UL*sizeof(T) to avoid spurious compiler warnings of
   shifts wider than type when popcnt is used on narrower types. */

#define fd_popcnt( x ) (__extension__({                \
    __typeof__((x)) _fd_bits_x = (x);                  \
    fd_tg_select( __typeof__((x)), int,                \
      __builtin_popcount ( (uint)(uchar) _fd_bits_x ), \
      __builtin_popcount ( (uint)(ushort)_fd_bits_x ), \
      __builtin_popcount ( (uint)        _fd_bits_x ), \
      __builtin_popcountl( (ulong)       _fd_bits_x ), \
      __builtin_popcountl( (ulong)_fd_bits_x ) + __builtin_popcountl( (ulong)(_fd_bits_x >> (4UL*sizeof(__typeof__((x)))) ) ) ); \
  }))

#define fd_find_lsb( x ) (__extension__({              \
    __typeof__((x)) _fd_bits_x = (x);                  \
    fd_tg_select( __typeof__((x)), int,                \
      fd_uchar_find_lsb  ( (uchar)  _fd_bits_x ),      \
      fd_ushort_find_lsb ( (ushort) _fd_bits_x ),      \
      fd_uint_find_lsb   ( (uint)   _fd_bits_x ),      \
      fd_ulong_find_lsb  ( (ulong)  _fd_bits_x ),      \
      fd_uint128_find_lsb( (uint128)_fd_bits_x ) );    \
  }))

#define fd_find_lsb_w_default( x, d ) (__extension__({                    \
    __typeof__((x)) _fd_bits_x = (x);                                     \
    int             _fd_bits_d = (d);                                     \
    fd_tg_select( __typeof__((x)), int,                                   \
      fd_uchar_find_lsb_w_default  ( (uchar)  _fd_bits_x, _fd_bits_d ),   \
      fd_ushort_find_lsb_w_default ( (ushort) _fd_bits_x, _fd_bits_d ),   \
      fd_uint_find_lsb_w_default   ( (uint)   _fd_bits_x, _fd_bits_d ),   \
      fd_ulong_find_lsb_w_default  ( (ulong)  _fd_bits_x, _fd_bits_d ),   \
      fd_uint128_find_lsb_w_default( (uint128)_fd_bits_x, _fd_bits_d ) ); \
  }))

#define fd_find_msb( x ) (__extension__({              \
    __typeof__((x)) _fd_bits_x = (x);                  \
    fd_tg_select( __typeof__((x)), int,                \
      fd_uchar_find_msb  ( (uchar)  _fd_bits_x ),      \
      fd_ushort_find_msb ( (ushort) _fd_bits_x ),      \
      fd_uint_find_msb   ( (uint)   _fd_bits_x ),      \
      fd_ulong_find_msb  ( (ulong)  _fd_bits_x ),      \
      fd_uint128_find_msb( (uint128)_fd_bits_x ) );    \
  }))

#define fd_find_msb_w_default( x, d ) (__extension__({                    \
    __typeof__((x)) _fd_bits_x = (x);                                     \
    int             _fd_bits_d = (d);                                     \
    fd_tg_select( __typeof__((x)), int,                                   \
      fd_uchar_find_msb_w_default  ( (uchar)  _fd_bits_x, _fd_bits_d ),   \
      fd_ushort_find_msb_w_default ( (ushort) _fd_bits_x, _fd_bits_d ),   \
      fd_uint_find_msb_w_default   ( (uint)   _fd_bits_x, _fd_bits_d ),   \
      fd_ulong_find_msb_w_default  ( (ulong)  _fd_bits_x, _fd_bits_d ),   \
      fd_uint128_find_msb_w_default( (uint128)_fd_bits_x, _fd_bits_d ) ); \
  }))

/* Note: defaults picked to match shift trick based implementation in
   edge cases.  FIXME: Consider using shift trick implementation anyway
   so that these are "const" functions (e.g. not inline asm that can't
   be compile time evaluated with compiler time inputs). */

#define fd_pow2_dn( x ) fd_shift_left( (__typeof__((x)))1, fd_find_msb_w_default( (x), 0 ) )

#define fd_pow2_up( x ) fd_shift_left( (__typeof__((x)))1, fd_find_msb_w_default( fd_tg_sub( (x), (__typeof__((x)))1 ), -1 ) + 1 )

/* Note: we use 4UL*sizeof(T) to avoid spurious compiler warnings of
   shifts wider than type when bswap is used on narrower types. */

#define fd_bswap( x ) (__extension__({              \
    __typeof__((x)) _fd_bits_x = (x);               \
    fd_tg_select( __typeof__((x)), __typeof__((x)), \
      /**/                       _fd_bits_x,        \
      __builtin_bswap16( (ushort)_fd_bits_x ),      \
      __builtin_bswap32( (uint  )_fd_bits_x ),      \
      __builtin_bswap64( (ulong )_fd_bits_x ),      \
      (((uint128)__builtin_bswap64( (ulong)_fd_bits_x )) << 64) | \
      ((uint128)__builtin_bswap64( (ulong)(_fd_bits_x >> (4UL*sizeof(__typeof__((x))))) )) ); \
  }))

/* Note: Type generic versions of fd_zz_enc/fd_zz_dec have similar
   signed/unsigned input -> unsigned/signed output issues as fd_abs
   above.  Unlike fd_abs though, the distinction is more fundamental
   than an edge case.  So either we'd force a casting (which defeats the
   point of making a type generic implementation) or we require
   toolchain support for __builtin_choose_expr.  Omitting for now. */
