#ifndef HEADER_fd_src_groove_fd_groove_meta_h
#define HEADER_fd_src_groove_fd_groove_meta_h

#include "fd_groove_base.h" /* includes ../util/fd_util.h */

/* fd_groove_meta_bits API ********************************************/

/* The groove key metadata contains a 64-bit wide bitfield used to hold
   irregularly sized key metadata compactly.

     bits[ 0: 0]  1 -> used    (map slot contains a key-meta pair)
     bits[ 1: 1]  1 -> cold    (val for key present in cold store)
     bits[ 2: 2]  1 -> hot     (val for key present in hot  store)
     bits[ 3:15] 13 -> -       (available for additional use)
     bits[16:39] 24 -> val_sz  (num bytes for key's val)
     bits[40:63] 24 -> val_max (max bytes for key's val, 0<=val_sz<=val_max)

   fd_groove_meta_bits pack the components used, cold, hot, val_sz and
   val_max into this bitfield.  used, cold and hot treat 0/non-zero as
   0/1.  val_sz and val_max are assumed in [0,2^24).

   fd_grove_meta_bits_{used,cold,hot,val_sz,val_max} unpack this field
   from the bitfield.  used, cold and hot return a value in [0,1].
   val_sz and val_max will be in [0,2^24). */

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_groove_meta_bits( int   used,
                     int   cold,
                     int   hot,
                     ulong val_sz,
                     ulong val_max ) {
  return ((ulong)!!used) | (((ulong)!!cold)<<1) | (((ulong)!!hot)<<2) | (val_sz<<16) | (val_max<<40);
}

FD_FN_CONST static inline int   fd_groove_meta_bits_used   ( ulong bits ) { return (int)( bits      &        1UL); }
FD_FN_CONST static inline int   fd_groove_meta_bits_cold   ( ulong bits ) { return (int)((bits>> 1) &        1UL); }
FD_FN_CONST static inline int   fd_groove_meta_bits_hot    ( ulong bits ) { return (int)((bits>> 2) &        1UL); }
FD_FN_CONST static inline ulong fd_groove_meta_bits_val_sz ( ulong bits ) { return       (bits>>16) & 16777215UL;  }
FD_FN_CONST static inline ulong fd_groove_meta_bits_val_max( ulong bits ) { return        bits>>40;                }

FD_PROTOTYPES_END

/* fd_groove_meta API *************************************************/

/* FIXME: consider if memoizing is worth speed / footprint tradeoff */

struct fd_groove_meta {
  fd_groove_key_t key;
  ulong           bits;    /* groove metadata bit field */
  ulong           val_off; /* if key's val is in the cold store, cold store bytes [val_off,val_off+val_sz)
                              hold the current val and bytes [val_off,val_off+val_max) are reserved for key's val.
                              Thus: 0 <= val_off <= val_off+val_sz <= val_off+val_max <= cold store addr space sz.
                              Further val's reserved bytes will all reside within a single cold store volume. */
};

typedef struct fd_groove_meta fd_groove_meta_t;

#define  MAP_NAME                  fd_groove_meta_map
#define  MAP_ELE_T                 fd_groove_meta_t
#define  MAP_KEY_T                 fd_groove_key_t
#define  MAP_KEY_EQ                fd_groove_key_eq
#define  MAP_KEY_HASH              fd_groove_key_hash
#define  MAP_ELE_IS_FREE(ctx,ele)  (!fd_groove_meta_bits_used( (ele)->bits ))
#define  MAP_ELE_FREE(ctx,ele)     do (ele)->bits = fd_groove_meta_bits( 0,0,0, 0UL, 0UL ); while(0)
#define  MAP_ELE_MOVE(ctx,dst,src) do {                  \
    fd_groove_meta_t * _src = (src);                     \
    *(dst) = *_src;                                      \
    _src->bits = fd_groove_meta_bits( 0,0,0, 0UL, 0UL ); \
  } while(0)
#define  MAP_VERSION_T             ushort
#define  MAP_LOCK_MAX              (8192)
#define  MAP_MAGIC                 (0xfd67007e3e7a3a90UL) /* fd groove meta map version 0 */
#define  MAP_IMPL_STYLE            1
#include "../util/tmpl/fd_map_slot_para.c"

#endif /* HEADER_fd_src_groove_fd_groove_meta_h */
