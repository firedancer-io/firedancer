#include "fd_dragon_session.h"
#include "proto/geyser.pb.h"
#include "../../third_party/nanopb/pb_decode.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/base64/fd_base64.h"

/* Decode errors.  The texts are the ones a yellowstone client sees for
   the same request (plugin/filter/name.rs, plugin/filter/limits.rs,
   plugin/filter/filter.rs); the caller prefixes them with "failed to
   create filter: ". */

#define DRAGON_DECODE_ERR_NONE          (0)
#define DRAGON_DECODE_ERR_NAME_SZ       (1)
#define DRAGON_DECODE_ERR_FILTER_MAX    (2)
#define DRAGON_DECODE_ERR_NAMES_MAX     (3)
#define DRAGON_DECODE_ERR_SLICE_MAX     (4)
#define DRAGON_DECODE_ERR_SLICE_ORDER   (5)
#define DRAGON_DECODE_ERR_SLICE_OVERLAP (6)
#define DRAGON_DECODE_ERR_COMMITMENT    (7)
#define DRAGON_DECODE_ERR_PUBKEY        (8)
#define DRAGON_DECODE_ERR_PUBKEY_MAX    (9)
#define DRAGON_DECODE_ERR_SIGNATURE    (10)
#define DRAGON_DECODE_ERR_CUCKOO       (11)
#define DRAGON_DECODE_ERR_STATE_MAX    (12)
#define DRAGON_DECODE_ERR_STATE_ROOM   (13)
#define DRAGON_DECODE_ERR_STATE        (14)
#define DRAGON_DECODE_ERR_ANY          (15)
#define DRAGON_DECODE_ERR_REJECT       (16)
#define DRAGON_DECODE_ERR_INCLUDE      (17)
#define DRAGON_DECODE_ERR_TOKEN_MODE   (18)
#define DRAGON_DECODE_ERR_CUCKOO_ROOM  (19)

struct dragon_decode {
  fd_dragon_filter_set_t *          set;
  fd_dragon_filter_limits_t const * limits;
  ulong                             names_seen;
  int                               err;
  ulong                             err_val;
  char const *                      err_txt; /* the reason a state predicate was refused */
  uchar                             err_key[ 32UL ]; /* the address a reject list refused */
};

typedef struct dragon_decode dragon_decode_t;

struct dragon_decode_map {
  dragon_decode_t * dec;
  int               type;
};

typedef struct dragon_decode_map dragon_decode_map_t;

/* dragon_filter_name_add records one filter name of the given type,
   with the predicates the caller decoded from its value.  Returns 0 on
   success, or -1 with dec->err set. */

static int
dragon_filter_name_add( dragon_decode_t *               dec,
                        int                             type,
                        char const *                    name,
                        ulong                           name_len,
                        fd_dragon_filter_name_t const * pred ) {
  fd_dragon_filter_set_t * set = dec->set;

  if( FD_UNLIKELY( name_len>FD_DRAGON_FILTER_NAME_MAX ) ) {
    dec->err     = DRAGON_DECODE_ERR_NAME_SZ;
    dec->err_val = name_len;
    return -1;
  }
  if( FD_UNLIKELY( set->type_cnt[ type ]>=dec->limits->filter_max[ type ] ) ) {
    dec->err     = DRAGON_DECODE_ERR_FILTER_MAX;
    dec->err_val = dec->limits->filter_max[ type ];
    return -1;
  }
  if( FD_UNLIKELY( set->name_cnt>=FD_DRAGON_FILTER_MAX ) ) {
    dec->err     = DRAGON_DECODE_ERR_FILTER_MAX;
    dec->err_val = FD_DRAGON_FILTER_MAX;
    return -1;
  }
  if( FD_UNLIKELY( dec->names_seen>=FD_DRAGON_FILTER_NAMES_MAX ) ) {
    dec->err = DRAGON_DECODE_ERR_NAMES_MAX;
    return -1;
  }

  fd_dragon_filter_name_t * out = set->name + set->name_cnt;
  *out = *pred;
  fd_memcpy( out->cstr, name, name_len );
  out->cstr[ name_len ] = '\0';
  out->len              = name_len;
  out->type             = type;
  set->name_cnt++;
  set->type_cnt[ type ]++;
  dec->names_seen++;
  return 0;
}

/* dragon_acct_add appends one base58 account address to the filter
   set's address pool.  reject_idx is the FD_DRAGON_REJECT_* list the
   operator may have forbidden addresses in, or -1 for a list that has
   none.  Returns 0 on success, or -1 with dec->err set. */

static int
dragon_acct_add( dragon_decode_t * dec,
                 char const *      b58,
                 ulong             b58_len,
                 int               reject_idx ) {
  fd_dragon_filter_set_t * set = dec->set;

  if( FD_UNLIKELY( set->acct_cnt>=FD_DRAGON_FILTER_ACCT_MAX ) ) {
    dec->err     = DRAGON_DECODE_ERR_PUBKEY_MAX;
    dec->err_val = FD_DRAGON_FILTER_ACCT_MAX;
    return -1;
  }

  char cstr[ 64 ];
  if( FD_UNLIKELY( b58_len>=sizeof(cstr) ) ) {
    dec->err = DRAGON_DECODE_ERR_PUBKEY;
    return -1;
  }
  fd_memcpy( cstr, b58, b58_len );
  cstr[ b58_len ] = '\0';

  if( FD_UNLIKELY( !fd_base58_decode_32( cstr, set->acct[ set->acct_cnt ] ) ) ) {
    dec->err = DRAGON_DECODE_ERR_PUBKEY;
    return -1;
  }

  if( FD_UNLIKELY( reject_idx>=0 ) ) {
    ulong reject_cnt = dec->limits->reject_cnt[ reject_idx ];
    for( ulong i=0UL; i<reject_cnt; i++ ) {
      if( FD_UNLIKELY( fd_memeq( dec->limits->reject[ reject_idx ][ i ], set->acct[ set->acct_cnt ], 32UL ) ) ) {
        dec->err = DRAGON_DECODE_ERR_REJECT;
        fd_memcpy( dec->err_key, set->acct[ set->acct_cnt ], 32UL );
        return -1;
      }
    }
  }

  set->acct_cnt++;
  return 0;
}

/* dragon_acct_list_add appends one base58 address to the filter set's
   pool as part of the list [off,off+cnt) of a filter.  max is how many
   addresses the list may name and reject_idx which addresses it may
   not. */

static int
dragon_acct_list_add( dragon_decode_t * dec,
                      ushort *          off,
                      ushort *          cnt,
                      char const *      b58,
                      ulong             b58_len,
                      ulong             max,
                      int               reject_idx ) {
  if( FD_UNLIKELY( (ulong)*cnt>=max ) ) {
    dec->err     = DRAGON_DECODE_ERR_PUBKEY_MAX;
    dec->err_val = max;
    return -1;
  }
  /* The addresses of one list are consecutive in the pool, so the
     first one fixes where the list starts. */
  if( !*cnt ) *off = (ushort)dec->set->acct_cnt;
  if( FD_UNLIKELY( dragon_acct_add( dec, b58, b58_len, reject_idx ) ) ) return -1;
  (*cnt)++;
  return 0;
}

/* dragon_decode_cuckoo decodes one CuckooFilter message into the
   filter set's bucket arena and points pred at it.  The fields other
   than data and hash_seed are not read, which is what the reference
   implementation does with the same bytes (see fd_dragon_cuckoo.h).
   type selects the cuckoo_max_size limit that applies. */

static int
dragon_decode_cuckoo( dragon_decode_t *         dec,
                      pb_istream_t *            stream,
                      fd_dragon_filter_name_t * pred,
                      int                       type ) {
  fd_dragon_filter_set_t * set        = dec->set;
  ulong                    entry_base = set->cuckoo_entry_cnt;
  ulong                    seed       = FD_DRAGON_CUCKOO_DEFAULT_SEED;
  ulong                    bucket_cnt = 0UL;
  int                      have_data  = 0;

  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return -1;
    }

    if( tag==1U && wire_type==PB_WT_STRING ) {
      uint32_t len;
      if( FD_UNLIKELY( !pb_decode_varint32( stream, &len ) ) ) return -1;
      if( FD_UNLIKELY( (ulong)len>dec->limits->cuckoo_max_size[ type ] ) ) {
        dec->err     = DRAGON_DECODE_ERR_CUCKOO;
        dec->err_val = dec->limits->cuckoo_max_size[ type ];
        return -1;
      }

      /* A field that holds no whole bucket is one empty bucket, and
         bytes past the last whole bucket are ignored. */
      bucket_cnt      = fd_dragon_cuckoo_wire_bucket_cnt( (ulong)len );
      ulong entry_cnt = bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
      if( FD_UNLIKELY( entry_cnt>set->cuckoo_entry_max-entry_base ) ) {
        dec->err     = DRAGON_DECODE_ERR_CUCKOO_ROOM;
        dec->err_val = set->cuckoo_entry_max*sizeof(ushort);
        return -1;
      }

      ulong copy_sz = fd_ulong_min( (ulong)len, entry_cnt*sizeof(ushort) );
      fd_memset( set->cuckoo+entry_base, 0, entry_cnt*sizeof(ushort) );
      if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)( set->cuckoo+entry_base ), (size_t)copy_sz ) ) ) return -1;
      for( ulong rem=(ulong)len-copy_sz; rem; rem-- ) {
        pb_byte_t drop;
        if( FD_UNLIKELY( !pb_read( stream, &drop, 1UL ) ) ) return -1;
      }
      have_data = 1;
      continue;
    }

    if( tag==5U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      seed = (ulong)v;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return -1;
  }

  /* A CuckooFilter with no data field is a filter of one empty bucket,
     which matches nothing. */
  if( !have_data ) {
    bucket_cnt = 1UL;
    if( FD_UNLIKELY( FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET>set->cuckoo_entry_max-entry_base ) ) {
      dec->err     = DRAGON_DECODE_ERR_CUCKOO_ROOM;
      dec->err_val = set->cuckoo_entry_max*sizeof(ushort);
      return -1;
    }
    fd_memset( set->cuckoo+entry_base, 0,
               FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET*sizeof(ushort) );
  }

  set->cuckoo_entry_cnt      = entry_base + bucket_cnt*FD_DRAGON_CUCKOO_ENTRIES_PER_BUCKET;
  pred->cuckoo_off           = (uint)entry_base;
  pred->cuckoo_bucket_cnt    = (uint)bucket_cnt;
  pred->cuckoo_seed          = seed;
  return 0;
}

/* dragon_decode_txn_filter decodes the value of a transactions or
   transactions_status map entry (geyser.proto
   SubscribeRequestFilterTransactions) into pred.  Returns 0 on
   success, or -1 with dec->err set. */

static int
dragon_decode_txn_filter( dragon_decode_t *         dec,
                          pb_istream_t *            stream,
                          fd_dragon_filter_name_t * pred,
                          int                       type ) {
  int    is_status   = type==FD_DRAGON_FILTER_TRANSACTIONS_STATUS;
  ulong  include_max = is_status ? dec->limits->status_include_max  : dec->limits->txn_include_max;
  ulong  exclude_max = is_status ? dec->limits->status_exclude_max  : dec->limits->txn_exclude_max;
  ulong  required_max= is_status ? dec->limits->status_required_max : dec->limits->txn_required_max;
  int    include_rej = is_status ? FD_DRAGON_REJECT_STATUS_INCLUDE  : FD_DRAGON_REJECT_TXN_INCLUDE;
  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return -1;
    }

    if( tag==1U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      pred->has_vote = 1;
      pred->vote     = !!v;
      continue;
    }

    if( tag==2U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      pred->has_failed = 1;
      pred->failed     = !!v;
      continue;
    }

    if( tag==30U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      /* TokenAccountExpansionControlFlag has two members; nothing
         expands the lists either way, because no token balances are
         computed, but a value that names no member is refused as
         yellowstone refuses it. */
      if( FD_UNLIKELY( v>1UL ) ) {
        dec->err     = DRAGON_DECODE_ERR_TOKEN_MODE;
        dec->err_val = (ulong)v;
        return -1;
      }
      pred->has_token_accounts = 1;
      continue;
    }

    if( tag==5U && wire_type==PB_WT_STRING ) {
      uint32_t len;
      if( FD_UNLIKELY( !pb_decode_varint32( stream, &len ) ) ) return -1;
      char b58[ 128 ];
      if( FD_UNLIKELY( (ulong)len>=sizeof(b58) ) ) {
        dec->err = DRAGON_DECODE_ERR_SIGNATURE;
        return -1;
      }
      if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)b58, (size_t)len ) ) ) return -1;
      b58[ len ] = '\0';
      if( FD_UNLIKELY( !fd_base58_decode_64( b58, pred->signature ) ) ) {
        dec->err = DRAGON_DECODE_ERR_SIGNATURE;
        return -1;
      }
      pred->has_signature = 1;
      continue;
    }

    if( ( tag==3U || tag==4U || tag==6U ) && wire_type==PB_WT_STRING ) {
      uint32_t len;
      if( FD_UNLIKELY( !pb_decode_varint32( stream, &len ) ) ) return -1;
      char b58[ 128 ];
      if( FD_UNLIKELY( (ulong)len>=sizeof(b58) ) ) {
        dec->err = DRAGON_DECODE_ERR_PUBKEY;
        return -1;
      }
      if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)b58, (size_t)len ) ) ) return -1;

      ushort * off;
      ushort * cnt;
      ulong    max;
      int      reject_idx = -1;
      if     ( tag==3U ) { off = &pred->include_off;  cnt = &pred->include_cnt;  max = include_max;  reject_idx = include_rej; }
      else if( tag==4U ) { off = &pred->exclude_off;  cnt = &pred->exclude_cnt;  max = exclude_max;  }
      else               { off = &pred->required_off; cnt = &pred->required_cnt; max = required_max; }

      if( FD_UNLIKELY( dragon_acct_list_add( dec, off, cnt, b58, (ulong)len, max, reject_idx ) ) ) return -1;
      continue;
    }

    if( tag==7U && wire_type==PB_WT_STRING ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return -1;
      if( FD_UNLIKELY( dragon_decode_cuckoo( dec, &sub, pred, type ) ) ) return -1;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return -1;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return -1;
  }

  /* A filter that constrains nothing matches every transaction, which
     an operator can forbid (plugin/filter/filter.rs:1578-1586: a
     signature alone still counts as unconstrained). */
  if( FD_UNLIKELY( !dec->limits->any[ type ] &&
                   !pred->has_vote && !pred->has_failed && !pred->has_token_accounts &&
                   !pred->include_cnt && !pred->exclude_cnt && !pred->required_cnt &&
                   !pred->cuckoo_bucket_cnt ) ) {
    dec->err = DRAGON_DECODE_ERR_ANY;
    return -1;
  }
  return 0;
}

/* DRAGON_MEMCMP_BUF is the scratch a memcmp predicate's bytes are
   decoded into, which is what the longest base64 string a request may
   carry decodes to; the bound on the bytes a predicate may keep is
   checked on the result. */

#define DRAGON_MEMCMP_BUF ( FD_BASE64_DEC_SZ(FD_DRAGON_MEMCMP_BASE64_MAX) + 8UL )

FD_STATIC_ASSERT( DRAGON_MEMCMP_BUF>FD_DRAGON_MEMCMP_BYTES_MAX, dragon_memcmp_buf );

/* dragon_base58_decode decodes a base58 string of any length, the way
   the bs58 crate does: the leading '1's are leading zero bytes and the
   rest is a base 58 big endian number.  Returns the number of bytes
   written, or -1 if the string is not base58 or its value does not fit
   out_max bytes, which is at most DRAGON_MEMCMP_BUF. */

static long
dragon_base58_decode( uchar *      out,
                      ulong        out_max,
                      char const * in,
                      ulong        in_len ) {
  /* The base58 digits, in value order.  The array is a C string, so
     the digit count is one less than its size. */
  static char const alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  ulong const       digit_cnt  = sizeof(alphabet)-1UL;

  FD_STATIC_ASSERT( sizeof(alphabet)==59UL, dragon_base58_alphabet );

  if( FD_UNLIKELY( out_max>DRAGON_MEMCMP_BUF ) ) return -1L;

  ulong zeros = 0UL;
  while( zeros<in_len && in[ zeros ]=='1' ) zeros++;

  uchar acc[ DRAGON_MEMCMP_BUF ]; /* least significant byte first */
  ulong len = 0UL;

  for( ulong i=zeros; i<in_len; i++ ) {
    char const * p = memchr( alphabet, in[ i ], digit_cnt );
    if( FD_UNLIKELY( !p ) ) return -1L;

    ulong carry = (ulong)( p-alphabet );
    for( ulong j=0UL; j<len; j++ ) {
      carry   += 58UL*(ulong)acc[ j ];
      acc[ j ] = (uchar)( carry & 0xFFUL );
      carry  >>= 8;
    }
    while( carry ) {
      if( FD_UNLIKELY( len>=sizeof(acc) ) ) return -1L;
      acc[ len++ ] = (uchar)( carry & 0xFFUL );
      carry      >>= 8;
    }
  }

  if( FD_UNLIKELY( zeros+len>out_max ) ) return -1L;

  fd_memset( out, 0, zeros );
  for( ulong i=0UL; i<len; i++ ) out[ zeros+len-1UL-i ] = acc[ i ];
  return (long)( zeros+len );
}

/* dragon_state_bytes takes sz bytes of the filter set's memcmp byte
   pool.  Returns the offset, or ULONG_MAX with dec->err set. */

static ulong
dragon_state_bytes( dragon_decode_t * dec,
                    ulong             sz ) {
  fd_dragon_filter_set_t * set = dec->set;
  if( FD_UNLIKELY( sz>FD_DRAGON_FILTER_STATE_BYTES-set->state_byte_cnt ) ) {
    dec->err = DRAGON_DECODE_ERR_STATE_ROOM;
    return ULONG_MAX;
  }
  ulong off            = set->state_byte_cnt;
  set->state_byte_cnt += sz;
  return off;
}

/* dragon_decode_memcmp decodes one memcmp predicate
   (SubscribeRequestFilterAccountsFilterMemcmp), whose data comes as
   raw bytes, base58 or base64.  The limits and the reasons a predicate
   is refused are yellowstone's (plugin/filter/filter.rs:1309-1381). */

static int
dragon_decode_memcmp( dragon_decode_t *        dec,
                      pb_istream_t *           stream,
                      fd_dragon_acct_state_t * st ) {
  int   have_data = 0;
  uchar data[ DRAGON_MEMCMP_BUF ];
  ulong data_sz   = 0UL;

  st->kind   = FD_DRAGON_ACCT_STATE_MEMCMP;
  st->offset = 0UL;

  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return -1;
    }

    if( tag==1U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      st->offset = (ulong)v;
      continue;
    }

    if( ( tag==2U || tag==3U || tag==4U ) && wire_type==PB_WT_STRING ) {
      uint32_t len;
      if( FD_UNLIKELY( !pb_decode_varint32( stream, &len ) ) ) return -1;

      char txt[ FD_DRAGON_MEMCMP_BASE58_MAX+1UL ];
      ulong txt_max = tag==3U ? FD_DRAGON_MEMCMP_BASE58_MAX :
                      tag==4U ? FD_DRAGON_MEMCMP_BASE64_MAX : FD_DRAGON_MEMCMP_BYTES_MAX;
      if( FD_UNLIKELY( (ulong)len>txt_max ) ) {
        dec->err     = DRAGON_DECODE_ERR_STATE;
        dec->err_txt = "data too large";
        return -1;
      }

      if( tag==2U ) {
        if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)data, (size_t)len ) ) ) return -1;
        data_sz = (ulong)len;
      } else {
        if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)txt, (size_t)len ) ) ) return -1;
        if( tag==3U ) {
          long n = dragon_base58_decode( data, sizeof(data), txt, (ulong)len );
          if( FD_UNLIKELY( n<0L ) ) {
            dec->err     = DRAGON_DECODE_ERR_STATE;
            dec->err_txt = "invalid base58";
            return -1;
          }
          data_sz = (ulong)n;
        } else {
          long n = fd_base64_decode( data, txt, (ulong)len );
          if( FD_UNLIKELY( n<0L ) ) {
            dec->err     = DRAGON_DECODE_ERR_STATE;
            dec->err_txt = "invalid base64";
            return -1;
          }
          data_sz = (ulong)n;
        }
        if( FD_UNLIKELY( data_sz>FD_DRAGON_MEMCMP_BYTES_MAX ) ) {
          dec->err     = DRAGON_DECODE_ERR_STATE;
          dec->err_txt = "data too large";
          return -1;
        }
      }
      have_data = 1;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return -1;
  }

  if( FD_UNLIKELY( !have_data ) ) {
    dec->err     = DRAGON_DECODE_ERR_STATE;
    dec->err_txt = "data for memcmp should be defined";
    return -1;
  }

  ulong off = dragon_state_bytes( dec, data_sz );
  if( FD_UNLIKELY( off==ULONG_MAX ) ) return -1;
  fd_memcpy( dec->set->state_byte+off, data, data_sz );
  st->data_off = (uint)off;
  st->data_sz  = (uint)data_sz;
  return 0;
}

/* dragon_decode_lamports decodes one lamports predicate
   (SubscribeRequestFilterAccountsFilterLamports), which is one
   comparison against a value. */

static int
dragon_decode_lamports( dragon_decode_t *        dec,
                        pb_istream_t *           stream,
                        fd_dragon_acct_state_t * st ) {
  int have_cmp = 0;

  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return -1;
    }

    if( tag>=1U && tag<=4U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      st->kind  = tag==1U ? FD_DRAGON_ACCT_STATE_LAMPORTS_EQ :
                  tag==2U ? FD_DRAGON_ACCT_STATE_LAMPORTS_NE :
                  tag==3U ? FD_DRAGON_ACCT_STATE_LAMPORTS_LT : FD_DRAGON_ACCT_STATE_LAMPORTS_GT;
      st->value = (ulong)v;
      have_cmp  = 1;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return -1;
  }

  if( FD_UNLIKELY( !have_cmp ) ) {
    dec->err     = DRAGON_DECODE_ERR_STATE;
    dec->err_txt = "cmp for lamports should be defined";
    return -1;
  }
  return 0;
}

/* dragon_decode_acct_state decodes one element of an accounts filter's
   filters list and appends it to the filter set's predicates. */

static int
dragon_decode_acct_state( dragon_decode_t *         dec,
                          pb_istream_t *            stream,
                          fd_dragon_filter_name_t * pred ) {
  fd_dragon_filter_set_t * set = dec->set;

  if( FD_UNLIKELY( (ulong)pred->state_cnt>=FD_DRAGON_ACCT_STATE_MAX ) ) {
    dec->err = DRAGON_DECODE_ERR_STATE_MAX;
    return -1;
  }
  if( FD_UNLIKELY( set->state_cnt>=FD_DRAGON_FILTER_STATE_MAX ) ) {
    dec->err = DRAGON_DECODE_ERR_STATE_ROOM;
    return -1;
  }

  fd_dragon_acct_state_t st[1];
  fd_memset( st, 0, sizeof(fd_dragon_acct_state_t) );
  int have = 0;

  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return -1;
    }

    if( tag==1U && wire_type==PB_WT_STRING ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return -1;
      if( FD_UNLIKELY( dragon_decode_memcmp( dec, &sub, st ) ) ) return -1;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return -1;
      have = 1;
      continue;
    }

    if( tag==2U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      /* Two data size predicates in one filter contradict each other
         wherever they differ, so yellowstone refuses the second. */
      for( ulong i=0UL; i<(ulong)pred->state_cnt; i++ ) {
        if( FD_UNLIKELY( set->state[ (ulong)pred->state_off+i ].kind==FD_DRAGON_ACCT_STATE_DATASIZE ) ) {
          dec->err     = DRAGON_DECODE_ERR_STATE;
          dec->err_txt = "datasize used more than once";
          return -1;
        }
      }
      st->kind  = FD_DRAGON_ACCT_STATE_DATASIZE;
      st->value = (ulong)v;
      have      = 1;
      continue;
    }

    if( tag==3U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      if( FD_UNLIKELY( !v ) ) {
        dec->err     = DRAGON_DECODE_ERR_STATE;
        dec->err_txt = "token_account_state only allowed to be true";
        return -1;
      }
      st->kind = FD_DRAGON_ACCT_STATE_TOKEN;
      have     = 1;
      continue;
    }

    if( tag==4U && wire_type==PB_WT_STRING ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return -1;
      if( FD_UNLIKELY( dragon_decode_lamports( dec, &sub, st ) ) ) return -1;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return -1;
      have = 1;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return -1;
  }

  if( FD_UNLIKELY( !have ) ) {
    dec->err     = DRAGON_DECODE_ERR_STATE;
    dec->err_txt = "filter should be defined";
    return -1;
  }

  /* The predicates of one filter are consecutive, so the first one
     fixes where the filter's range starts. */
  if( !pred->state_cnt ) pred->state_off = (ushort)set->state_cnt;
  set->state[ set->state_cnt++ ] = *st;
  pred->state_cnt++;
  return 0;
}

/* dragon_decode_acct_filter decodes the value of an accounts map entry
   (geyser.proto SubscribeRequestFilterAccounts). */

static int
dragon_decode_acct_filter( dragon_decode_t *         dec,
                           pb_istream_t *            stream,
                           fd_dragon_filter_name_t * pred ) {
  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return -1;
    }

    if( ( tag==2U || tag==3U ) && wire_type==PB_WT_STRING ) {
      uint32_t len;
      if( FD_UNLIKELY( !pb_decode_varint32( stream, &len ) ) ) return -1;
      char b58[ 128 ];
      if( FD_UNLIKELY( (ulong)len>=sizeof(b58) ) ) {
        dec->err = DRAGON_DECODE_ERR_PUBKEY;
        return -1;
      }
      if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)b58, (size_t)len ) ) ) return -1;

      ushort * off = tag==2U ? &pred->acct_off : &pred->owner_off;
      ushort * cnt = tag==2U ? &pred->acct_cnt : &pred->owner_cnt;
      ulong    max = tag==2U ? dec->limits->account_max : dec->limits->owner_max;
      int      rej = tag==2U ? FD_DRAGON_REJECT_ACCOUNT : FD_DRAGON_REJECT_OWNER;
      if( FD_UNLIKELY( dragon_acct_list_add( dec, off, cnt, b58, (ulong)len, max, rej ) ) ) return -1;
      continue;
    }

    if( tag==4U && wire_type==PB_WT_STRING ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return -1;
      if( FD_UNLIKELY( dragon_decode_acct_state( dec, &sub, pred ) ) ) return -1;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return -1;
      continue;
    }

    if( tag==5U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      pred->has_txn_sig = 1;
      pred->txn_sig     = !!v;
      continue;
    }

    if( tag==6U && wire_type==PB_WT_STRING ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return -1;
      if( FD_UNLIKELY( dragon_decode_cuckoo( dec, &sub, pred, FD_DRAGON_FILTER_ACCOUNTS ) ) ) return -1;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return -1;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return -1;
  }

  /* An accounts filter that names no account, owner or cuckoo set
     matches every account write, which an operator can forbid
     (plugin/filter/filter.rs:1231-1236). */
  if( FD_UNLIKELY( !dec->limits->any[ FD_DRAGON_FILTER_ACCOUNTS ] &&
                   !pred->acct_cnt && !pred->owner_cnt && !pred->cuckoo_bucket_cnt ) ) {
    dec->err = DRAGON_DECODE_ERR_ANY;
    return -1;
  }
  return 0;
}

/* dragon_decode_blocks_filter decodes the value of a blocks map entry
   (geyser.proto SubscribeRequestFilterBlocks).  A block carries its
   transactions unless the request turns them off, and its accounts and
   entries only when the request asks for them. */

static int
dragon_decode_blocks_filter( dragon_decode_t *         dec,
                             pb_istream_t *            stream,
                             fd_dragon_filter_name_t * pred ) {
  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return -1;
    }

    if( tag==1U && wire_type==PB_WT_STRING ) {
      uint32_t len;
      if( FD_UNLIKELY( !pb_decode_varint32( stream, &len ) ) ) return -1;
      char b58[ 128 ];
      if( FD_UNLIKELY( (ulong)len>=sizeof(b58) ) ) {
        dec->err = DRAGON_DECODE_ERR_PUBKEY;
        return -1;
      }
      if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)b58, (size_t)len ) ) ) return -1;
      if( FD_UNLIKELY( dragon_acct_list_add( dec, &pred->acct_off, &pred->acct_cnt, b58, (ulong)len,
                                             dec->limits->blocks_include_max,
                                             FD_DRAGON_REJECT_BLOCKS_INCLUDE ) ) ) return -1;
      continue;
    }

    if( tag>=2U && tag<=4U && wire_type==PB_WT_VARINT ) {
      uint64_t v;
      if( FD_UNLIKELY( !pb_decode_varint( stream, &v ) ) ) return -1;
      if     ( tag==2U ) pred->include_txns    = !!v;
      else if( tag==3U ) pred->include_accts   = !!v;
      else               pred->include_entries = !!v;
      continue;
    }

    if( tag==5U && wire_type==PB_WT_STRING ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return -1;
      if( FD_UNLIKELY( dragon_decode_cuckoo( dec, &sub, pred, FD_DRAGON_FILTER_BLOCKS ) ) ) return -1;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return -1;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return -1;
  }

  /* What a block may carry is the operator's to permit
     (plugin/filter/filter.rs:2126-2133). */
  if( FD_UNLIKELY( pred->include_txns    && !dec->limits->include_transactions ) ) {
    dec->err     = DRAGON_DECODE_ERR_INCLUDE;
    dec->err_txt = "transactions";
    return -1;
  }
  if( FD_UNLIKELY( pred->include_accts   && !dec->limits->include_accounts ) ) {
    dec->err     = DRAGON_DECODE_ERR_INCLUDE;
    dec->err_txt = "accounts";
    return -1;
  }
  if( FD_UNLIKELY( pred->include_entries && !dec->limits->include_entries ) ) {
    dec->err     = DRAGON_DECODE_ERR_INCLUDE;
    dec->err_txt = "entries";
    return -1;
  }

  if( FD_UNLIKELY( !dec->limits->any[ FD_DRAGON_FILTER_BLOCKS ] &&
                   !pred->acct_cnt && !pred->cuckoo_bucket_cnt ) ) {
    dec->err = DRAGON_DECODE_ERR_ANY;
    return -1;
  }
  return 0;
}

/* dragon_decode_map_entry decodes one entry of a filter map.  The key
   is the client chosen filter name.  The value holds the predicates;
   only a slots filter's two flags are kept, the other predicates are
   skipped without being materialized. */

static bool
dragon_decode_map_entry( pb_istream_t *     stream,
                         pb_field_t const * field,
                         void **            arg ) {
  (void)field;
  dragon_decode_map_t * map = *arg;
  dragon_decode_t *     dec = map->dec;

  char  name[ FD_DRAGON_FILTER_NAME_MAX+1UL ];
  ulong name_len  = 0UL;
  int   have_name = 0;

  fd_dragon_filter_name_t pred[1];
  fd_memset( pred, 0, sizeof(fd_dragon_filter_name_t) );

  /* A blocks filter that says nothing about transactions carries them
     (plugin/filter/filter.rs:2165). */
  if( map->type==FD_DRAGON_FILTER_BLOCKS ) pred->include_txns = 1;

  for(;;) {
    pb_wire_type_t wire_type;
    uint32_t       tag;
    bool           eof = false;
    if( FD_UNLIKELY( !pb_decode_tag( stream, &wire_type, &tag, &eof ) ) ) {
      if( eof ) break;
      return false;
    }

    if( tag==1U && wire_type==PB_WT_STRING ) {
      uint32_t len;
      if( FD_UNLIKELY( !pb_decode_varint32( stream, &len ) ) ) return false;
      if( FD_UNLIKELY( (ulong)len>FD_DRAGON_FILTER_NAME_MAX ) ) {
        dec->err     = DRAGON_DECODE_ERR_NAME_SZ;
        dec->err_val = (ulong)len;
        return false;
      }
      if( FD_UNLIKELY( !pb_read( stream, (pb_byte_t *)name, (size_t)len ) ) ) return false;
      name_len  = (ulong)len;
      have_name = 1;
      continue;
    }

    if( tag==2U && wire_type==PB_WT_STRING && map->type==FD_DRAGON_FILTER_SLOTS ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return false;
      geyser_SubscribeRequestFilterSlots slots = geyser_SubscribeRequestFilterSlots_init_zero;
      if( FD_UNLIKELY( !pb_decode( &sub, geyser_SubscribeRequestFilterSlots_fields, &slots ) ) ) return false;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return false;
      pred->filter_by_commitment = slots.has_filter_by_commitment && slots.filter_by_commitment;
      pred->interslot_updates    = slots.has_interslot_updates    && slots.interslot_updates;
      continue;
    }

    if( tag==2U && wire_type==PB_WT_STRING &&
        ( map->type==FD_DRAGON_FILTER_TRANSACTIONS ||
          map->type==FD_DRAGON_FILTER_TRANSACTIONS_STATUS ) ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return false;
      if( FD_UNLIKELY( dragon_decode_txn_filter( dec, &sub, pred, map->type ) ) ) return false;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return false;
      continue;
    }

    if( tag==2U && wire_type==PB_WT_STRING && map->type==FD_DRAGON_FILTER_ACCOUNTS ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return false;
      if( FD_UNLIKELY( dragon_decode_acct_filter( dec, &sub, pred ) ) ) return false;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return false;
      continue;
    }

    if( tag==2U && wire_type==PB_WT_STRING && map->type==FD_DRAGON_FILTER_BLOCKS ) {
      pb_istream_t sub;
      if( FD_UNLIKELY( !pb_make_string_substream( stream, &sub ) ) ) return false;
      if( FD_UNLIKELY( dragon_decode_blocks_filter( dec, &sub, pred ) ) ) return false;
      if( FD_UNLIKELY( !pb_close_string_substream( stream, &sub ) ) ) return false;
      continue;
    }

    if( FD_UNLIKELY( !pb_skip_field( stream, wire_type ) ) ) return false;
  }

  /* A map entry with no key is a name of length zero, which is what a
     protobuf implementation sends for an empty string key. */
  if( !have_name ) name_len = 0UL;

  return dragon_filter_name_add( dec, map->type, name, name_len, pred )==0;
}

/* dragon_decode_data_slice decodes one accounts_data_slice element. */

static bool
dragon_decode_data_slice( pb_istream_t *     stream,
                          pb_field_t const * field,
                          void **            arg ) {
  (void)field;
  dragon_decode_t *        dec = *arg;
  fd_dragon_filter_set_t * set = dec->set;

  geyser_SubscribeRequestAccountsDataSlice slice = geyser_SubscribeRequestAccountsDataSlice_init_zero;
  if( FD_UNLIKELY( !pb_decode( stream, geyser_SubscribeRequestAccountsDataSlice_fields, &slice ) ) ) return false;

  if( FD_UNLIKELY( set->slice_cnt>=dec->limits->data_slice_max ) ) {
    dec->err     = DRAGON_DECODE_ERR_SLICE_MAX;
    dec->err_val = dec->limits->data_slice_max;
    return false;
  }
  if( FD_UNLIKELY( set->slice_cnt>=FD_DRAGON_DATA_SLICE_MAX ) ) {
    dec->err     = DRAGON_DECODE_ERR_SLICE_MAX;
    dec->err_val = FD_DRAGON_DATA_SLICE_MAX;
    return false;
  }

  set->slice[ set->slice_cnt ].offset = slice.offset;
  set->slice[ set->slice_cnt ].length = slice.length;
  set->slice_cnt++;
  return true;
}

/* dragon_data_slice_check rejects slices that are out of order or
   overlap, like yellowstone's FilterAccountsDataSlice::new. */

static int
dragon_data_slice_check( dragon_decode_t * dec ) {
  fd_dragon_filter_set_t * set = dec->set;
  for( ulong i=0UL; i<set->slice_cnt; i++ ) {
    ulong start_a = set->slice[ i ].offset;
    for( ulong j=i+1UL; j<set->slice_cnt; j++ ) {
      if( FD_UNLIKELY( start_a>set->slice[ j ].offset ) ) {
        dec->err = DRAGON_DECODE_ERR_SLICE_ORDER;
        return -1;
      }
    }
    for( ulong j=0UL; j<i; j++ ) {
      ulong off_b = set->slice[ j ].offset;
      if( FD_UNLIKELY( start_a<off_b || start_a-off_b<set->slice[ j ].length ) ) {
        dec->err = DRAGON_DECODE_ERR_SLICE_OVERLAP;
        return -1;
      }
    }
  }
  return 0;
}

FD_FN_PURE int
fd_dragon_slots_match( fd_dragon_filter_name_t const * name,
                       int                             commitment,
                       int                             status ) {
  if( FD_UNLIKELY( name->filter_by_commitment ) ) {
    int level = status==FD_GEYSER_SLOT_PROCESSED ? FD_DRAGON_COMMITMENT_PROCESSED :
                status==FD_GEYSER_SLOT_CONFIRMED ? FD_DRAGON_COMMITMENT_CONFIRMED :
                status==FD_GEYSER_SLOT_FINALIZED ? FD_DRAGON_COMMITMENT_FINALIZED : -1;
    if( level!=commitment ) return 0;
  }
  if( FD_LIKELY( name->interslot_updates ) ) return 1;
  return status==FD_GEYSER_SLOT_PROCESSED ||
         status==FD_GEYSER_SLOT_CONFIRMED ||
         status==FD_GEYSER_SLOT_FINALIZED;
}

/* dragon_cuckoo_of fills f with the cuckoo filter of one filter name,
   and returns it, or NULL if the filter carries none. */

FD_FN_PURE static fd_dragon_cuckoo_t *
dragon_cuckoo_of( fd_dragon_filter_set_t const *  set,
                  fd_dragon_filter_name_t const * name,
                  fd_dragon_cuckoo_t *            f ) {
  if( FD_LIKELY( !name->cuckoo_bucket_cnt ) ) return NULL;
  f->seed       = name->cuckoo_seed;
  f->bucket_cnt = (ulong)name->cuckoo_bucket_cnt;
  f->bucket     = set->cuckoo + name->cuckoo_off;
  return f;
}

/* dragon_cuckoo_has_key returns 1 if the filter's cuckoo set probably
   holds one of the keys. */

FD_FN_PURE static int
dragon_cuckoo_has_key( fd_dragon_filter_set_t const *  set,
                       fd_dragon_filter_name_t const * name,
                       uchar const                     (* keys)[ 32UL ],
                       ulong                           key_cnt ) {
  fd_dragon_cuckoo_t f[1];
  if( FD_LIKELY( !dragon_cuckoo_of( set, name, f ) ) ) return 0;
  for( ulong i=0UL; i<key_cnt; i++ ) {
    if( fd_dragon_cuckoo_contains32( f, keys[ i ] ) ) return 1;
  }
  return 0;
}

FD_FN_PURE static int
dragon_cuckoo_has( fd_dragon_filter_set_t const *  set,
                   fd_dragon_filter_name_t const * name,
                   uchar const *                   pubkey ) {
  fd_dragon_cuckoo_t f[1];
  if( FD_LIKELY( !dragon_cuckoo_of( set, name, f ) ) ) return 0;
  return fd_dragon_cuckoo_contains32( f, pubkey );
}

/* dragon_key_in returns 1 if one of the transaction's keys is in the
   filter list [off,off+cnt) of the address pool.  A transaction has
   tens of keys and a list can have hundreds of addresses, so which
   side is the outer loop only matters for the largest lists. */

FD_FN_PURE static int
dragon_key_in( fd_dragon_filter_set_t const * set,
               ulong                          off,
               ulong                          cnt,
               uchar const                    (* keys)[ 32UL ],
               ulong                          key_cnt ) {
  for( ulong i=0UL; i<key_cnt; i++ ) {
    for( ulong j=0UL; j<cnt; j++ ) {
      if( fd_memeq( keys[ i ], set->acct[ off+j ], 32UL ) ) return 1;
    }
  }
  return 0;
}

FD_FN_PURE int
fd_dragon_txn_match( fd_dragon_filter_set_t const *  set,
                     fd_dragon_filter_name_t const * name,
                     uchar const *                   signature,
                     int                             is_vote,
                     int                             failed,
                     uchar const                     (* keys)[ 32UL ],
                     ulong                           key_cnt ) {
  if( name->has_vote   && !!name->vote  !=!!is_vote ) return 0;
  if( name->has_failed && !!name->failed!=!!failed  ) return 0;
  if( name->has_signature && !fd_memeq( name->signature, signature, 64UL ) ) return 0;

  for( ulong j=0UL; j<(ulong)name->required_cnt; j++ ) {
    int found = 0;
    for( ulong i=0UL; i<key_cnt && !found; i++ ) {
      found = fd_memeq( keys[ i ], set->acct[ (ulong)name->required_off+j ], 32UL );
    }
    if( !found ) return 0;
  }

  /* The account set to include is the explicit list and the cuckoo
     filter together: a key in either one is a hit, and only a filter
     that carries neither matches every transaction. */
  if( ( name->include_cnt || name->cuckoo_bucket_cnt ) &&
      !( name->include_cnt &&
         dragon_key_in( set, (ulong)name->include_off, (ulong)name->include_cnt, keys, key_cnt ) ) &&
      !dragon_cuckoo_has_key( set, name, keys, key_cnt ) ) return 0;

  if( name->exclude_cnt &&
      dragon_key_in( set, (ulong)name->exclude_off, (ulong)name->exclude_cnt, keys, key_cnt ) ) return 0;

  return 1;
}

/* dragon_acct_listed returns 1 if the address is in the filter list
   [off,off+cnt) of the address pool. */

FD_FN_PURE static int
dragon_acct_listed( fd_dragon_filter_set_t const * set,
                    ulong                          off,
                    ulong                          cnt,
                    uchar const *                  pubkey ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( fd_memeq( set->acct[ off+i ], pubkey, 32UL ) ) return 1;
  }
  return 0;
}

/* dragon_token_account returns 1 if the bytes are the state of an
   initialized SPL token account, which is what yellowstone's
   token_account_state predicate asks
   (spl-token-2022-interface state.rs:317-325,
   generic_token_account.rs:55-65): an account of the packed length, or
   a longer one that is not a multisig and carries the token account
   type marker behind the packed account, whose state field is not
   uninitialized.  */

#define DRAGON_TOKEN_ACCOUNT_SZ   (165UL)
#define DRAGON_TOKEN_MULTISIG_SZ  (355UL)
#define DRAGON_TOKEN_STATE_OFF    (108UL)
#define DRAGON_TOKEN_TYPE_ACCOUNT    (2U)

FD_FN_PURE static int
dragon_token_account( uchar const * data,
                      ulong         data_sz ) {
  if( FD_UNLIKELY( data_sz<DRAGON_TOKEN_ACCOUNT_SZ ) ) return 0;
  if( FD_UNLIKELY( !data[ DRAGON_TOKEN_STATE_OFF ] ) ) return 0; /* uninitialized */
  if( data_sz==DRAGON_TOKEN_ACCOUNT_SZ ) return 1;
  return data_sz!=DRAGON_TOKEN_MULTISIG_SZ &&
         data[ DRAGON_TOKEN_ACCOUNT_SZ ]==DRAGON_TOKEN_TYPE_ACCOUNT;
}

FD_FN_PURE static int
dragon_state_match( fd_dragon_acct_state_t const * st,
                    uchar const *                  state_byte,
                    ulong                          lamports,
                    uchar const *                  data,
                    ulong                          data_sz ) {
  switch( st->kind ) {
  case FD_DRAGON_ACCT_STATE_DATASIZE:    return data_sz==st->value;
  case FD_DRAGON_ACCT_STATE_TOKEN:       return dragon_token_account( data, data_sz );
  case FD_DRAGON_ACCT_STATE_LAMPORTS_EQ: return lamports==st->value;
  case FD_DRAGON_ACCT_STATE_LAMPORTS_NE: return lamports!=st->value;
  case FD_DRAGON_ACCT_STATE_LAMPORTS_LT: return lamports< st->value;
  case FD_DRAGON_ACCT_STATE_LAMPORTS_GT: return lamports> st->value;
  default: break;
  }

  /* memcmp: the account has to be long enough to hold the whole
     comparison, and the bytes there have to be it. */
  if( FD_UNLIKELY( st->offset>data_sz ||
                   (ulong)st->data_sz>data_sz-st->offset ) ) return 0;
  return fd_memeq( data+st->offset, state_byte+st->data_off, (ulong)st->data_sz );
}

FD_FN_PURE int
fd_dragon_acct_match( fd_dragon_filter_set_t const *  set,
                      fd_dragon_filter_name_t const * name,
                      uchar const *                   pubkey,
                      uchar const *                   owner,
                      ulong                           lamports,
                      uchar const *                   data,
                      ulong                           data_sz,
                      int                             has_txn_sig ) {
  if( name->has_txn_sig && !!name->txn_sig!=!!has_txn_sig ) return 0;

  if( ( name->acct_cnt || name->cuckoo_bucket_cnt ) &&
      !( name->acct_cnt &&
         dragon_acct_listed( set, (ulong)name->acct_off, (ulong)name->acct_cnt, pubkey ) ) &&
      !dragon_cuckoo_has( set, name, pubkey ) ) return 0;

  if( name->owner_cnt &&
      !dragon_acct_listed( set, (ulong)name->owner_off, (ulong)name->owner_cnt, owner ) ) return 0;

  for( ulong i=0UL; i<(ulong)name->state_cnt; i++ ) {
    if( !dragon_state_match( set->state + (ulong)name->state_off + i, set->state_byte,
                             lamports, data, data_sz ) ) return 0;
  }
  return 1;
}

FD_FN_PURE int
fd_dragon_blocks_txn_match( fd_dragon_filter_set_t const *  set,
                            fd_dragon_filter_name_t const * name,
                            uchar const                     (* keys)[ 32UL ],
                            ulong                           key_cnt ) {
  if( FD_LIKELY( !name->acct_cnt && !name->cuckoo_bucket_cnt ) ) return 1;
  if( name->acct_cnt &&
      dragon_key_in( set, (ulong)name->acct_off, (ulong)name->acct_cnt, keys, key_cnt ) ) return 1;
  return dragon_cuckoo_has_key( set, name, keys, key_cnt );
}

FD_FN_PURE int
fd_dragon_blocks_acct_match( fd_dragon_filter_set_t const *  set,
                             fd_dragon_filter_name_t const * name,
                             uchar const *                   pubkey ) {
  if( FD_LIKELY( !name->acct_cnt && !name->cuckoo_bucket_cnt ) ) return 1;
  if( name->acct_cnt &&
      dragon_acct_listed( set, (ulong)name->acct_off, (ulong)name->acct_cnt, pubkey ) ) return 1;
  return dragon_cuckoo_has( set, name, pubkey );
}

void
fd_dragon_filter_set_init( fd_dragon_filter_set_t * set,
                           ushort *                 cuckoo,
                           ulong                    cuckoo_entry_max ) {
  fd_memset( set, 0, sizeof(fd_dragon_filter_set_t) );
  set->commitment       = FD_DRAGON_COMMITMENT_PROCESSED;
  set->cuckoo           = cuckoo;
  set->cuckoo_entry_max = cuckoo ? cuckoo_entry_max : 0UL;
}

void
fd_dragon_filter_set_adopt( fd_dragon_filter_set_t *       dst,
                            fd_dragon_filter_set_t const * src,
                            ushort *                       cuckoo,
                            ulong                          cuckoo_entry_max ) {
  *dst                  = *src;
  dst->cuckoo           = cuckoo;
  dst->cuckoo_entry_max = cuckoo ? cuckoo_entry_max : 0UL;
  dst->cuckoo_entry_cnt = fd_ulong_min( src->cuckoo_entry_cnt, dst->cuckoo_entry_max );
  if( FD_UNLIKELY( dst->cuckoo_entry_cnt ) ) {
    fd_memcpy( dst->cuckoo, src->cuckoo, dst->cuckoo_entry_cnt*sizeof(ushort) );
  }
}

void
fd_dragon_filter_limits_default( fd_dragon_filter_limits_t * limits ) {
  fd_memset( limits, 0, sizeof(fd_dragon_filter_limits_t) );
  for( ulong i=0UL; i<FD_DRAGON_FILTER_TYPE_CNT; i++ ) {
    limits->filter_max     [ i ] = FD_DRAGON_FILTER_MAX;
    limits->any            [ i ] = 1;
    limits->cuckoo_max_size[ i ] = ULONG_MAX;
  }
  limits->account_max         = FD_DRAGON_FILTER_ACCT_MAX;
  limits->owner_max           = FD_DRAGON_FILTER_ACCT_MAX;
  limits->data_slice_max      = FD_DRAGON_DATA_SLICE_MAX;
  limits->txn_include_max     = FD_DRAGON_FILTER_ACCT_MAX;
  limits->txn_exclude_max     = FD_DRAGON_FILTER_ACCT_MAX;
  limits->txn_required_max    = FD_DRAGON_FILTER_ACCT_MAX;
  limits->status_include_max  = FD_DRAGON_FILTER_ACCT_MAX;
  limits->status_exclude_max  = FD_DRAGON_FILTER_ACCT_MAX;
  limits->status_required_max = FD_DRAGON_FILTER_ACCT_MAX;
  limits->blocks_include_max  = FD_DRAGON_FILTER_ACCT_MAX;
  limits->include_transactions = 1;
  limits->include_accounts     = 1;
  limits->include_entries      = 1;
}

static void
dragon_decode_err_cstr( dragon_decode_t const * dec,
                        char *                  err,
                        ulong                   err_sz ) {
  switch( dec->err ) {
  case DRAGON_DECODE_ERR_NAME_SZ:
    fd_cstr_printf( err, err_sz, NULL, "oversized filter name (max allowed size %lu), found %lu",
                    FD_DRAGON_FILTER_NAME_MAX, dec->err_val );
    break;
  case DRAGON_DECODE_ERR_FILTER_MAX:
  case DRAGON_DECODE_ERR_SLICE_MAX:
    fd_cstr_printf( err, err_sz, NULL, "Max amount of filters/data_slices reached, only %lu allowed",
                    dec->err_val );
    break;
  case DRAGON_DECODE_ERR_NAMES_MAX:
    fd_cstr_printf( err, err_sz, NULL, "Max amount of filters/data_slices reached, only %lu allowed",
                    FD_DRAGON_FILTER_NAMES_MAX );
    break;
  case DRAGON_DECODE_ERR_SLICE_ORDER:
    fd_cstr_printf( err, err_sz, NULL, "failed to create filter: data slices out of order" );
    break;
  case DRAGON_DECODE_ERR_SLICE_OVERLAP:
    fd_cstr_printf( err, err_sz, NULL, "failed to create filter: data slices overlapped" );
    break;
  case DRAGON_DECODE_ERR_COMMITMENT:
    fd_cstr_printf( err, err_sz, NULL, "failed to create CommitmentLevel from %ld", (long)dec->err_val );
    break;
  case DRAGON_DECODE_ERR_PUBKEY:
  case DRAGON_DECODE_ERR_SIGNATURE:
    fd_cstr_printf( err, err_sz, NULL, "Invalid Base58 string" );
    break;
  case DRAGON_DECODE_ERR_PUBKEY_MAX:
    fd_cstr_printf( err, err_sz, NULL, "Max amount of Pubkeys reached, only %lu allowed",
                    dec->err_val );
    break;
  case DRAGON_DECODE_ERR_ANY:
    fd_cstr_printf( err, err_sz, NULL,
                    "Subscribe on full stream with `any` is not allowed, at least one filter required" );
    break;
  case DRAGON_DECODE_ERR_REJECT: {
    char b58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( dec->err_key, NULL, b58 );
    fd_cstr_printf( err, err_sz, NULL, "Pubkey %s in filters is not allowed", b58 );
    break;
  }
  case DRAGON_DECODE_ERR_INCLUDE:
    fd_cstr_printf( err, err_sz, NULL, "`include_%s` is not allowed",
                    dec->err_txt ? dec->err_txt : "transactions" );
    break;
  case DRAGON_DECODE_ERR_TOKEN_MODE:
    fd_cstr_printf( err, err_sz, NULL,
                    "invalid token_accounts mode value %lu; expected ALL (0) or BALANCE_CHANGED (1)",
                    dec->err_val );
    break;
  case DRAGON_DECODE_ERR_CUCKOO:
    fd_cstr_printf( err, err_sz, NULL, "Max amount of filters/data_slices reached, only %lu allowed",
                    dec->err_val );
    break;
  case DRAGON_DECODE_ERR_CUCKOO_ROOM:
    fd_cstr_printf( err, err_sz, NULL,
                    "cuckoo filters of one subscription have to fit %lu bytes on this server",
                    dec->err_val );
    break;
  case DRAGON_DECODE_ERR_STATE_MAX:
    fd_cstr_printf( err, err_sz, NULL, "Too many filters provided; max %lu", FD_DRAGON_ACCT_STATE_MAX );
    break;
  case DRAGON_DECODE_ERR_STATE_ROOM:
    fd_cstr_printf( err, err_sz, NULL, "Max amount of filters/data_slices reached, only %lu allowed",
                    FD_DRAGON_FILTER_STATE_MAX );
    break;
  case DRAGON_DECODE_ERR_STATE:
    fd_cstr_printf( err, err_sz, NULL, "%s", dec->err_txt ? dec->err_txt : "filter should be defined" );
    break;
  default:
    fd_cstr_printf( err, err_sz, NULL, "failed to decode SubscribeRequest" );
    break;
  }
}

int
fd_dragon_filter_decode( fd_dragon_filter_set_t *          set,
                         fd_dragon_filter_limits_t const * limits,
                         ushort *                          cuckoo,
                         ulong                             cuckoo_entry_max,
                         ulong *                           names_seen,
                         uchar const *                     msg,
                         ulong                             msg_sz,
                         char *                            err,
                         ulong                             err_sz ) {
  fd_dragon_filter_set_init( set, cuckoo, cuckoo_entry_max );

  fd_dragon_filter_limits_t dflt[1];
  if( FD_UNLIKELY( !limits ) ) {
    fd_dragon_filter_limits_default( dflt );
    limits = dflt;
  }

  dragon_decode_t dec = { .set = set, .limits = limits, .names_seen = *names_seen,
                          .err = DRAGON_DECODE_ERR_NONE, .err_txt = NULL };

  dragon_decode_map_t map[ FD_DRAGON_FILTER_TYPE_CNT ];
  for( ulong i=0UL; i<FD_DRAGON_FILTER_TYPE_CNT; i++ ) {
    map[ i ].dec  = &dec;
    map[ i ].type = (int)i;
  }

  geyser_SubscribeRequest req = geyser_SubscribeRequest_init_zero;

  req.accounts.funcs.decode            = dragon_decode_map_entry;
  req.accounts.arg                     = map + FD_DRAGON_FILTER_ACCOUNTS;
  req.slots.funcs.decode               = dragon_decode_map_entry;
  req.slots.arg                        = map + FD_DRAGON_FILTER_SLOTS;
  req.transactions.funcs.decode        = dragon_decode_map_entry;
  req.transactions.arg                 = map + FD_DRAGON_FILTER_TRANSACTIONS;
  req.transactions_status.funcs.decode  = dragon_decode_map_entry;
  req.transactions_status.arg           = map + FD_DRAGON_FILTER_TRANSACTIONS_STATUS;
  req.blocks.funcs.decode              = dragon_decode_map_entry;
  req.blocks.arg                       = map + FD_DRAGON_FILTER_BLOCKS;
  req.blocks_meta.funcs.decode         = dragon_decode_map_entry;
  req.blocks_meta.arg                  = map + FD_DRAGON_FILTER_BLOCKS_META;
  req.entry.funcs.decode               = dragon_decode_map_entry;
  req.entry.arg                        = map + FD_DRAGON_FILTER_ENTRY;
  req.accounts_data_slice.funcs.decode = dragon_decode_data_slice;
  req.accounts_data_slice.arg          = &dec;

  pb_istream_t stream = pb_istream_from_buffer( (pb_byte_t const *)msg, (size_t)msg_sz );
  if( FD_UNLIKELY( !pb_decode( &stream, geyser_SubscribeRequest_fields, &req ) ) ) {
    dragon_decode_err_cstr( &dec, err, err_sz );
    fd_dragon_filter_set_init( set, cuckoo, cuckoo_entry_max );
    return -1;
  }

  if( req.has_commitment ) {
    int commitment = (int)req.commitment;
    if( FD_UNLIKELY( commitment!=FD_DRAGON_COMMITMENT_PROCESSED &&
                     commitment!=FD_DRAGON_COMMITMENT_CONFIRMED &&
                     commitment!=FD_DRAGON_COMMITMENT_FINALIZED ) ) {
      dec.err     = DRAGON_DECODE_ERR_COMMITMENT;
      dec.err_val = (ulong)(long)commitment;
      dragon_decode_err_cstr( &dec, err, err_sz );
      fd_dragon_filter_set_init( set, cuckoo, cuckoo_entry_max );
      return -1;
    }
    set->commitment = commitment;
  }

  if( FD_UNLIKELY( dragon_data_slice_check( &dec ) ) ) {
    dragon_decode_err_cstr( &dec, err, err_sz );
    fd_dragon_filter_set_init( set, cuckoo, cuckoo_entry_max );
    return -1;
  }

  set->has_ping = !!req.has_ping;
  set->ping_id  = req.has_ping ? req.ping.id : 0;

  set->has_from_slot = !!req.has_from_slot;
  set->from_slot     = req.has_from_slot ? req.from_slot : 0UL;

  *names_seen = dec.names_seen;
  err[ 0 ] = '\0';
  return 0;
}
