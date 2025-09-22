#include "fd_slot_delta_parser.h"

#define SLOT_DELTA_PARSER_DEBUG 0

#define STATE_SLOT_DELTAS_LEN                                    ( 0)
#define STATE_SLOT_DELTA_SLOT                                    ( 1)
#define STATE_SLOT_DELTA_IS_ROOT                                 ( 2)
#define STATE_SLOT_DELTA_STATUS_LEN                              ( 3)
#define STATE_STATUS_BLOCKHASH                                   ( 4)
#define STATE_STATUS_TXN_IDX                                     ( 5)
#define STATE_CACHE_STATUS_LEN                                   ( 6)
#define STATE_CACHE_STATUS_KEY_SLICE                             ( 7)
#define STATE_CACHE_STATUS_RESULT                                ( 8)
#define STATE_CACHE_STATUS_RESULT_ERR                            ( 9)
#define STATE_CACHE_STATUS_RESULT_ERR_INSTR_IDX                  (10)
#define STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR                  (11)
#define STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM           (12)
#define STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_LEN (13)
#define STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_ERR (14)
#define STATE_CACHE_STATUS_RESULT_ERR_IDX                        (15)
#define STATE_DONE                                               (16)

#define FD_SLOT_DELTA_PARSER_SLOT_SET_MAX_ENTRIES (512UL)

struct fd_slot_delta_parser_private {
  int     state;                       /* parser state machine */
  int     entry_avail;                 /* whether a parsed entry is available */
  int     group_avail;                 /* whether a parsed group is available */

  uchar * dst;                         /* where to store the next parsed value */
  ulong   dst_cur;                     /* offset into dst */
  ulong   dst_sz;                      /* size of dst */

  ulong   len;                         /* number of slot delta entries */
  int     is_root;                     /* whether the current slot delta entry is rooted */
  ulong   txnhash_offset;              /* offset into the txncache for the current slot delta entry */
  ulong   slot_delta_status_len;       /* number of blockhashes in the slot delta entry */
  ulong   cache_status_len;            /* number of txns associated with the blockhash */
  ulong   borsh_io_error_len;          /* used to parse a variable len borsh_io_error string */
  uint    error_discriminant;          /* stores the error discriminant of a txn result */
  uchar   error;                       /* stores the error code of a txn result */

  fd_slot_entry_t * slot_pool;         /* pool backing a slot hashset */
  slot_set_t *      slot_set;          /* slot hash set to detect duplicate slots */
  ulong             slot_pool_ele_cnt; /* count of slots in pool */
  fd_sstxncache_entry_t entry[1];      /* parsed slot delta entry */
};

static inline ulong
state_size( fd_slot_delta_parser_t * parser ) {
  switch( parser->state ) {
    case STATE_SLOT_DELTAS_LEN:                                    return sizeof(ulong);
    case STATE_SLOT_DELTA_SLOT:                                    return sizeof(ulong);
    case STATE_SLOT_DELTA_IS_ROOT:                                 return sizeof(uchar);
    case STATE_SLOT_DELTA_STATUS_LEN:                              return sizeof(ulong);
    case STATE_STATUS_BLOCKHASH:                                   return 32UL;
    case STATE_STATUS_TXN_IDX:                                     return sizeof(ulong);
    case STATE_CACHE_STATUS_LEN:                                   return sizeof(ulong);
    case STATE_CACHE_STATUS_KEY_SLICE:                             return 20UL;
    case STATE_CACHE_STATUS_RESULT:                                return sizeof(uint);
    case STATE_CACHE_STATUS_RESULT_ERR:                            return sizeof(uint);
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_IDX:                  return sizeof(uchar);
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR:                  return sizeof(uint);
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM:           return sizeof(uint);
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_LEN: return sizeof(ulong);
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_ERR: return parser->borsh_io_error_len;
    case STATE_CACHE_STATUS_RESULT_ERR_IDX:                        return sizeof(uchar);
    case STATE_DONE:                                               return 0UL;
    default: FD_LOG_ERR(( "unknown state %d", parser->state ));
  }
}

static inline uchar *
state_dst( fd_slot_delta_parser_t * parser ) {
  switch( parser->state ) {
    case STATE_SLOT_DELTAS_LEN:                                    return (uchar*)&parser->len;
    case STATE_SLOT_DELTA_SLOT:                                    return (uchar*)&parser->entry->slot;
    case STATE_SLOT_DELTA_IS_ROOT:                                 return (uchar*)&parser->is_root;
    case STATE_SLOT_DELTA_STATUS_LEN:                              return (uchar*)&parser->slot_delta_status_len;
    case STATE_STATUS_BLOCKHASH:                                   return parser->entry->blockhash;
    case STATE_STATUS_TXN_IDX:                                     return (uchar*)&parser->txnhash_offset;
    case STATE_CACHE_STATUS_LEN:                                   return (uchar*)&parser->cache_status_len;
    case STATE_CACHE_STATUS_KEY_SLICE:                             return parser->entry->txnhash;
    case STATE_CACHE_STATUS_RESULT:                                return (uchar*)&parser->error_discriminant;
    case STATE_CACHE_STATUS_RESULT_ERR:                            return (uchar*)&parser->error_discriminant;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_IDX:                  return NULL;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR:                  return (uchar*)&parser->error_discriminant;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM:           return (uchar*)&parser->error_discriminant;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_LEN: return (uchar*)&parser->borsh_io_error_len;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_ERR: return NULL;
    case STATE_CACHE_STATUS_RESULT_ERR_IDX:                        return (uchar*)&parser->error;
    case STATE_DONE:                                               return NULL;
    default: FD_LOG_ERR(( "unknown state %d", parser->state ));
  }
}

#if SLOT_DELTA_PARSER_DEBUG
static inline void
state_log( fd_slot_delta_parser_t * parser ) {
  switch( parser->state ) {
    case STATE_SLOT_DELTAS_LEN:        FD_LOG_NOTICE(( "STATE_SLOT_DELTAS_LEN:        %lu", parser->len ));                                         break;
    case STATE_SLOT_DELTA_SLOT:        FD_LOG_NOTICE(( "STATE_SLOT_DELTA_SLOT:        %lu", parser->entry->slot ));                                 break;
    case STATE_SLOT_DELTA_IS_ROOT:     FD_LOG_NOTICE(( "STATE_SLOT_DELTA_IS_ROOT:     %d",  parser->is_root ));                                     break;
    case STATE_SLOT_DELTA_STATUS_LEN:  FD_LOG_NOTICE(( "STATE_SLOT_DELTA_STATUS_LEN:  %lu", parser->slot_delta_status_len ));                       break;
    case STATE_STATUS_BLOCKHASH:       FD_LOG_NOTICE(( "STATE_STATUS_BLOCKHASH:       %s",  FD_BASE58_ENC_32_ALLOCA( parser->entry->blockhash ) )); break;
    case STATE_CACHE_STATUS_LEN:       FD_LOG_NOTICE(( "STATE_CACHE_STATUS_LEN:       %lu", parser->cache_status_len ));                            break;
    default: break;
  }
}
#endif

static inline int
state_validate( fd_slot_delta_parser_t * parser ) {
  switch( parser->state ) {
    case STATE_SLOT_DELTAS_LEN:
      if( FD_UNLIKELY( parser->len>FD_SLOT_DELTA_MAX_ENTRIES ) ) {
        return FD_SLOT_DELTA_PARSER_ADVANCE_ERROR_TOO_MANY_ENTRIES;
      }
      break;
    case STATE_SLOT_DELTA_SLOT: {
      ulong slot_idx = slot_set_idx_query_const( parser->slot_set, &parser->entry->slot, ULONG_MAX, parser->slot_pool );
      if( FD_UNLIKELY( slot_idx!=ULONG_MAX ) ) return FD_SLOT_DELTA_PARSER_ADVANCE_ERROR_SLOT_HASH_MULTIPLE_ENTRIES;

      if( FD_UNLIKELY( parser->slot_pool_ele_cnt>=FD_SLOT_DELTA_MAX_ENTRIES ) ) {
        return FD_SLOT_DELTA_PARSER_ADVANCE_ERROR_TOO_MANY_ENTRIES;
      }

      fd_slot_entry_t * slot_entry = &parser->slot_pool[ parser->slot_pool_ele_cnt++ ];
      slot_entry->slot             = parser->entry->slot;
      slot_set_ele_insert( parser->slot_set, slot_entry, parser->slot_pool );
      break;
    }
    case STATE_SLOT_DELTA_IS_ROOT:
      if( FD_UNLIKELY( !parser->is_root) ) {
        return FD_SLOT_DELTA_PARSER_ADVANCE_ERROR_SLOT_IS_NOT_ROOT;
      }
      break;
    default: break;
  }

  return 0;
}

static inline void
loop( fd_slot_delta_parser_t * parser ) {
  if( FD_LIKELY( parser->cache_status_len ) ) {
    parser->state = STATE_CACHE_STATUS_KEY_SLICE;
  } else if( FD_LIKELY( parser->slot_delta_status_len ) ) {
    parser->state = STATE_STATUS_BLOCKHASH;
  } else if( FD_LIKELY( parser->len ) ) {
    parser->state = STATE_SLOT_DELTA_SLOT;
  } else {
    parser->state = STATE_DONE;
  }
}

static inline void
result_loop( fd_slot_delta_parser_t * parser ) {
  parser->entry_avail = 1;
  loop( parser );
}

static inline int
state_process( fd_slot_delta_parser_t * parser ) {
  FD_TEST( parser->state!=STATE_DONE );

  switch( parser->state ) {
    case STATE_SLOT_DELTAS_LEN:
      parser->state = STATE_SLOT_DELTA_SLOT;
      break;
    case STATE_SLOT_DELTA_SLOT:
      parser->state = STATE_SLOT_DELTA_IS_ROOT;
      parser->len--;
      break;
    case STATE_SLOT_DELTA_IS_ROOT:
      parser->state = STATE_SLOT_DELTA_STATUS_LEN;
      break;
    case STATE_SLOT_DELTA_STATUS_LEN:
      if( FD_UNLIKELY( !parser->slot_delta_status_len ) ) loop( parser );
      else                                                parser->state = STATE_STATUS_BLOCKHASH;
      break;
    case STATE_STATUS_BLOCKHASH:
      parser->state = STATE_STATUS_TXN_IDX;
      parser->slot_delta_status_len--;
      break;
    case STATE_STATUS_TXN_IDX:
      parser->state       = STATE_CACHE_STATUS_LEN;
      parser->group_avail = 1;
      break;
    case STATE_CACHE_STATUS_LEN:
      if( FD_UNLIKELY( !parser->cache_status_len ) ) loop( parser );
      else                                           parser->state = STATE_CACHE_STATUS_KEY_SLICE;
      break;
    case STATE_CACHE_STATUS_KEY_SLICE:
      parser->state = STATE_CACHE_STATUS_RESULT;
      parser->cache_status_len--;
      break;
    case STATE_CACHE_STATUS_RESULT:
      if( FD_LIKELY( !parser->error_discriminant ) ) {
        parser->entry->result = 0;
        result_loop( parser );
      }
      else {
        parser->state = STATE_CACHE_STATUS_RESULT_ERR;
      }
      break;
    case STATE_CACHE_STATUS_RESULT_ERR:
      if( FD_UNLIKELY( parser->error_discriminant==8U ) ) {
        parser->state = STATE_CACHE_STATUS_RESULT_ERR_INSTR_IDX;
      } else if( FD_UNLIKELY( parser->error_discriminant==30U || parser->error_discriminant==31U || parser->error_discriminant==35U ) ) {
        parser->state = STATE_CACHE_STATUS_RESULT_ERR_IDX;
      } else {
        parser->entry->result = (uchar)parser->error_discriminant;
        result_loop( parser );
      }
    break;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_IDX:
      parser->state = STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR;
      break;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR:
      if( FD_UNLIKELY( parser->error_discriminant==25U ) ) {
        parser->state = STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM;
      } else if( FD_UNLIKELY( parser->error_discriminant==44U ) ) {
        parser->state = STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_LEN;
      } else {
        parser->entry->result = (uchar)parser->error_discriminant;
        result_loop( parser );
      }
      break;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM:
      parser->entry->result = (uchar)parser->error_discriminant;
      result_loop( parser );
      break;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_LEN:
      parser->state = STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_ERR;
      break;
    case STATE_CACHE_STATUS_RESULT_ERR_INSTR_ERR_CUSTOM_BORSH_ERR:
      parser->entry->result = (uchar)parser->error_discriminant;
      result_loop( parser );
      break;
    case STATE_CACHE_STATUS_RESULT_ERR_IDX:
      parser->entry->result = (uchar)parser->error;
      result_loop( parser );
      break;
    default: FD_LOG_ERR(( "unknown state %d", parser->state ));
  }
  return 0;
}

FD_FN_CONST ulong
fd_slot_delta_parser_align( void ) {
  return fd_ulong_max( alignof(fd_slot_delta_parser_t), slot_set_align() );
}

FD_FN_CONST ulong
fd_slot_delta_parser_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l,  alignof(fd_slot_delta_parser_t), sizeof(fd_slot_delta_parser_t)                                  );
  l = FD_LAYOUT_APPEND( l,  slot_pool_align(),               slot_pool_footprint( FD_SLOT_DELTA_MAX_ENTRIES )                );
  l = FD_LAYOUT_APPEND( l,  slot_set_align(),                slot_set_footprint( FD_SLOT_DELTA_PARSER_SLOT_SET_MAX_ENTRIES ) );
  return FD_LAYOUT_FINI( l, alignof(fd_slot_delta_parser_t) );
}

void *
fd_slot_delta_parser_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_slot_delta_parser_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_slot_delta_parser_t * parser = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_slot_delta_parser_t), sizeof(fd_slot_delta_parser_t)                                  );
  void * slot_pool_mem            = FD_SCRATCH_ALLOC_APPEND( l, slot_pool_align(),               slot_pool_footprint( FD_SLOT_DELTA_MAX_ENTRIES )                );
  void * slot_set_mem             = FD_SCRATCH_ALLOC_APPEND( l, slot_set_align(),                slot_set_footprint( FD_SLOT_DELTA_PARSER_SLOT_SET_MAX_ENTRIES ) );

  parser->slot_pool = slot_pool_join( slot_pool_new( slot_pool_mem, FD_SLOT_DELTA_MAX_ENTRIES ) );
  FD_TEST( parser->slot_pool );

  parser->slot_set = slot_set_join( slot_set_new( slot_set_mem, FD_SLOT_DELTA_PARSER_SLOT_SET_MAX_ENTRIES, 1UL ) );
  FD_TEST( parser->slot_set );

  for( ulong i=0UL; i<slot_pool_max( parser->slot_pool ); i++ ) {
    fd_slot_entry_t * slot_entry = &parser->slot_pool[ i ];
    slot_entry->slot = ULONG_MAX;
  }

  parser->entry_avail       = 0;
  parser->slot_pool_ele_cnt = 0UL;
  parser->state             = STATE_DONE;

  return parser;
}

fd_slot_delta_parser_t *
fd_slot_delta_parser_join( void * shmem ) {
  return shmem;
}

void *
fd_slot_delta_parser_leave( fd_slot_delta_parser_t * parser ) {
  return (void *)parser;
}

void *
fd_slot_delta_parser_delete( void * shmem ) {
  return shmem;
}

void
fd_slot_delta_parser_init( fd_slot_delta_parser_t * parser ) {
  parser->state     = STATE_SLOT_DELTAS_LEN;
  parser->len       = 0UL;
  parser->is_root   = 0;

  parser->slot_delta_status_len = 0UL;
  parser->cache_status_len      = 0UL;
  parser->borsh_io_error_len    = 0UL;
  parser->error_discriminant    = 0U;

  for( ulong i=0UL; i<parser->slot_pool_ele_cnt; i++ ) {
    fd_slot_entry_t * slot_entry = &parser->slot_pool[ i ];
    slot_set_ele_remove_fast( parser->slot_set, slot_entry, parser->slot_pool );
    slot_entry->slot = ULONG_MAX;
  }

  parser->slot_pool_ele_cnt = 0UL;

  parser->dst       = state_dst( parser );
  parser->dst_sz    = state_size( parser );
  parser->dst_cur   = 0UL;
}

int
fd_slot_delta_parser_consume( fd_slot_delta_parser_t *                parser,
                              uchar const *                           buf,
                              ulong                                   bufsz,
                              fd_slot_delta_parser_advance_result_t * result ) {
  uchar const * data    = buf;
  ulong         data_sz = bufsz;
  while( data_sz ) {
    if( FD_UNLIKELY( parser->state==STATE_DONE ) ) break;

    ulong consume = fd_ulong_min( data_sz, parser->dst_sz-parser->dst_cur );

    if( FD_LIKELY( parser->dst && consume ) ) {
      memcpy( parser->dst+parser->dst_cur, data, consume );
    }

    parser->dst_cur += consume;
    data            += consume;
    data_sz         -= consume;

#if SLOT_DELTA_PARSER_DEBUG
    state_log( parser );
#endif

    if( FD_LIKELY( parser->dst_cur==parser->dst_sz ) ) {
      int err = state_validate( parser );
      if( FD_UNLIKELY( err ) ) return err;

      err = state_process( parser );
      if( FD_UNLIKELY( err ) ) return err;

      parser->dst     = state_dst( parser );
      parser->dst_sz  = state_size( parser );
      parser->dst_cur = 0UL;

      if( FD_LIKELY( parser->group_avail ) ) {
        parser->group_avail          = 0;
        result->entry                = NULL;
        result->group.blockhash      = parser->entry->blockhash;
        result->group.txnhash_offset = parser->txnhash_offset;
        result->bytes_consumed       = (ulong)(data - buf);
        return FD_SLOT_DELTA_PARSER_ADVANCE_GROUP;
      } else if( FD_LIKELY( parser->entry_avail ) ) {
        parser->entry_avail    = 0;
        result->entry          = parser->entry;
        result->bytes_consumed = (ulong)(data - buf);
        return FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY;
      }
    }
  }

  if( FD_UNLIKELY( data_sz ) ) {
    FD_LOG_WARNING(( "excess data in buffer" ));
    return -1;
  }

  result->bytes_consumed = (ulong)(data - buf);
  return parser->state==STATE_DONE ? FD_SLOT_DELTA_PARSER_ADVANCE_DONE : FD_SLOT_DELTA_PARSER_ADVANCE_AGAIN;
}
