#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <stdlib.h>
#include <string.h>

#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"
#include "fd_forest.h"

#define ELE_MAX      (8UL)
#define FUZZ_MAX_OPS (128UL)

static fd_wksp_t * wksp;
static void *      forest_mem;

typedef struct {
  uchar const * data;
  ulong         data_sz;
  ulong         data_off;
} fuzz_cursor_t;

static inline uchar
fuzz_fallback_u8( fuzz_cursor_t const * cur ) {
  ulong h = fd_ulong_hash( cur->data_off ^ (cur->data_sz<<1) ^ 0x9e3779b97f4a7c15UL );
  return (uchar)h;
}

static inline uchar
fuzz_u8( fuzz_cursor_t * cur ) {
  if( FD_LIKELY( cur->data_off < cur->data_sz ) ) return cur->data[ cur->data_off++ ];
  cur->data_off++;
  return fuzz_fallback_u8( cur );
}

static inline ushort
fuzz_u16( fuzz_cursor_t * cur ) {
  uchar b0 = fuzz_u8( cur );
  uchar b1 = fuzz_u8( cur );
  return (ushort)( (uint)b0 | ( (uint)b1 << 8 ) );
}

typedef enum {
  FUZZ_OP_BLK_INSERT = 0,
  FUZZ_OP_DATA_SHRED = 1,
  FUZZ_OP_CODE_SHRED = 2,
  FUZZ_OP_FEC_INSERT = 3,
  FUZZ_OP_FEC_CLEAR  = 4,
  FUZZ_OP_CHAIN_VERIFY = 5,
  FUZZ_OP_PUBLISH    = 6,
  FUZZ_OP_ITER_NEXT       = 7,
  FUZZ_OP_VERIFY          = 8,
  FUZZ_OP_HIGHEST_REPAIRED = 9,
  FUZZ_OP_FILL_SLOT         = 10,
  FUZZ_OP_FILL_AND_VERIFY   = 11,
  FUZZ_OP_FILL_PARENT_CHILD = 12,
  FUZZ_OP_CONFLICTING_SHRED = 13,
  FUZZ_OP_CNT               = 14
} fuzz_op_kind_t;

struct fuzz_op {
  uchar  kind;
  ushort slot_a;   /* primary slot operand */
  ushort slot_b;   /* secondary slot / parent */
  ushort idx;      /* shred_idx or fec_set_idx */
  uchar  flags;    /* bit 0: slot_complete, bits 1-2: shred src, bits 3-7: mr variant */
};
typedef struct fuzz_op fuzz_op_t;

struct fuzz_program {
  fuzz_op_t ops[ FUZZ_MAX_OPS ];
  ulong     op_cnt;
};
typedef struct fuzz_program fuzz_program_t;

static void
fuzz_decode_program( fuzz_cursor_t * cur, fuzz_program_t * prog ) {
  prog->op_cnt = 0UL;
  while( cur->data_off < cur->data_sz && prog->op_cnt < FUZZ_MAX_OPS - 1UL ) {
    fuzz_op_t * op = &prog->ops[ prog->op_cnt++ ];
    op->kind   = fuzz_u8 ( cur ) % FUZZ_OP_CNT;
    op->slot_a = fuzz_u16( cur );
    op->slot_b = fuzz_u16( cur );
    op->idx    = fuzz_u16( cur );
    op->flags  = fuzz_u8 ( cur );
  }
  /* guarantee terminal verify */
  prog->ops[ prog->op_cnt++ ] = (fuzz_op_t){ .kind = FUZZ_OP_VERIFY };
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 );
  fd_log_level_logfile_set( 4 );
  fd_log_level_stderr_set( 4 );

  wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 2048UL, 0UL, "fuzz_forest_actor", 0UL );
  FD_TEST( wksp );

  forest_mem = fd_wksp_alloc_laddr( wksp, fd_forest_align(),
                                    fd_forest_footprint( ELE_MAX ), 1UL );
  FD_TEST( forest_mem );

  return 0;
}

/* Insert a block and fill it with complete FEC sets, marking
   slot_complete on the last one.  fec_cnt is 1 or 2.  Returns the
   element or NULL on failure.

   Respects repair invariants: fec_insert always receives a full
   FEC set (last_shred_idx == fec_set_idx + FD_FEC_SHRED_CNT - 1). */
static fd_forest_blk_t *
fill_slot( fd_forest_t * forest,
           ulong         slot,
           ulong         parent,
           uint          fec_cnt,
           fd_hash_t *   mr0,
           fd_hash_t *   cmr0,
           fd_hash_t *   mr1,
           fd_hash_t *   cmr1 ) {
  ulong evicted = ULONG_MAX;
  if( !fd_forest_blk_insert( forest, slot, parent, &evicted ) ) return NULL;
  if( fec_cnt<=1U ) {
    fd_forest_fec_insert( forest, slot, parent, FD_FEC_SHRED_CNT-1U, 0U,
                          1 /*slot_complete*/, 0 /*ref_tick*/,
                          mr0, cmr0 );
  } else {
    fd_forest_fec_insert( forest, slot, parent, FD_FEC_SHRED_CNT-1U, 0U,
                          0, 0, mr0, cmr0 );
    fd_forest_fec_insert( forest, slot, parent, 32U+FD_FEC_SHRED_CNT-1U, 32U,
                          1, 0, mr1, cmr1 );
  }
  return fd_forest_query( forest, slot );
}

static void
fuzz_execute_op( fd_forest_t * forest, fuzz_op_t const * op ) {
  /* Derive slot and parent relative to current root so they remain valid
     across publish operations that advance the root.  Slot range is 4x
     pool capacity so distinct inserts naturally overflow the pool and
     trigger eviction. */
  ulong root   = fd_forest_root_slot( forest );
  ulong slot   = root + (ulong)op->slot_a % (ELE_MAX * 4UL - 1UL) + 1UL;
  ulong parent = root + (ulong)op->slot_b % (slot - root);

  uint shred_idx   = (uint)op->idx & (FD_SHRED_BLK_MAX - 1U);
  uint fec_set_idx = shred_idx - (shred_idx % 32U);

  switch( op->kind ) {

  case FUZZ_OP_BLK_INSERT: {
    ulong evicted = ULONG_MAX;
    fd_forest_blk_insert( forest, slot, parent, &evicted );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_DATA_SHRED: {
    ulong evicted  = ULONG_MAX;
    if( !fd_forest_blk_insert( forest, slot, parent, &evicted ) ) break;
    ulong mr_tag   = (ulong)(op->flags >> 3);
    fd_hash_t mr   = { .ul = { (ulong)fec_set_idx ^ mr_tag,            1UL, 0UL, 0UL } };
    fd_hash_t cmr  = { .ul = { (ulong)fec_set_idx ^ mr_tag ^ 0xdeadUL, 1UL, 0UL, 0UL } };
    /* Invariant: slot_complete only allowed on last shred in FEC set
       (shred_idx % 32 == 31). */
    int slot_complete = (op->flags & 1) & (shred_idx % 32U == 31U);
    /* Invariant: src is TURBINE (0) or REPAIR (1) from after_shred.
       RECOVERED (2) is only used internally by fec_insert. */
    int src           = (op->flags >> 1) & 1;
    fd_forest_data_shred_insert( forest, slot, parent, shred_idx, fec_set_idx,
                                 slot_complete, 0, src, &mr, &cmr );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_CODE_SHRED: {
    if( !fd_forest_query( forest, slot ) ) break;
    /* Invariant: shred_idx < FD_SHRED_BLK_MAX, enforced by
       fec_resolver. */
    fd_forest_code_shred_insert( forest, slot, shred_idx );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_FEC_INSERT: {
    ulong evicted  = ULONG_MAX;
    if( !fd_forest_blk_insert( forest, slot, parent, &evicted ) ) break;
    ulong mr_tag   = (ulong)(op->flags >> 3);
    fd_hash_t mr   = { .ul = { (ulong)fec_set_idx ^ mr_tag,            1UL, 0UL, 0UL } };
    fd_hash_t cmr  = { .ul = { (ulong)fec_set_idx ^ mr_tag ^ 0xdeadUL, 1UL, 0UL, 0UL } };
    int slot_complete = op->flags & 1;
    /* Invariant: fec_insert always receives a complete FEC set.
       last_shred_idx == fec_set_idx + FD_FEC_SHRED_CNT - 1. */
    uint last_shred_idx = fec_set_idx + FD_FEC_SHRED_CNT - 1U;
    fd_forest_fec_insert( forest, slot, parent, last_shred_idx, fec_set_idx,
                          slot_complete, 0, &mr, &cmr );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_FEC_CLEAR: {
    if( !fd_forest_query( forest, slot ) ) break;
    fd_forest_fec_clear( forest, slot, fec_set_idx, FD_FEC_SHRED_CNT - 1U );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_CHAIN_VERIFY: {
    fd_forest_blk_t * ele = fd_forest_query( forest, slot );
    /* Invariant: check_confirmed in repair_tile requires
       !chain_confirmed && complete_idx != UINT_MAX &&
       buffered_idx == complete_idx. */
    if( ele && !ele->chain_confirmed &&
        ele->complete_idx != UINT_MAX &&
        ele->buffered_idx == ele->complete_idx ) {
      uint top_fec = ele->complete_idx / 32UL;
      /* Use the actual stored MR half the time (flags bit 0) to allow
         chain verification to succeed, enabling chain_confirmed=1 and
         the parent-hop path (fec_idx==0). */
      fd_hash_t mr;
      if( op->flags & 1 ) {
        mr = ele->merkle_roots[top_fec].mr;
      } else {
        mr = (fd_hash_t){ .ul = { (ulong)op->slot_a, (ulong)op->slot_b, 1UL, 0UL } };
      }
      fd_forest_fec_chain_verify( forest, ele, &mr );
    }
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_PUBLISH: {
    /* allow publishing any in-forest slot: ancestry, frontier, or orphaned/subtrees */
    if( fd_forest_query( forest, slot ) )
      fd_forest_publish( forest, slot );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_ITER_NEXT: {
    /* Seed iterator from reqslist head when in null/initializing state */
    fd_forest_ref_t *      reqspool = fd_forest_reqspool( forest );
    fd_forest_reqslist_t * reqslist = fd_forest_reqslist( forest );
    if( forest->iter.ele_idx == fd_forest_pool_idx_null( fd_forest_pool( forest ) ) &&
        !fd_forest_reqslist_is_empty( reqslist, reqspool ) ) {
      forest->iter.ele_idx = fd_forest_reqslist_ele_peek_head( reqslist, reqspool )->idx;
    }
    if( !fd_forest_iter_done( &forest->iter, forest ) )
      fd_forest_iter_next( &forest->iter, forest );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_VERIFY: {
    FD_TEST( !fd_forest_verify( forest ) );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_HIGHEST_REPAIRED: {
    fd_forest_highest_repaired_slot( forest );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_FILL_SLOT: {
    uint  fec_cnt = (uint)(op->idx & 1U) + 1U; /* 1 or 2 FEC sets */
    ulong mr_tag  = (ulong)(op->flags >> 3);
    fd_hash_t mr0   = { .ul = { mr_tag,                     1UL, 0UL, 0UL } };
    fd_hash_t cmr0  = { .ul = { mr_tag ^ 0xdeadUL,          1UL, 0UL, 0UL } };
    fd_hash_t mr1   = { .ul = { 32UL ^ mr_tag,              1UL, 0UL, 0UL } };
    fd_hash_t cmr1  = { .ul = { 32UL ^ mr_tag ^ 0xdeadUL,   1UL, 0UL, 0UL } };
    fill_slot( forest, slot, parent, fec_cnt, &mr0, &cmr0, &mr1, &cmr1 );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_FILL_AND_VERIFY: {
    uint  fec_cnt = (uint)(op->idx & 1U) + 1U; /* 1 or 2 FEC sets */
    ulong mr_tag  = (ulong)(op->flags >> 3);
    fd_hash_t mr0   = { .ul = { mr_tag,                     1UL, 0UL, 0UL } };
    fd_hash_t cmr0  = { .ul = { mr_tag ^ 0xdeadUL,          1UL, 0UL, 0UL } };
    fd_hash_t mr1   = { .ul = { 32UL ^ mr_tag,              1UL, 0UL, 0UL } };
    fd_hash_t cmr1  = { .ul = { 32UL ^ mr_tag ^ 0xdeadUL,   1UL, 0UL, 0UL } };
    fd_forest_blk_t * ele = fill_slot( forest, slot, parent, fec_cnt, &mr0, &cmr0, &mr1, &cmr1 );
    if( ele && !ele->chain_confirmed &&
        ele->complete_idx != UINT_MAX &&
        ele->buffered_idx == ele->complete_idx ) {
      uint top_fec = ele->complete_idx / 32U;
      fd_hash_t bid = ele->merkle_roots[top_fec].mr;
      fd_forest_fec_chain_verify( forest, ele, &bid );
    }
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_FILL_PARENT_CHILD: {
    ulong slot_max    = root + ELE_MAX * 4UL - 1UL; /* same range as normal slot derivation */
    ulong parent_slot = slot;
    if( parent_slot >= slot_max ) break; /* no room for child */
    ulong child_slot  = parent_slot + (ulong)op->slot_b % (slot_max - parent_slot) + 1UL;
    ulong mr_tag      = (ulong)(op->flags >> 3);

    /* MR chain: child's CMR == parent's MR so chain_verify propagates */
    fd_hash_t parent_mr  = { .ul = { 0xAAAAUL ^ mr_tag,              1UL, 0UL, 0UL } };
    fd_hash_t parent_cmr = { .ul = { 0xAAAAUL ^ mr_tag ^ 0xBBBBUL,  1UL, 0UL, 0UL } };
    fd_hash_t child_mr   = { .ul = { 0xCCCCUL ^ mr_tag,             1UL, 0UL, 0UL } };
    fd_hash_t child_cmr  = parent_mr;

    /* Fill parent and child with single complete FEC sets */
    if( !fill_slot( forest, parent_slot, root, 1U, &parent_mr, &parent_cmr, NULL, NULL ) ) break;
    fd_forest_blk_t * child_ele = fill_slot( forest, child_slot, parent_slot, 1U, &child_mr, &child_cmr, NULL, NULL );
    if( !child_ele ) break;
    /* Chain verify child — should hop to parent */
    if( !child_ele->chain_confirmed &&
        child_ele->complete_idx != UINT_MAX &&
        child_ele->buffered_idx == child_ele->complete_idx )
      fd_forest_fec_chain_verify( forest, child_ele, &child_mr );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  case FUZZ_OP_CONFLICTING_SHRED: {
    fd_forest_blk_t * ele = fd_forest_query( forest, slot );
    if( !ele || ele->complete_idx == UINT_MAX ) break;
    fd_hash_t mr  = { .ul = { 0xBADUL ^ (ulong)fec_set_idx, 2UL, 0UL, 0UL } };
    fd_hash_t cmr = { .ul = { 0xBADUL ^ (ulong)fec_set_idx ^ 0xdeadUL, 2UL, 0UL, 0UL } };
    fd_forest_data_shred_insert( forest, slot, ele->parent_slot, shred_idx, fec_set_idx,
                                 0 /*slot_complete*/, 0, 0, &mr, &cmr );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  }

  default:
    break;
  }

  /* fd_forest_clear is not yet declared in the header.  Add this back
     to the enum when it is:
  case FUZZ_OP_CLEAR: {
    fd_forest_clear( forest );
    FD_FUZZ_MUST_BE_COVERED;
    break;
  } */
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  fd_forest_t * forest = fd_forest_join(
                           fd_forest_new( forest_mem, ELE_MAX, 42UL ) );
  if( FD_UNLIKELY( !forest ) ) return 0;

  fd_forest_init( forest, 0UL );
  forest->iter.list_gaddr = forest->reqslist_gaddr;

  fuzz_cursor_t  cur = { .data = data, .data_sz = data_sz, .data_off = 0UL };
  fuzz_program_t prog[1];
  fuzz_decode_program( &cur, prog );

  for( ulong i = 0UL; i < prog->op_cnt; i++ )
    fuzz_execute_op( forest, &prog->ops[ i ] );

  fd_forest_fini( forest );
  fd_forest_leave( forest );
  return 0;
}
