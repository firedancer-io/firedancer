/* test_rotor_tile.c is a closed-loop harness for the rotor tile.  It
   includes fd_rotor_tile.c with fd_stem_publish mocked to a recorder,
   then plays the rest of the validator around the tile:

   - sign tile:  every repair_sign publish is immediately answered via
     after_sign with a dummy signature (the rotor never verifies its own
     request signatures, it just splices them into the packet).
   - network:    repair_net packets are parsed back into fd_repair_msg_t
     requests.  Tests craft wire-format responses -- with REAL bmtree
     double-merkle proofs for the Alpenglow metadata responses -- and
     feed them back through the tile's net path (after_frag/IN_KIND_NET,
     which runs ag_repair_response_de + after_alpen_meta_repair).
   - shred tile: turbine shreds and ShredForBlockId responses are
     delivered as fd_shred_base_t frags, FEC completions as
     fd_fec_complete_t and evictions as fd_fec_evicted_t, the same way
     shred_out does.
   - replay:     repair_out publishes (ROTOR_SIG_FEC_REPLAY) are
     recorded and asserted on. */

#include "../../disco/topo/fd_topo.h"   /* pulls in fd_stem.h so the static inline parses */
#include "../../disco/shred/fd_shred_tile.h"

#define TEST_OUT_MAX (8UL)
static void * test_out_mem[ TEST_OUT_MAX ];

/* Out link indices (assigned in setup_ctx) */
#define OUT_IDX_NET    (0UL)
#define OUT_IDX_REPLAY (1UL)
#define OUT_IDX_SIGN   (2UL)

/* In link indices */
#define IN_IDX_NET    (0UL)
#define IN_IDX_SHRED  (1UL)
#define IN_IDX_VOTOR  (2UL)
#define IN_IDX_SIGN   (3UL)

typedef struct {
  ulong out_idx;
  ulong sig;
  ulong sz;
  uchar data[ 2048 ];
} pub_t;

#define PUB_MAX (8192UL)
static pub_t pub_log[ PUB_MAX ];
static ulong pub_cnt;
static ulong pub_cursor;

static void
test_stem_publish( ulong out_idx, ulong sig, ulong chunk, ulong sz ) {
  FD_TEST( pub_cnt<PUB_MAX );
  FD_TEST( out_idx<TEST_OUT_MAX && test_out_mem[ out_idx ] );
  pub_t * rec = &pub_log[ pub_cnt++ ];
  rec->out_idx = out_idx;
  rec->sig     = sig;
  rec->sz      = sz;
  FD_TEST( sz<=sizeof(rec->data) );
  fd_memcpy( rec->data, fd_chunk_to_laddr( test_out_mem[ out_idx ], chunk ), sz );
}

#undef  fd_stem_publish /* no prior macro, but harmless */
#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub )  \
  do { (void)(stem); (void)(ctl); (void)(tsorig); (void)(tspub);              \
       test_stem_publish( (out_idx), (sig), (chunk), (sz) ); } while(0)

#include "fd_rotor_tile.c"

#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"

/* ---------------------------------------------------------------------
   Request log: every packet the tile sends on repair_net, parsed. */

typedef struct {
  uint      kind;
  uint      nonce;
  ulong     slot;
  uint      idx;      /* shred idx (SHRED*, SHRED_FOR_BLOCK_ID) or fec_set_idx (FEC_ROOT) */
  fd_hash_t block_id; /* ag kinds only */
} req_t;

#define REQ_MAX (8192UL)
static req_t req_log[ REQ_MAX ];
static ulong req_cnt;

/* Replay delivery log: every ROTOR_SIG_FEC_REPLAY frag published. */

#define REP_MAX (512UL)
static fd_rotor_replay_fec_t rep_log[ REP_MAX ];
static ulong                 rep_cnt;

/* drain processes every unprocessed publish: sign requests are echoed
   straight back into after_sign (which in turn publishes the signed
   packet to repair_net, picked up by the same loop), net packets are
   parsed into req_log, replay frags into rep_log. */

static void
drain( ctx_t * ctx ) {
  while( pub_cursor<pub_cnt ) {
    pub_t rec = pub_log[ pub_cursor++ ]; /* copy: log grows while we iterate */

    if( rec.out_idx==OUT_IDX_SIGN ) {

      memset( ctx->sign_buf, 0xAB, sizeof(ctx->sign_buf) ); /* dummy signature */
      after_sign( ctx, IN_IDX_SIGN, rec.sig, NULL );

    } else if( rec.out_idx==OUT_IDX_NET ) {

      FD_TEST( rec.sz>sizeof(fd_ip4_udp_hdrs_t) );
      fd_repair_msg_t msg[1];
      memset( msg, 0, sizeof(msg) );
      fd_memcpy( msg, rec.data+sizeof(fd_ip4_udp_hdrs_t),
                 fd_ulong_min( rec.sz-sizeof(fd_ip4_udp_hdrs_t), sizeof(fd_repair_msg_t) ) );

      FD_TEST( req_cnt<REQ_MAX );
      req_t * req = &req_log[ req_cnt++ ];
      memset( req, 0, sizeof(req_t) );
      req->kind = msg->kind;
      switch( msg->kind ) {
        case FD_REPAIR_KIND_PONG:
          break;
        case FD_REPAIR_KIND_SHRED:
          req->nonce = msg->shred.nonce;                req->slot = msg->shred.slot;                req->idx = (uint)msg->shred.shred_idx;         break;
        case FD_REPAIR_KIND_HIGHEST_SHRED:
          req->nonce = msg->highest_shred.nonce;        req->slot = msg->highest_shred.slot;        req->idx = (uint)msg->highest_shred.shred_idx; break;
        case FD_REPAIR_KIND_ORPHAN:
          req->nonce = msg->orphan.nonce;               req->slot = msg->orphan.slot;                                                              break;
        case AG_REPAIR_KIND_PARENT_FEC_COUNT:
          req->nonce = msg->parent_fec_set_count.nonce; req->slot = msg->parent_fec_set_count.slot; req->block_id = msg->parent_fec_set_count.block_id; break;
        case AG_REPAIR_KIND_FEC_ROOT:
          req->nonce = msg->fec_set_root.nonce;         req->slot = msg->fec_set_root.slot;         req->idx = msg->fec_set_root.fec_set_idx; req->block_id = msg->fec_set_root.block_id; break;
        case AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID:
          req->nonce = msg->shred_block_id.nonce;       req->slot = msg->shred_block_id.slot;       req->idx = msg->shred_block_id.shred_idx; req->block_id = msg->shred_block_id.block_id; break;
        default: FD_LOG_ERR(( "unexpected outgoing request kind %u", msg->kind ));
      }

    } else if( rec.out_idx==OUT_IDX_REPLAY ) {

      if( FD_LIKELY( rec.sig==ROTOR_SIG_FEC_REPLAY ) ) {
        FD_TEST( rec.sz==sizeof(fd_rotor_replay_fec_t) );
        FD_TEST( rep_cnt<REP_MAX );
        fd_memcpy( &rep_log[ rep_cnt++ ], rec.data, sizeof(fd_rotor_replay_fec_t) );
      } else {
        /* fec_complete frags are also forwarded to replay verbatim; not
           tracked by these tests */
        FD_TEST( rec.sig==REPAIR_SIG_FEC || rec.sig==REPAIR_SIG_FEC_LEADER || rec.sig==REPAIR_SIG_FEC_INVALID );
      }

    } else {
      FD_LOG_ERR(( "unexpected out_idx %lu", rec.out_idx ));
    }
  }
}

/* tick runs one after_credit iteration (at most one FEC publish or one
   sign dispatch) and immediately plays the sign tile / collects output. */

static void
tick( ctx_t * ctx ) {
  int charge_busy = 0;
  int poll_in     = 1;
  after_credit( ctx, NULL, &poll_in, &charge_busy );
  drain( ctx );
}

/* pump ticks until an iteration produces no new publishes and all
   internal queues are drained. */

static void
pump( ctx_t * ctx ) {
  for( ulong i=0UL; i<100000UL; i++ ) {
    ulong before = pub_cnt;
    tick( ctx );
    if( pub_cnt==before &&
        fd_signs_queue_empty( ctx->pong_queue ) &&
        out_queue_empty( ctx->chainer->out_queue ) ) return;
  }
  FD_LOG_ERR(( "pump did not quiesce" ));
}

/* ---------------------------------------------------------------------
   req / rep query helpers */

static req_t *
req_find( ulong from, uint kind, ulong slot, uint idx, fd_hash_t const * block_id ) {
  for( ulong i=from; i<req_cnt; i++ ) {
    req_t * r = &req_log[ i ];
    if( r->kind!=kind || r->slot!=slot                      ) continue;
    if( idx!=UINT_MAX && r->idx!=idx                        ) continue;
    if( block_id && !fd_hash_eq( &r->block_id, block_id )   ) continue;
    return r;
  }
  return NULL;
}

static ulong
req_count( ulong from, uint kind, ulong slot ) {
  ulong cnt = 0UL;
  for( ulong i=from; i<req_cnt; i++ ) if( req_log[ i ].kind==kind && req_log[ i ].slot==slot ) cnt++;
  return cnt;
}

static void
rep_expect( ulong i, ulong slot, uint fec_set_idx, fd_hash_t const * mr,
            fd_hash_t const * block_id /* NULL = expect all-zero */, int slot_complete ) {
  FD_TEST( i<rep_cnt );
  fd_rotor_replay_fec_t * m = &rep_log[ i ];
  FD_TEST( m->slot==slot );
  FD_TEST( m->fec_set_idx==fec_set_idx );
  FD_TEST( fd_hash_eq( &m->mr, mr ) );
  fd_hash_t zero = {0};
  FD_TEST( fd_hash_eq( &m->block_id, block_id ? block_id : &zero ) );
  FD_TEST( m->slot_complete==slot_complete );
}

/* ---------------------------------------------------------------------
   Synthetic block builder.  A block's id is the double merkle root over
   its FEC set roots plus a final parent-info leaf (see
   finalize_block_id in fd_chainer.c and ag_repair_*_verify in
   fd_repair.c).  blk_build computes the block_id the same way and
   extracts the inclusion proof for every leaf so tests can craft
   verifiable ParentFecSetCount / FecSetRoot responses. */

#define BLK_FEC_MAX (8UL)
#define BLK_TREE_LAYER_CNT (6UL) /* supports up to 32 leaves */

typedef struct {
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t parent_block_id;
  uint      fec_cnt;
  fd_hash_t fec_root[ BLK_FEC_MAX ];
  fd_hash_t block_id;
  ulong     proof_len; /* nodes per proof == fd_bmtree_depth( fec_cnt+1 )-1 */
  uchar     proof[ BLK_FEC_MAX+1UL ][ AG_MAX_FEC_PROOF_NODE_CNT*FD_SHRED_MERKLE_NODE_SZ ]; /* [i]: fec leaf i; [fec_cnt]: parent-info leaf */
} blk_t;

static void
blk_build( blk_t * b ) {
  static uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( BLK_TREE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, BLK_TREE_LAYER_CNT );

  FD_TEST( b->fec_cnt>0U && b->fec_cnt<=BLK_FEC_MAX );
  for( uint i=0U; i<b->fec_cnt; i++ ) {
    fd_bmtree_node_t leaf[1];
    memcpy( leaf->hash, b->fec_root[ i ].uc, sizeof(fd_hash_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  fd_bmtree_node_t parent_info[1];
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &b->parent_slot,        sizeof(ulong)     );
  fd_sha256_append( sha, b->parent_block_id.uc,  sizeof(fd_hash_t) );
  fd_sha256_append( sha, &b->fec_cnt,            sizeof(uint)      );
  fd_sha256_fini  ( sha, parent_info->hash );
  fd_bmtree_commit_append( tree, parent_info, 1UL );

  uchar * root = fd_bmtree_commit_fini( tree );
  memcpy( b->block_id.uc, root, sizeof(fd_hash_t) );

  b->proof_len = fd_bmtree_depth( b->fec_cnt+1UL )-1UL;
  for( uint i=0U; i<=b->fec_cnt; i++ ) {
    int cnt = fd_bmtree_get_proof( tree, b->proof[ i ], i );
    FD_TEST( cnt==(int)b->proof_len );
  }
}

/* blk_fec_flags returns the data-shred flags carried by the last shred
   (and the completion message) of block b's FEC set k. */

static uchar
blk_fec_flags( blk_t const * b, uint k ) {
  return (uchar)( k==b->fec_cnt-1U ? FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE
                                   : FD_SHRED_DATA_FLAG_DATA_COMPLETE );
}

/* mkhash returns a distinct, deterministic, never-zero hash for n. */

static fd_hash_t
mkhash( ulong n ) {
  fd_hash_t h;
  memset( h.uc, 0, sizeof(fd_hash_t) );
  for( ulong i=0UL; i<8UL; i++ ) h.uc[ i ] = (uchar)( n>>(i*8UL) );
  h.uc[ 8 ] = 0xa5;
  return h;
}

/* slot_version_cnt returns the number of versions of slot the chainer
   currently tracks. */

static ulong
slot_version_cnt( fd_chainer_t * chainer, ulong slot ) {
  ulong n = 0UL;
  for( ulong i=fd_slotv_map_idx_query_const( chainer->slotv_map, &slot, ULONG_MAX, chainer->slotv_pool );
             i!=ULONG_MAX;
             i=fd_slotv_map_idx_next_const( i, ULONG_MAX, chainer->slotv_pool ) ) n++;
  return n;
}

/* ---------------------------------------------------------------------
   Inbound frag delivery.  Reliable frags are staged in per-in-link
   dcache buffers and pushed through before/during/after_frag; net frags
   go through after_frag's IN_KIND_NET path via ctx->net_buf. */

static uchar * test_in_mem[ 4 ];

/* noipa: keep GCC from constant-propagating sz into during_frag's
   inlined IN_KIND_SIGN branch (never taken here), which trips
   -Warray-bounds on ctx->sign_buf. */

#if defined(__clang__)
#define TEST_NOIPA __attribute__((noinline))
#else
#define TEST_NOIPA __attribute__((noipa))
#endif

TEST_NOIPA static void
deliver_frag( ctx_t * ctx, ulong in_idx, ulong sig, void const * msg, ulong sz ) {
  FD_TEST( !before_frag( ctx, in_idx, 0UL, sig ) );
  fd_memcpy( test_in_mem[ in_idx ], msg, sz );
  during_frag( ctx, in_idx, 0UL, sig, 0UL /* chunk */, sz, 0UL );
  FD_TEST( !ctx->skip_frag );
  after_frag( ctx, in_idx, 0UL, sig, sz, 0UL, 0UL, NULL );
  drain( ctx );
}

static void
deliver_net_response( ctx_t * ctx, uchar const * payload, ulong payload_sz ) {
  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, 0x0A000001U, 8000 );
  FD_TEST( sizeof(fd_ip4_udp_hdrs_t)+payload_sz<=FD_NET_MTU );
  fd_memcpy( ctx->net_buf,                           hdrs,    sizeof(fd_ip4_udp_hdrs_t) );
  fd_memcpy( ctx->net_buf+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz               );
  ctx->skip_frag = 0;
  after_frag( ctx, IN_IDX_NET, 0UL, 0UL, sizeof(fd_ip4_udp_hdrs_t)+payload_sz, 0UL, 0UL, NULL );
  drain( ctx );
}

/* Alpenglow metadata response wire serializers (see
   ag_repair_response_de for the schema). */

static ulong
ser_parent_fec_count_res( uchar * buf, uint fec_set_count, ulong parent_slot,
                          fd_hash_t const * parent_block_id,
                          uchar const * proof, ulong proof_len, uint nonce ) {
  ulong proof_sz = proof_len*FD_SHRED_MERKLE_NODE_SZ;
  ulong off      = 0UL;
  FD_STORE( uint,  buf+off, AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT ); off += 4UL;
  FD_STORE( uint,  buf+off, fec_set_count                           ); off += 4UL;
  FD_STORE( ulong, buf+off, parent_slot                             ); off += 8UL;
  fd_memcpy( buf+off, parent_block_id->uc, sizeof(fd_hash_t)         ); off += sizeof(fd_hash_t);
  FD_STORE( ulong, buf+off, proof_sz                                ); off += 8UL;
  fd_memcpy( buf+off, proof, proof_sz                                ); off += proof_sz;
  FD_STORE( uint,  buf+off, nonce                                   ); off += 4UL;
  return off;
}

static ulong
ser_fec_root_res( uchar * buf, fd_hash_t const * root,
                  uchar const * proof, ulong proof_len, uint nonce ) {
  ulong proof_sz = proof_len*FD_SHRED_MERKLE_NODE_SZ;
  ulong off      = 0UL;
  FD_STORE( uint,  buf+off, AG_REPAIR_RESPONSE_FEC_SET_ROOT ); off += 4UL;
  fd_memcpy( buf+off, root->uc, FD_SHRED_MERKLE_NODE_SZ      ); off += FD_SHRED_MERKLE_NODE_SZ;
  FD_STORE( ulong, buf+off, proof_sz                        ); off += 8UL;
  fd_memcpy( buf+off, proof, proof_sz                        ); off += proof_sz;
  FD_STORE( uint,  buf+off, nonce                           ); off += 4UL;
  return off;
}

/* corrupt=1 flips a proof byte so verification must fail. */

static void
respond_parent_fec_count( ctx_t * ctx, blk_t const * b, uint nonce, int corrupt ) {
  uchar proof[ AG_MAX_FEC_PROOF_NODE_CNT*FD_SHRED_MERKLE_NODE_SZ ];
  fd_memcpy( proof, b->proof[ b->fec_cnt ], b->proof_len*FD_SHRED_MERKLE_NODE_SZ );
  if( corrupt ) proof[ 0 ] ^= 0xFF;
  uchar buf[ 512 ];
  ulong sz = ser_parent_fec_count_res( buf, b->fec_cnt, b->parent_slot, &b->parent_block_id, proof, b->proof_len, nonce );
  FD_TEST( sz!=sizeof(fd_repair_ping_t) ); /* would be misrouted to the ping path */
  deliver_net_response( ctx, buf, sz );
}

static void
respond_fec_root( ctx_t * ctx, blk_t const * b, uint fec_set_idx, uint nonce, int corrupt ) {
  uint  k = fec_set_idx/FD_FEC_SHRED_CNT;
  uchar proof[ AG_MAX_FEC_PROOF_NODE_CNT*FD_SHRED_MERKLE_NODE_SZ ];
  fd_memcpy( proof, b->proof[ k ], b->proof_len*FD_SHRED_MERKLE_NODE_SZ );
  if( corrupt ) proof[ 0 ] ^= 0xFF;
  uchar buf[ 512 ];
  ulong sz = ser_fec_root_res( buf, &b->fec_root[ k ], proof, b->proof_len, nonce );
  FD_TEST( sz!=sizeof(fd_repair_ping_t) );
  deliver_net_response( ctx, buf, sz );
}

/* ---------------------------------------------------------------------
   Shred tile simulation */

/* mk_block_header_marker serializes a BlockHeaderV1 block marker into
   buf (see fd_block_marker_de): marker flag (u64 0) | VersionedBlockMarker
   tag (u16 1) | variant (u8) | length (u16) | VersionedBlockHeader tag
   (u8 1) | parent_slot (u64) | parent_block_id (32). */

static ulong
mk_block_header_marker( uchar * buf, ulong parent_slot, fd_hash_t const * parent_block_id ) {
  FD_TEST( parent_block_id ); /* shred 0 must name a parent; also dominates the memcpy below so -Wnonnull sees non-null */
  ulong off = 0UL;
  FD_STORE( ulong,  buf+off, 0UL          ); off += 8UL;
  FD_STORE( ushort, buf+off, (ushort)1    ); off += 2UL;
  buf[ off++ ] = (uchar)HEADER;
  FD_STORE( ushort, buf+off, (ushort)41   ); off += 2UL;
  buf[ off++ ] = (uchar)1;
  FD_STORE( ulong,  buf+off, parent_slot  ); off += 8UL;
  fd_memcpy( buf+off, parent_block_id->uc, sizeof(fd_hash_t) ); off += sizeof(fd_hash_t);
  return off;
}

/* deliver_shred pushes one data shred frag at the tile the way
   shred_out does.  Shred 0 of a block must carry the block-header
   marker naming (parent_slot, parent_block_id); other shreds carry an
   empty payload. */

static void
deliver_shred( ctx_t * ctx, ulong slot, uint idx, uchar flags, fd_hash_t const * mr,
               uint rnonce, uint src, ulong parent_slot, fd_hash_t const * parent_block_id ) {
  static fd_shred_base_t base[1];
  memset( base, 0, sizeof(fd_shred_base_t) );
  base->merkle_root = *mr;
  base->rnonce      = rnonce;

  fd_shred_t * shred = &base->shred;
  shred->variant     = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred->slot        = slot;
  shred->idx         = idx;
  shred->fec_set_idx = idx & ~( (uint)FD_FEC_SHRED_CNT-1U );
  shred->data.parent_off = 1;
  shred->data.flags      = flags;

  ulong payload_sz = 0UL;
  if( FD_UNLIKELY( idx==0U ) ) {
    payload_sz = mk_block_header_marker( (uchar *)shred+FD_SHRED_DATA_HEADER_SZ, parent_slot, parent_block_id );
  }
  shred->data.size = (ushort)( FD_SHRED_DATA_HEADER_SZ+payload_sz );

  ulong sig = (ulong)src; /* result SHRED_SIG_RESULT_OKAY in the high bits */
  deliver_frag( ctx, IN_IDX_SHRED, sig, base, sizeof(fd_shred_base_t) );
}

static void
deliver_fec_complete( ctx_t * ctx, ulong slot, uint fec_set_idx, uchar flags, fd_hash_t const * mr ) {
  fd_fec_complete_t msg;
  memset( &msg, 0, sizeof(msg) );
  msg.merkle_root = *mr;
  fd_shred_t * shred = &msg.last_shred_hdr;
  shred->variant     = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred->slot        = slot;
  shred->idx         = fec_set_idx+FD_FEC_SHRED_CNT-1U;
  shred->fec_set_idx = fec_set_idx;
  shred->data.parent_off = 1;
  shred->data.flags      = flags;
  shred->data.size       = FD_SHRED_DATA_HEADER_SZ;
  deliver_frag( ctx, IN_IDX_SHRED, SHRED_SIG_FEC_COMPLETE, &msg, sizeof(msg) );
}

static void
deliver_fec_evicted( ctx_t * ctx, ulong slot, uint fec_set_idx, fd_hash_t const * mr ) {
  fd_fec_evicted_t msg = { .slot = slot, .fec_set_idx = fec_set_idx, .merkle_root = *mr };
  deliver_frag( ctx, IN_IDX_SHRED, SHRED_SIG_FEC_EVICTED, &msg, sizeof(msg) );
}

static void
deliver_votor( ctx_t * ctx, ulong sig, ulong slot, fd_hash_t const * block_id ) {
  fd_votor_repair_t msg = { .slot = slot, .block_id = *block_id };
  deliver_frag( ctx, IN_IDX_VOTOR, sig, &msg, sizeof(msg) );
}

/* deliver_turbine_block feeds a whole synthetic block through the
   turbine path: all shreds of every FEC set (shred 0 carrying the
   parent marker) plus a completion message per FEC set. */

static void
deliver_turbine_block( ctx_t * ctx, blk_t const * b ) {
  for( uint k=0U; k<b->fec_cnt; k++ ) {
    for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
      uint  idx   = k*FD_FEC_SHRED_CNT+i;
      uchar flags = (uchar)( i==FD_FEC_SHRED_CNT-1U ? blk_fec_flags( b, k ) : 0 );
      deliver_shred( ctx, b->slot, idx, flags, &b->fec_root[ k ], 0U, SHRED_SIG_SRC_TURBINE,
                     b->parent_slot, &b->parent_block_id );
    }
    deliver_fec_complete( ctx, b->slot, k*FD_FEC_SHRED_CNT, blk_fec_flags( b, k ), &b->fec_root[ k ] );
  }
}

/* deliver_turbine_fec_set feeds only FEC set k of block b through the
   turbine path (all its shreds plus the completion message), so a block
   can be left incomplete in the chainer. */

static void
deliver_turbine_fec_set( ctx_t * ctx, blk_t const * b, uint k ) {
  FD_TEST( k<b->fec_cnt );
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    uint  idx   = k*FD_FEC_SHRED_CNT+i;
    uchar flags = (uchar)( i==FD_FEC_SHRED_CNT-1U ? blk_fec_flags( b, k ) : 0 );
    deliver_shred( ctx, b->slot, idx, flags, &b->fec_root[ k ], 0U, SHRED_SIG_SRC_TURBINE,
                   b->parent_slot, &b->parent_block_id );
  }
  deliver_fec_complete( ctx, b->slot, k*FD_FEC_SHRED_CNT, blk_fec_flags( b, k ), &b->fec_root[ k ] );
}

/* serve_shred_request answers one ShredForBlockId request for block b
   with a repair shred whose merkle root is mr (normally the fec set's
   real root; passing a different root simulates a wrong-version
   response). */

static void
serve_shred_request( ctx_t * ctx, blk_t const * b, req_t const * r, fd_hash_t const * mr ) {
  uint  k        = r->idx/FD_FEC_SHRED_CNT;
  int   last_idx = ( (r->idx&(FD_FEC_SHRED_CNT-1U))==FD_FEC_SHRED_CNT-1U );
  uchar flags    = (uchar)( last_idx ? blk_fec_flags( b, k ) : 0 );
  FD_TEST( k<b->fec_cnt );
  deliver_shred( ctx, b->slot, r->idx, flags, mr, r->nonce, SHRED_SIG_SRC_REPAIR,
                 b->parent_slot, &b->parent_block_id );
}

/* serve_shred_requests answers every ShredForBlockId request for block
   b in req_log[from..) with a repair shred whose merkle root is the
   fec set's real root -- except bad_idx (UINT_MAX = none), which is
   answered once with bad_mr to simulate a peer returning a shred from
   the wrong (equivocating) version.  A FEC completion is emitted as
   soon as all of a set's shreds have been (correctly) served.
   served[k] accumulates per-FEC-set served counts across calls.
   Returns the number of requests answered. */

static ulong
serve_shred_requests( ctx_t * ctx, ulong from, blk_t const * b,
                      uint bad_idx, fd_hash_t const * bad_mr,
                      uint * served ) {
  ulong answered = 0UL;
  for( ulong i=from; i<req_cnt; i++ ) {
    req_t const * r = &req_log[ i ];
    if( r->kind!=AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID ) continue;
    if( r->slot!=b->slot                           ) continue;
    if( !fd_hash_eq( &r->block_id, &b->block_id )  ) continue;

    uint k = r->idx/FD_FEC_SHRED_CNT;
    FD_TEST( k<b->fec_cnt );

    if( FD_UNLIKELY( r->idx==bad_idx ) ) {
      serve_shred_request( ctx, b, r, bad_mr );
    } else {
      serve_shred_request( ctx, b, r, &b->fec_root[ k ] );
      served[ k ]++;
      if( served[ k ]==FD_FEC_SHRED_CNT ) {
        deliver_fec_complete( ctx, b->slot, k*FD_FEC_SHRED_CNT, blk_fec_flags( b, k ), &b->fec_root[ k ] );
        /* Publish queued deliveries between completions, like the live
           tile does in after_credit, so per-FEC delivery order is
           deterministic for the asserts. */
        pump( ctx );
      }
    }
    answered++;
  }
  return answered;
}

/* ---------------------------------------------------------------------
   Setup.  Mirrors what privileged_init/unprivileged_init assemble, with
   test-sized parameters, dcache-backed out links and flat in-link
   buffers. */

#define TEST_SLOT_MAX  (32UL)
#define TEST_PEER_MAX  (64UL)
#define TEST_DEDUP_MAX (4096UL)
static int lg_sign_depth = 6;

#define SNAP_SLOT (100UL)
static fd_hash_t snap_bid;

static fd_pubkey_t peer_key[ 2 ];

static void
setup_ctx( ctx_t * ctx, fd_wksp_t * wksp ) {
  memset( ctx, 0, sizeof(*ctx) );

  pub_cnt = 0UL; pub_cursor = 0UL;
  req_cnt = 0UL;
  rep_cnt = 0UL;
  memset( test_out_mem, 0, sizeof(test_out_mem) );

  FD_TEST( fd_rng_secure( &ctx->repair_seed, sizeof(ulong) ) );
  FD_TEST( fd_rng_secure( ctx->repair_nonce_ss, sizeof(fd_rnonce_ss_t) ) );

  void * chainer_mem    = fd_wksp_alloc_laddr( wksp, fd_chainer_align(),        fd_chainer_footprint( TEST_SLOT_MAX ),   1UL );
  void * policy_mem     = fd_wksp_alloc_laddr( wksp, fd_policy_align(),         fd_policy_footprint( TEST_PEER_MAX ),    1UL );
  void * dedup_mem      = fd_wksp_alloc_laddr( wksp, fd_reqlim_align(),         fd_reqlim_footprint( TEST_DEDUP_MAX ),   1UL );
  void * inflights_mem  = fd_wksp_alloc_laddr( wksp, fd_inflights_align(),      fd_inflights_footprint(),                1UL );
  void * signs_map_mem  = fd_wksp_alloc_laddr( wksp, fd_signs_map_align(),      fd_signs_map_footprint( lg_sign_depth ), 1UL );
  void * pong_queue_mem = fd_wksp_alloc_laddr( wksp, fd_signs_queue_align(),    fd_signs_queue_footprint(),              1UL );
  void * ag_req_mem     = fd_wksp_alloc_laddr( wksp, ag_req_queue_align(),      ag_req_queue_footprint(),                1UL );
  void * repair_mem     = fd_wksp_alloc_laddr( wksp, fd_repair_align(),         fd_repair_footprint(),                   1UL );
  void * metrics_mem    = fd_wksp_alloc_laddr( wksp, fd_repair_metrics_align(), fd_repair_metrics_footprint(),           1UL );
  void * deliver_q_mem  = fd_wksp_alloc_laddr( wksp, out_queue_align(),         out_queue_footprint( (ulong)TEST_SLOT_MAX * FD_CHAINER_SLOT_VER_MAX * FD_FEC_BLK_MAX ), 1UL );
  FD_TEST( chainer_mem && policy_mem && dedup_mem && inflights_mem && signs_map_mem && pong_queue_mem && ag_req_mem && repair_mem && metrics_mem && deliver_q_mem );

  ctx->chainer       = fd_chainer_join       ( fd_chainer_new       ( chainer_mem,    TEST_SLOT_MAX, ctx->repair_seed                       ) );
  ctx->policy        = fd_policy_join        ( fd_policy_new        ( policy_mem,     TEST_PEER_MAX, ctx->repair_seed, ctx->repair_nonce_ss ) );
  ctx->dedup         = fd_reqlim_join        ( fd_reqlim_new        ( dedup_mem,      TEST_DEDUP_MAX, ctx->repair_seed                      ) );
  ctx->inflights     = fd_inflights_join     ( fd_inflights_new     ( inflights_mem,  ctx->repair_seed+1234UL                               ) );
  ctx->signs_map     = fd_signs_map_join     ( fd_signs_map_new     ( signs_map_mem,  lg_sign_depth, 0UL                                    ) );
  ctx->pong_queue    = fd_signs_queue_join   ( fd_signs_queue_new   ( pong_queue_mem                                                        ) );
  ctx->ag_req_queue  = ag_req_queue_join     ( ag_req_queue_new     ( ag_req_mem                                                            ) );
  ctx->protocol      = fd_repair_join        ( fd_repair_new        ( repair_mem,     &ctx->identity_public_key                             ) );
  ctx->slot_metrics  = fd_repair_metrics_join( fd_repair_metrics_new( metrics_mem                                                           ) );
  ctx->deliver_queue = out_queue_join        ( out_queue_new        ( deliver_q_mem, (ulong)TEST_SLOT_MAX * FD_CHAINER_SLOT_VER_MAX * FD_FEC_BLK_MAX ) );
  FD_TEST( ctx->chainer && ctx->policy && ctx->dedup && ctx->inflights && ctx->signs_map && ctx->pong_queue && ctx->ag_req_queue && ctx->protocol && ctx->slot_metrics && ctx->deliver_queue );

  /* Out links.  fd_chunk_to_laddr( mem, 0 )==mem, so chunk0=0 with mem
     pointing at a flat buffer works like a compact dcache.  wmark leaves
     2 KiB of headroom so a frag written at wmark stays in bounds. */

  ulong dcache_sz = 65536UL;
  void * net_dcache    = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  void * replay_dcache = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  void * sign_dcache   = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  FD_TEST( net_dcache && replay_dcache && sign_dcache );
  ulong wmark = (dcache_sz>>FD_CHUNK_LG_SZ)-(2048UL>>FD_CHUNK_LG_SZ)-1UL;

  ctx->net_out_ctx->idx    = OUT_IDX_NET;
  ctx->net_out_ctx->mem    = net_dcache;
  ctx->net_out_ctx->chunk0 = 0UL;
  ctx->net_out_ctx->wmark  = wmark;
  ctx->net_out_ctx->chunk  = 0UL;

  ctx->repair_out_ctx->idx    = OUT_IDX_REPLAY;
  ctx->repair_out_ctx->mem    = replay_dcache;
  ctx->repair_out_ctx->chunk0 = 0UL;
  ctx->repair_out_ctx->wmark  = wmark;
  ctx->repair_out_ctx->chunk  = 0UL;

  ctx->repair_sign_cnt                    = 1UL;
  ctx->repair_sign_out_ctx[0].idx         = OUT_IDX_SIGN;
  ctx->repair_sign_out_ctx[0].in_idx      = IN_IDX_SIGN;
  ctx->repair_sign_out_ctx[0].mem         = sign_dcache;
  ctx->repair_sign_out_ctx[0].chunk0      = 0UL;
  ctx->repair_sign_out_ctx[0].wmark       = wmark;
  ctx->repair_sign_out_ctx[0].chunk       = 0UL;
  ctx->repair_sign_out_ctx[0].max_credits = 128UL;
  ctx->repair_sign_out_ctx[0].credits     = 128UL;

  test_out_mem[ OUT_IDX_NET    ] = net_dcache;
  test_out_mem[ OUT_IDX_REPLAY ] = replay_dcache;
  test_out_mem[ OUT_IDX_SIGN   ] = sign_dcache;

  /* In links */

  ulong in_buf_sz = 4096UL;
  ctx->in_kind[ IN_IDX_NET   ] = IN_KIND_NET;
  ctx->in_kind[ IN_IDX_SHRED ] = IN_KIND_SHRED;
  ctx->in_kind[ IN_IDX_VOTOR ] = IN_KIND_VOTOR;
  ctx->in_kind[ IN_IDX_SIGN  ] = IN_KIND_SIGN;
  for( ulong i=IN_IDX_SHRED; i<=IN_IDX_VOTOR; i++ ) {
    void * buf = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, in_buf_sz, 1UL );
    FD_TEST( buf );
    test_in_mem[ i ]           = buf;
    ctx->in_links[ i ].mem     = buf;
    ctx->in_links[ i ].chunk0  = 0UL;
    ctx->in_links[ i ].wmark   = (in_buf_sz>>FD_CHUNK_LG_SZ)-1UL;
    ctx->in_links[ i ].mtu     = in_buf_sz;
  }

  fd_ip4_udp_hdr_init( ctx->intake_hdr, 0UL, 0U, 1234 );
  ctx->repair_intake_addr.port = fd_ushort_bswap( 1234 );

  fd_histf_join( fd_histf_new( ctx->metrics->slot_compl_time, FD_MHIST_SECONDS_MIN( REPAIR, SLOT_COMPLETE_DURATION_SECONDS ),
                                                              FD_MHIST_SECONDS_MAX( REPAIR, SLOT_COMPLETE_DURATION_SECONDS ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics->response_latency, FD_MHIST_MIN( REPAIR, RESPONSE_LATENCY_NANOS ),
                                                               FD_MHIST_MAX( REPAIR, RESPONSE_LATENCY_NANOS ) ) );

  ctx->turbine_slot0    = ULONG_MAX;
  ctx->pending_key_next = 0U;
  ctx->ag_nonce         = 0U;

  /* Snapshot: root the chainer the way after_snap does. */

  snap_bid = mkhash( 0xB1D100UL );
  fd_chainer_init( ctx->chainer, SNAP_SLOT, &snap_bid );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Two repair peers, as if discovered via gossip. */

  peer_key[ 0 ] = *(fd_pubkey_t *)fd_type_pun( mkhash( 0xEE01UL ).uc );
  peer_key[ 1 ] = *(fd_pubkey_t *)fd_type_pun( mkhash( 0xEE02UL ).uc );
  fd_ip4_port_t addr0 = { .addr = 0x0A000002U, .port = 9001 };
  fd_ip4_port_t addr1 = { .addr = 0x0A000003U, .port = 9002 };
  FD_TEST( fd_policy_peer_upsert( ctx->policy, &peer_key[ 0 ], &addr0 ) );
  FD_TEST( fd_policy_peer_upsert( ctx->policy, &peer_key[ 1 ], &addr1 ) );
}

/* =====================================================================
   Test 1: synthetic turbine shreds.

   A block arrives shred-by-shred from turbine: the parent marker on
   shred 0 is parsed, catchup seeding fires on the first turbine shred,
   FEC completions deliver in order to replay (unverified, block_id only
   on the slot-complete FEC), the finalized block_id matches an
   independent double-merkle computation, equivocating/code/EQVOC shreds
   are dropped, resolver evictions rewind the slot, and a votor ROOTED
   frag publishes the chainer root. */

static void
test_turbine_shreds( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0xA0UL );
  blk->fec_root[ 1 ] = mkhash( 0xA1UL );
  blk_build( blk );

  /* First FEC set, shred by shred.  The first turbine shred sets
     turbine_slot0 and seeds catchup requests for (root, turbine_slot0). */

  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ )
    deliver_shred( ctx, blk->slot, i, (uchar)( i==FD_FEC_SHRED_CNT-1U ? FD_SHRED_DATA_FLAG_DATA_COMPLETE : 0 ),
                   &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_TURBINE, blk->parent_slot, &blk->parent_block_id );
  FD_TEST( ctx->turbine_slot0==blk->slot );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  fd_chainer_slotv_t * v0 = fd_chainer_slot_query( ctx->chainer, blk->slot );
  FD_TEST( v0 && v0->turbine );
  FD_TEST( v0->buffered_idx==FD_FEC_SHRED_CNT-1U );
  FD_TEST( v0->parent_slot==SNAP_SLOT );                       /* parsed from the shred-0 marker */
  FD_TEST( fd_hash_eq( &v0->parent_block_id, &snap_bid ) );
  FD_TEST( v0->connected );

  pump( ctx );
  /* catchup seeding: one shred-0 request for the single slot between the
     snapshot and turbine_slot0 */
  FD_TEST( req_find( 0UL, FD_REPAIR_KIND_SHRED, blk->slot, 0U, NULL ) );

  /* FEC 0 completes: delivered to replay unverified with a zero block_id
     (turbine version, slot not complete). */

  deliver_fec_complete( ctx, blk->slot, 0U, FD_SHRED_DATA_FLAG_DATA_COMPLETE, &blk->fec_root[ 0 ] );
  pump( ctx );
  FD_TEST( rep_cnt==1UL );
  rep_expect( 0UL, blk->slot, 0U, &blk->fec_root[ 0 ], NULL /* block_id: not finalized yet */, 0 /* slot_complete */ );
  FD_TEST( rep_log[ 0 ].parent_slot==SNAP_SLOT );
  FD_TEST( fd_hash_eq( &rep_log[ 0 ].parent_block_id, &snap_bid ) );
  FD_TEST( rep_log[ 0 ].data_complete==1 );

  /* Second (last) FEC set: block completes, the finalized block_id must
     equal the independently computed double-merkle root. */

  for( uint i=FD_FEC_SHRED_CNT; i<2U*FD_FEC_SHRED_CNT; i++ )
    deliver_shred( ctx, blk->slot, i,
                   (uchar)( i==2U*FD_FEC_SHRED_CNT-1U ? FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE : 0 ),
                   &blk->fec_root[ 1 ], 0U, SHRED_SIG_SRC_TURBINE, AG_UNKNOWN_SLOT, NULL );
  deliver_fec_complete( ctx, blk->slot, FD_FEC_SHRED_CNT,
                        FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE, &blk->fec_root[ 1 ] );
  pump( ctx );

  FD_TEST( rep_cnt==2UL );
  rep_expect( 1UL, blk->slot, FD_FEC_SHRED_CNT, &blk->fec_root[ 1 ], &blk->block_id, 1 );
  FD_TEST( fd_hash_eq( &v0->block_id, &blk->block_id ) ); /* finalize_block_id agrees with blk_build */
  FD_TEST( fd_chainer_highest_repaired_slot( ctx->chainer )==blk->slot );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Unauthorized equivocation, coding shreds, and EQVOC-flagged shreds
     are all dropped without touching the chainer. */

  ulong shred_cnt = fd_chainer_slotv_shred_cnt( ctx->chainer, v0 );
  fd_hash_t evil = mkhash( 0xEE1AUL );
  deliver_shred( ctx, blk->slot, 40U, 0, &evil, 0U, SHRED_SIG_SRC_TURBINE, AG_UNKNOWN_SLOT, NULL );
  FD_TEST( fd_chainer_slotv_shred_cnt( ctx->chainer, v0 )==shred_cnt );

  {
    static fd_shred_base_t base[1];
    memset( base, 0, sizeof(fd_shred_base_t) );
    base->merkle_root = evil;
    base->shred.variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_CODE, 5 );
    base->shred.slot    = blk->slot;
    base->shred.idx     = 7U;
    deliver_frag( ctx, IN_IDX_SHRED, (ulong)SHRED_SIG_SRC_TURBINE, base, sizeof(fd_shred_base_t) );
    FD_TEST( fd_chainer_slotv_shred_cnt( ctx->chainer, v0 )==shred_cnt );

    base->shred.variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
    base->shred.data.size = FD_SHRED_DATA_HEADER_SZ;
    ulong eqvoc_sig = ( (ulong)(uint)SHRED_SIG_RESULT_EQVOC<<32 ) | (ulong)SHRED_SIG_SRC_TURBINE;
    deliver_frag( ctx, IN_IDX_SHRED, eqvoc_sig, base, sizeof(fd_shred_base_t) );
    FD_TEST( fd_chainer_slotv_shred_cnt( ctx->chainer, v0 )==shred_cnt );
  }
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Resolver eviction of an in-progress FEC set rewinds the buffered
     prefix so repair re-requests it. */

  ulong next_slot = blk->slot+1UL;
  fd_hash_t rX = mkhash( 0xF00UL );
  for( uint i=0U; i<5U; i++ )
    deliver_shred( ctx, next_slot, i, 0, &rX, 0U, SHRED_SIG_SRC_TURBINE, blk->slot, &blk->block_id );
  fd_chainer_slotv_t * v1 = fd_chainer_slot_query( ctx->chainer, next_slot );
  FD_TEST( v1 && v1->buffered_idx==4U );

  deliver_fec_evicted( ctx, next_slot, 0U, &rX );
  FD_TEST( v1->buffered_idx==UINT_MAX );
  FD_TEST( fd_chainer_in_repair( ctx->chainer, v1 ) );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Votor roots the completed block: everything below is pruned. */

  pump( ctx );
  deliver_votor( ctx, FD_VOTOR_SIG_ROOTED, blk->slot, &blk->block_id );
  FD_TEST( ctx->chainer->root==blk->slot );
  FD_TEST( !fd_chainer_slot_query( ctx->chainer, SNAP_SLOT ) );
  FD_TEST( fd_chainer_slot_query( ctx->chainer, next_slot ) ); /* above the root: survives */
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  FD_LOG_NOTICE(( "pass: test_turbine_shreds" ));
}

/* =====================================================================
   Test 2: votor notar-fallback repair, end to end, under equivocation.

   Turbine delivers version A of a slot.  Votor then emits a
   FD_VOTOR_SIG_REPAIR (notar-fallback) for version B, which shares
   FEC set 0 with A and diverges after.  The tile must discover B's
   shape via getParentAndFecSetCount, learn its roots via getFecSetRoot
   (both proof-verified in after_alpen_meta_repair against B's cert block
   id), fill the diverging sets via ShredForBlockId (each response
   verified against the authorized roots), survive a wrong-version
   shred response plus a resolver eviction, and deliver ALL of B to
   replay as verified FECs carrying the cert block id.

   Five more certs (versions C..G) then bring the slot to the protocol
   maximum of FD_CHAINER_SLOT_VER_MAX versions, with their repair fully
   interleaved so the versions complete in an order unrelated to cert
   arrival; all seven versions must deliver completely, and rooting one
   prunes the other six.

   A second cert'd slot finally exercises the bad-metadata-response
   paths: corrupt-proof and wrong-kind responses are rejected without
   consuming the request, which is redispatched under a fresh nonce
   after the drain timeout and completes the block on retry. */

#define NF_EXTRA_CNT (5UL) /* cert versions beyond turbine's A and cert B */

static void
test_votor_notar_fallback( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  ulong slot = SNAP_SLOT+1UL;

  /* Version A via turbine (delivers 3 unverified FECs). */

  blk_t blkA[1] = {{ .slot = slot, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 3U }};
  blkA->fec_root[ 0 ] = mkhash( 0xAA0UL );
  blkA->fec_root[ 1 ] = mkhash( 0xAA1UL );
  blkA->fec_root[ 2 ] = mkhash( 0xAA2UL );
  blk_build( blkA );

  deliver_turbine_block( ctx, blkA );
  pump( ctx );
  FD_TEST( rep_cnt==3UL );
  rep_expect( 2UL, slot, 2U*FD_FEC_SHRED_CNT, &blkA->fec_root[ 2 ], &blkA->block_id, 1 );
  fd_chainer_slotv_t * vA = fd_chainer_slot_query( ctx->chainer, slot );
  FD_TEST( vA && fd_hash_eq( &vA->block_id, &blkA->block_id ) );

  /* Version B: shares FEC set 0 with A, diverges at sets 1 and 2. */

  blk_t blkB[1] = {{ .slot = slot, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 3U }};
  blkB->fec_root[ 0 ] = blkA->fec_root[ 0 ];
  blkB->fec_root[ 1 ] = mkhash( 0xBB1UL );
  blkB->fec_root[ 2 ] = mkhash( 0xBB2UL );
  blk_build( blkB );
  FD_TEST( !fd_hash_eq( &blkB->block_id, &blkA->block_id ) );

  /* Votor notar-fallback cert for B. */

  ulong mark = req_cnt;
  deliver_votor( ctx, FD_VOTOR_SIG_REPAIR, slot, &blkB->block_id );
  fd_chainer_slotv_t * vB = fd_chainer_slot_version_query( ctx->chainer, slot, &blkB->block_id );
  FD_TEST( vB && vB!=vA && !vB->turbine );
  FD_TEST( vB->complete_idx==UINT_MAX );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  pump( ctx );
  req_t * meta_req = req_find( mark, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot, UINT_MAX, &blkB->block_id );
  FD_TEST( meta_req );

  /* A response whose nonce matches no outstanding request is ignored. */

  respond_parent_fec_count( ctx, blkB, 0xDEADBEEFU, 0 );
  FD_TEST( vB->complete_idx==UINT_MAX );
  FD_TEST( ctx->metrics->failed_parent_fec_count_cnt==0UL );

  /* The verified ParentFecSetCount response teaches the tile B's shape
     and ancestry, and fans out a getFecSetRoot per FEC set. */

  respond_parent_fec_count( ctx, blkB, meta_req->nonce, 0 );
  FD_TEST( vB->complete_idx==3U*FD_FEC_SHRED_CNT-1U );
  FD_TEST( vB->parent_slot==SNAP_SLOT );
  FD_TEST( fd_hash_eq( &vB->parent_block_id, &snap_bid ) );
  FD_TEST( vB->connected );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  pump( ctx );
  req_t * root_req[ 3 ];
  for( uint k=0U; k<3U; k++ ) {
    root_req[ k ] = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slot, k*FD_FEC_SHRED_CNT, &blkB->block_id );
    FD_TEST( root_req[ k ] );
  }

  /* A repeated cert for a version we already track is a no-op: no new
     metadata request is issued. */

  ulong meta_cnt = req_count( 0UL, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot );
  deliver_votor( ctx, FD_VOTOR_SIG_REPAIR, slot, &blkB->block_id );
  pump( ctx );
  FD_TEST( req_count( 0UL, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot )==meta_cnt );

  /* getFecSetRoot responses.  Set 0's root is shared with A, so B picks
     up those shreds without repair and immediately re-delivers FEC 0 to
     replay under the cert version. */

  ulong rep_mark = rep_cnt;
  respond_fec_root( ctx, blkB, 0U, root_req[ 0 ]->nonce, 0 );
  pump( ctx );
  FD_TEST( rep_cnt==rep_mark+1UL );
  rep_expect( rep_mark, slot, 0U, &blkB->fec_root[ 0 ], &blkB->block_id, 0 );
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) FD_TEST( fd_chainer_shred_test( ctx->chainer, vB, i ) );

  respond_fec_root( ctx, blkB, 1U*FD_FEC_SHRED_CNT, root_req[ 1 ]->nonce, 0 );
  respond_fec_root( ctx, blkB, 2U*FD_FEC_SHRED_CNT, root_req[ 2 ]->nonce, 0 );
  FD_TEST( fd_chainer_fec_query( ctx->chainer, slot, 1U*FD_FEC_SHRED_CNT, &blkB->block_id ) );
  FD_TEST( fd_chainer_fec_query( ctx->chainer, slot, 2U*FD_FEC_SHRED_CNT, &blkB->block_id ) );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* The repair walk now issues ShredForBlockId requests for exactly the
     diverging shreds (the shared prefix is already in hand). */

  mark = req_cnt;
  pump( ctx );
  FD_TEST( req_count( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot )==2UL*FD_FEC_SHRED_CNT );
  FD_TEST( !req_find( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot, 0U, NULL ) ); /* nothing from the shared set */
  for( uint i=FD_FEC_SHRED_CNT; i<3U*FD_FEC_SHRED_CNT; i++ )
    FD_TEST( req_find( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot, i, &blkB->block_id ) );

  /* Serve every request; answer shred 40 once with version A's root to
     simulate a peer returning the wrong (equivocating) version.  The
     response fails to verify against version B's authorized root for
     that set, so it is never admitted to version B -- it matches no B
     inflight and lands only on version A's (already complete) FEC. */

  uint bad_idx = FD_FEC_SHRED_CNT+8U;
  uint served[ BLK_FEC_MAX ] = {0};
  serve_shred_requests( ctx, mark, blkB, bad_idx, &blkA->fec_root[ 1 ], served );
  FD_TEST( !fd_chainer_shred_test( ctx->chainer, vB, bad_idx ) );

  /* FEC set 2 completed (its shreds all landed), but set 1 has a hole:
     nothing beyond the shared prefix may be delivered yet. */

  pump( ctx );
  FD_TEST( rep_cnt==rep_mark+1UL );
  FD_TEST( vB->delivered_idx==FD_FEC_SHRED_CNT-1U );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* The resolver gives up on the incomplete set and evicts it.  The
     tile rewinds and re-requests the whole set. */

  mark = req_cnt;
  deliver_fec_evicted( ctx, slot, 1U*FD_FEC_SHRED_CNT, &blkB->fec_root[ 1 ] );
  FD_TEST( vB->buffered_idx==FD_FEC_SHRED_CNT-1U );
  FD_TEST( fd_chainer_in_repair( ctx->chainer, vB ) );
  pump( ctx );
  FD_TEST( req_count( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot )==FD_FEC_SHRED_CNT );
  for( uint i=FD_FEC_SHRED_CNT; i<2U*FD_FEC_SHRED_CNT; i++ )
    FD_TEST( req_find( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot, i, &blkB->block_id ) );

  /* Serve the re-requests cleanly: version B completes and the
     diverging tail is delivered in order, verified, carrying the
     notar-fallback cert's block id. */

  memset( served, 0, sizeof(served) );
  serve_shred_requests( ctx, mark, blkB, UINT_MAX, NULL, served );
  pump( ctx );

  FD_TEST( rep_cnt==rep_mark+3UL );
  rep_expect( rep_mark+1UL, slot, 1U*FD_FEC_SHRED_CNT, &blkB->fec_root[ 1 ], &blkB->block_id, 0 );
  rep_expect( rep_mark+2UL, slot, 2U*FD_FEC_SHRED_CNT, &blkB->fec_root[ 2 ], &blkB->block_id, 1 );
  FD_TEST( rep_log[ rep_mark+2UL ].parent_slot==SNAP_SLOT );
  FD_TEST( fd_hash_eq( &rep_log[ rep_mark+2UL ].parent_block_id, &snap_bid ) );
  FD_TEST( fd_chainer_highest_repaired_slot( ctx->chainer )==slot );
  FD_TEST( fd_hash_eq( &vB->block_id, &blkB->block_id ) );
  FD_TEST( fd_hash_eq( &vA->block_id, &blkA->block_id ) ); /* version A untouched */
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Protocol maximum: five more notar-fallback certs (versions C..G,
     in cert order) land for the same slot, bringing it to
     FD_CHAINER_SLOT_VER_MAX versions alongside turbine's A and cert B.
     Each shares FEC set 0 with A and diverges after.  Their repair is
     fully interleaved: metadata and FEC-root responses arrive in
     shuffled orders, shred responses round-robin across the versions
     shred by shred, and the FEC completions land out of order both
     within and across versions, so the versions complete in an order
     unrelated to cert arrival.  Every version must still deliver its
     whole block to replay, in FEC order, verified, under its own cert
     block id. */

  FD_TEST( 2UL+NF_EXTRA_CNT==FD_CHAINER_SLOT_VER_MAX );

  static blk_t blkX[ NF_EXTRA_CNT ];
  for( ulong v=0UL; v<NF_EXTRA_CNT; v++ ) {
    memset( &blkX[ v ], 0, sizeof(blk_t) );
    blkX[ v ].slot            = slot;
    blkX[ v ].parent_slot     = SNAP_SLOT;
    blkX[ v ].parent_block_id = snap_bid;
    blkX[ v ].fec_cnt         = 3U;
    blkX[ v ].fec_root[ 0 ]   = blkA->fec_root[ 0 ]; /* shared with A */
    blkX[ v ].fec_root[ 1 ]   = mkhash( 0xC10UL+v );
    blkX[ v ].fec_root[ 2 ]   = mkhash( 0xC20UL+v );
    blk_build( &blkX[ v ] );
    FD_TEST( !fd_hash_eq( &blkX[ v ].block_id, &blkA->block_id ) );
    FD_TEST( !fd_hash_eq( &blkX[ v ].block_id, &blkB->block_id ) );
  }

  mark = req_cnt;
  for( ulong v=0UL; v<NF_EXTRA_CNT; v++ ) {
    deliver_votor( ctx, FD_VOTOR_SIG_REPAIR, slot, &blkX[ v ].block_id );
    FD_TEST( fd_chainer_slot_version_query( ctx->chainer, slot, &blkX[ v ].block_id ) );
  }
  FD_TEST( slot_version_cnt( ctx->chainer, slot )==FD_CHAINER_SLOT_VER_MAX );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );
  pump( ctx );

  /* Metadata responses arrive in shuffled order. */

  ulong const meta_order[ NF_EXTRA_CNT ] = { 4UL, 1UL, 0UL, 3UL, 2UL }; /* G D C F E */
  for( ulong i=0UL; i<NF_EXTRA_CNT; i++ ) {
    blk_t * b = &blkX[ meta_order[ i ] ];
    req_t * mreq = req_find( mark, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot, UINT_MAX, &b->block_id );
    FD_TEST( mreq );
    respond_parent_fec_count( ctx, b, mreq->nonce, 0 );
    fd_chainer_slotv_t * vX = fd_chainer_slot_version_query( ctx->chainer, slot, &b->block_id );
    FD_TEST( vX && vX->complete_idx==3U*FD_FEC_SHRED_CNT-1U && vX->connected );
  }
  pump( ctx );

  /* FEC-root responses interleave across versions and sets: all set-2
     roots first, then set 0, then set 1, each in a different version
     order.  Each shared set-0 adoption immediately re-delivers FEC 0 to
     replay under that version. */

  ulong const root2_order[ NF_EXTRA_CNT ] = { 2UL, 0UL, 4UL, 1UL, 3UL }; /* E C G D F */
  ulong const root0_order[ NF_EXTRA_CNT ] = { 1UL, 3UL, 0UL, 4UL, 2UL }; /* D F C G E */
  ulong const root1_order[ NF_EXTRA_CNT ] = { 0UL, 4UL, 3UL, 1UL, 2UL }; /* C G F D E */

  rep_mark = rep_cnt;
  for( ulong i=0UL; i<NF_EXTRA_CNT; i++ ) {
    blk_t * b = &blkX[ root2_order[ i ] ];
    req_t * rq = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slot, 2U*FD_FEC_SHRED_CNT, &b->block_id );
    FD_TEST( rq );
    respond_fec_root( ctx, b, 2U*FD_FEC_SHRED_CNT, rq->nonce, 0 );
  }
  for( ulong i=0UL; i<NF_EXTRA_CNT; i++ ) {
    blk_t * b = &blkX[ root0_order[ i ] ];
    req_t * rq = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slot, 0U, &b->block_id );
    FD_TEST( rq );
    respond_fec_root( ctx, b, 0U, rq->nonce, 0 );
  }
  for( ulong i=0UL; i<NF_EXTRA_CNT; i++ ) {
    blk_t * b = &blkX[ root1_order[ i ] ];
    req_t * rq = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slot, 1U*FD_FEC_SHRED_CNT, &b->block_id );
    FD_TEST( rq );
    respond_fec_root( ctx, b, 1U*FD_FEC_SHRED_CNT, rq->nonce, 0 );
  }

  /* This pump publishes the five shared-set-0 re-deliveries and lets
     the repair walk emit the ShredForBlockId requests for exactly the
     diverging shreds of every version. */

  mark = req_cnt;
  pump( ctx );

  FD_TEST( rep_cnt==rep_mark+NF_EXTRA_CNT );
  for( ulong i=0UL; i<NF_EXTRA_CNT; i++ )
    rep_expect( rep_mark+i, slot, 0U, &blkA->fec_root[ 0 ], &blkX[ root0_order[ i ] ].block_id, 0 );

  req_t const * vreq[ NF_EXTRA_CNT ][ 2UL*FD_FEC_SHRED_CNT ];
  ulong vreq_cnt[ NF_EXTRA_CNT ] = {0};
  for( ulong i=mark; i<req_cnt; i++ ) {
    req_t const * r = &req_log[ i ];
    if( r->kind!=AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID || r->slot!=slot ) continue;
    for( ulong v=0UL; v<NF_EXTRA_CNT; v++ ) {
      if( !fd_hash_eq( &r->block_id, &blkX[ v ].block_id ) ) continue;
      FD_TEST( r->idx>=FD_FEC_SHRED_CNT ); /* the shared set is never re-requested */
      FD_TEST( vreq_cnt[ v ]<2UL*FD_FEC_SHRED_CNT );
      vreq[ v ][ vreq_cnt[ v ]++ ] = r;
      break;
    }
  }
  for( ulong v=0UL; v<NF_EXTRA_CNT; v++ ) FD_TEST( vreq_cnt[ v ]==2UL*FD_FEC_SHRED_CNT );

  /* Serve the shreds round-robin across the versions, one shred per
     version per round (rotating the version order every round), holding
     back all FEC completion messages: nothing may deliver yet.  One of
     version F's responses is withheld ("lost on the network") to prove
     that a sibling version's response for the same (slot, idx) -- which
     shares the time-bucketed rnonce -- does not consume F's request. */

  ulong const hold_v = 3UL;  /* version F */
  ulong const hold_r = 18UL;
  req_t const * held = NULL;

  for( ulong r_=0UL; r_<2UL*FD_FEC_SHRED_CNT; r_++ ) {
    for( ulong v=0UL; v<NF_EXTRA_CNT; v++ ) {
      ulong vv = (r_+v)%NF_EXTRA_CNT;
      req_t const * rq = vreq[ vv ][ r_ ];
      if( FD_UNLIKELY( vv==hold_v && r_==hold_r ) ) { held = rq; continue; }
      serve_shred_request( ctx, &blkX[ vv ], rq, &blkX[ vv ].fec_root[ rq->idx/FD_FEC_SHRED_CNT ] );
    }
  }
  FD_TEST( held );
  pump( ctx );
  FD_TEST( rep_cnt==rep_mark+NF_EXTRA_CNT );

  /* Every admitted response was routed to -- and verified against --
     exactly the version that requested it: despite five same-nonce
     requests per (slot, idx), no shred is missing (except the withheld
     one) and no response was falsely rejected against a sibling
     version's root. */

  for( ulong v=0UL; v<NF_EXTRA_CNT; v++ ) {
    fd_chainer_slotv_t * vX = fd_chainer_slot_version_query( ctx->chainer, slot, &blkX[ v ].block_id );
    FD_TEST( vX );
    for( ulong r_=0UL; r_<2UL*FD_FEC_SHRED_CNT; r_++ ) {
      int held_one = ( v==hold_v && r_==hold_r );
      FD_TEST( fd_chainer_shred_test( ctx->chainer, vX, vreq[ v ][ r_ ]->idx )==!held_one );
    }
  }

  /* FEC completions land interleaved and out of order: E and C receive
     their slot-complete set ahead of their middle set (nothing may
     deliver across the hole), and the versions slot-complete in order
     E C G D F -- unrelated to the cert order C D E F G.  F's
     completions are held back until its lost shred is re-repaired. */

  rep_mark = rep_cnt;
  struct { ulong v; uint k; } const sched[ 2UL*NF_EXTRA_CNT ] = {
    { 2UL, 2U }, /* E set 2: held, set 1 is a hole   */
    { 1UL, 1U }, /* D set 1: delivers D.32           */
    { 4UL, 1U }, /* G set 1: delivers G.32           */
    { 2UL, 1U }, /* E set 1: delivers E.32+E.64, 1st */
    { 0UL, 2U }, /* C set 2: held, set 1 is a hole   */
    { 0UL, 1U }, /* C set 1: delivers C.32+C.64, 2nd */
    { 4UL, 2U }, /* G set 2: delivers G.64,       3rd */
    { 1UL, 2U }, /* D set 2: delivers D.64,       4th */
    { 3UL, 1U }, /* F set 1: delivers F.32           */
    { 3UL, 2U }, /* F set 2: delivers F.64,       5th */
  };
  struct { ulong v; uint k; int sc; } const exp[ 2UL*NF_EXTRA_CNT ] = {
    { 1UL, 1U, 0 }, /* D.32 */
    { 4UL, 1U, 0 }, /* G.32 */
    { 2UL, 1U, 0 }, /* E.32 */
    { 2UL, 2U, 1 }, /* E.64 */
    { 0UL, 1U, 0 }, /* C.32 */
    { 0UL, 2U, 1 }, /* C.64 */
    { 4UL, 2U, 1 }, /* G.64 */
    { 1UL, 2U, 1 }, /* D.64 */
    { 3UL, 1U, 0 }, /* F.32 */
    { 3UL, 2U, 1 }, /* F.64 */
  };

  for( ulong i=0UL; i<2UL*NF_EXTRA_CNT-2UL; i++ ) {
    blk_t * b = &blkX[ sched[ i ].v ];
    uint    k = sched[ i ].k;
    deliver_fec_complete( ctx, slot, k*FD_FEC_SHRED_CNT, blk_fec_flags( b, k ), &b->fec_root[ k ] );
    pump( ctx );
  }
  FD_TEST( rep_cnt==rep_mark+2UL*NF_EXTRA_CNT-2UL );
  for( ulong i=0UL; i<2UL*NF_EXTRA_CNT-2UL; i++ ) {
    blk_t * b = &blkX[ exp[ i ].v ];
    rep_expect( rep_mark+i, slot, exp[ i ].k*FD_FEC_SHRED_CNT, &b->fec_root[ exp[ i ].k ], &b->block_id, exp[ i ].sc );
  }

  /* The withheld response left F's request outstanding (the sibling
     versions' responses consumed only their own requests), so past the
     drain timeout it is redispatched under a fresh rnonce; serving the
     retry lets F complete and deliver. */

  fd_chainer_slotv_t * vF = fd_chainer_slot_version_query( ctx->chainer, slot, &blkX[ hold_v ].block_id );
  FD_TEST( vF && !fd_chainer_shred_test( ctx->chainer, vF, held->idx ) );

  mark = req_cnt;
  long hold_deadline = fd_log_wallclock()+FD_REQLIM_DEDUP_TIMEOUT+(long)20e6;
  while( fd_log_wallclock()<hold_deadline ) fd_log_sleep( hold_deadline-fd_log_wallclock() );

  req_t * fretry = NULL;
  for( ulong i=0UL; i<64UL && !fretry; i++ ) {
    tick( ctx );
    fretry = req_find( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot, held->idx, &blkX[ hold_v ].block_id );
  }
  FD_TEST( fretry );
  FD_TEST( fretry->nonce!=held->nonce ); /* fresh rnonce (new time bucket) */

  serve_shred_request( ctx, &blkX[ hold_v ], fretry, &blkX[ hold_v ].fec_root[ fretry->idx/FD_FEC_SHRED_CNT ] );
  FD_TEST( fd_chainer_shred_test( ctx->chainer, vF, held->idx ) );

  for( ulong i=2UL*NF_EXTRA_CNT-2UL; i<2UL*NF_EXTRA_CNT; i++ ) {
    blk_t * b = &blkX[ sched[ i ].v ];
    uint    k = sched[ i ].k;
    deliver_fec_complete( ctx, slot, k*FD_FEC_SHRED_CNT, blk_fec_flags( b, k ), &b->fec_root[ k ] );
    pump( ctx );
  }
  FD_TEST( rep_cnt==rep_mark+2UL*NF_EXTRA_CNT );
  for( ulong i=2UL*NF_EXTRA_CNT-2UL; i<2UL*NF_EXTRA_CNT; i++ ) {
    blk_t * b = &blkX[ exp[ i ].v ];
    rep_expect( rep_mark+i, slot, exp[ i ].k*FD_FEC_SHRED_CNT, &b->fec_root[ exp[ i ].k ], &b->block_id, exp[ i ].sc );
  }

  /* All seven versions of the slot are fully delivered (A and B were
     asserted above as they completed): for each cert version, replay
     received its complete FEC sequence in order under its block id. */

  for( ulong v=0UL; v<NF_EXTRA_CNT; v++ ) {
    uint next_fec = 0U;
    for( ulong i=0UL; i<rep_cnt; i++ ) {
      fd_rotor_replay_fec_t * m = &rep_log[ i ];
      if( !fd_hash_eq( &m->block_id, &blkX[ v ].block_id ) ) continue;
      FD_TEST( m->slot==slot );
      FD_TEST( m->fec_set_idx==next_fec*FD_FEC_SHRED_CNT );
      FD_TEST( fd_hash_eq( &m->mr, &blkX[ v ].fec_root[ next_fec ] ) );
      FD_TEST( m->slot_complete==(next_fec==blkX[ v ].fec_cnt-1U) );
      next_fec++;
    }
    FD_TEST( next_fec==blkX[ v ].fec_cnt );
  }
  FD_TEST( slot_version_cnt( ctx->chainer, slot )==FD_CHAINER_SLOT_VER_MAX );
  FD_TEST( fd_chainer_highest_repaired_slot( ctx->chainer )==slot );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Votor roots cert version B: the turbine version and the five other
     cert versions are all pruned. */

  deliver_votor( ctx, FD_VOTOR_SIG_ROOTED, slot, &blkB->block_id );
  FD_TEST( ctx->chainer->root==slot );
  FD_TEST( fd_chainer_slot_version_query( ctx->chainer, slot, &blkB->block_id ) );
  FD_TEST( !fd_chainer_slot_version_query( ctx->chainer, slot, &blkA->block_id ) );
  for( ulong v=0UL; v<NF_EXTRA_CNT; v++ )
    FD_TEST( !fd_chainer_slot_version_query( ctx->chainer, slot, &blkX[ v ].block_id ) );
  FD_TEST( slot_version_cnt( ctx->chainer, slot )==1UL );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Failure injection on a fresh notar-fallback slot: a FecSetRoot
     response with a corrupt proof and a response of the wrong kind must
     both be rejected without creating a sentinel -- and, critically,
     without consuming the request: the tile requeues it onto the ag req
     queue under a fresh nonce, so one bad peer response cannot
     permanently strand a cert'd block. */

  ulong slotD = slot+1UL;
  blk_t blkD[1] = {{ .slot = slotD, .parent_slot = slot, .parent_block_id = blkB->block_id, .fec_cnt = 2U }};
  blkD->fec_root[ 0 ] = mkhash( 0xDD0UL );
  blkD->fec_root[ 1 ] = mkhash( 0xDD1UL );
  blk_build( blkD );

  mark = req_cnt;
  deliver_votor( ctx, FD_VOTOR_SIG_REPAIR, slotD, &blkD->block_id );
  pump( ctx );
  req_t * meta_d = req_find( mark, AG_REPAIR_KIND_PARENT_FEC_COUNT, slotD, UINT_MAX, &blkD->block_id );
  FD_TEST( meta_d );
  respond_parent_fec_count( ctx, blkD, meta_d->nonce, 0 );
  pump( ctx );

  req_t * root_d0 = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slotD, 0U, &blkD->block_id );
  FD_TEST( root_d0 );
  respond_fec_root( ctx, blkD, 0U, root_d0->nonce, 1 /* corrupt */ );
  FD_TEST( ctx->metrics->failed_fec_root_cnt==1UL );
  FD_TEST( !fd_chainer_fec_query( ctx->chainer, slotD, 0U, &blkD->block_id ) );

  /* A response whose kind does not match the pending request is
     likewise rejected (a ParentFecSetCount response to a getFecSetRoot
     request). */

  req_t * root_d1 = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slotD, FD_FEC_SHRED_CNT, &blkD->block_id );
  FD_TEST( root_d1 );
  respond_parent_fec_count( ctx, blkD, root_d1->nonce, 0 );
  FD_TEST( !fd_chainer_fec_query( ctx->chainer, slotD, FD_FEC_SHRED_CNT, &blkD->block_id ) );
  FD_TEST( ctx->metrics->failed_fec_root_cnt==1UL );
  FD_TEST( ctx->metrics->failed_parent_fec_count_cnt==0UL );

  /* Both rejected requests were requeued onto the ag req queue (not
     consumed); draining it re-issues both getFecSetRoot requests under
     fresh nonces.  No sentinels exist yet, so no ShredForBlockId
     requests are issued. */

  mark = req_cnt;
  pump( ctx );
  req_t * retry_d0 = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slotD, 0U,               &blkD->block_id );
  req_t * retry_d1 = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slotD, FD_FEC_SHRED_CNT, &blkD->block_id );
  FD_TEST( retry_d0 && retry_d0->nonce!=root_d0->nonce );
  FD_TEST( retry_d1 && retry_d1->nonce!=root_d1->nonce );
  FD_TEST( !req_find( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slotD, UINT_MAX, NULL ) );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Good responses to the retries complete the recovery: the block is
     repaired and delivered end to end. */

  respond_fec_root( ctx, blkD, 0U,               retry_d0->nonce, 0 );
  respond_fec_root( ctx, blkD, FD_FEC_SHRED_CNT, retry_d1->nonce, 0 );
  FD_TEST( fd_chainer_fec_query( ctx->chainer, slotD, 0U,               &blkD->block_id ) );
  FD_TEST( fd_chainer_fec_query( ctx->chainer, slotD, FD_FEC_SHRED_CNT, &blkD->block_id ) );

  mark = req_cnt;
  pump( ctx );
  FD_TEST( req_count( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slotD )==2UL*FD_FEC_SHRED_CNT );
  uint served_d[ BLK_FEC_MAX ] = {0};
  serve_shred_requests( ctx, mark, blkD, UINT_MAX, NULL, served_d );
  pump( ctx );

  FD_TEST( fd_chainer_highest_repaired_slot( ctx->chainer )==slotD );
  int seen_d_complete = 0;
  for( ulong i=0UL; i<rep_cnt; i++ ) {
    fd_rotor_replay_fec_t * m = &rep_log[ i ];
    if( m->slot!=slotD ) continue;
    FD_TEST( fd_hash_eq( &m->mr, &blkD->fec_root[ m->fec_set_idx/FD_FEC_SHRED_CNT ] ) );
    if( m->slot_complete ) {
      seen_d_complete = 1;
      FD_TEST( fd_hash_eq( &m->block_id, &blkD->block_id ) );
    }
  }
  FD_TEST( seen_d_complete );
  FD_TEST( ctx->metrics->failed_fec_root_cnt==1UL ); /* no new failures during recovery */
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  FD_LOG_NOTICE(( "pass: test_votor_notar_fallback" ));
}

/* =====================================================================
   Test 2b: FEC re-key merge.

   When turbine sees a FEC first it keys it by the full 32-byte merkle
   root.  A later notar-fallback version that shares that FEC learns only
   the 20-byte root prefix from its FecSetRoot repair response, so
   verified_hash_insert (querying with the padded root) misses the
   full-root entry and creates a distinct sentinel.  Once a real shred
   delivers the full root, fd_chainer_fec_rekey must merge the sentinel's
   owners onto the existing full-root FEC rather than leaving them
   stranded.  This is invisible unless the root has a non-zero tail
   (bytes 20-31), which mkhash does not produce, so build one here. */

static void
test_fec_rekey_merge( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  ulong slot = SNAP_SLOT+1UL;

  /* Version A via turbine.  FEC set 0's root has a non-zero tail so its
     full 32-byte form differs from the 20-byte prefix committed by
     block_id and returned in FecSetRoot responses. */
  blk_t blkA[1] = {{ .slot = slot, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blkA->fec_root[ 0 ] = mkhash( 0xCC0UL ); blkA->fec_root[ 0 ].uc[ 24 ] = 0x5a; /* non-zero tail */
  blkA->fec_root[ 1 ] = mkhash( 0xCC1UL );
  blk_build( blkA );

  deliver_turbine_block( ctx, blkA );
  pump( ctx );
  fd_chainer_slotv_t * vA = fd_chainer_slot_query( ctx->chainer, slot );
  FD_TEST( vA && fd_hash_eq( &vA->block_id, &blkA->block_id ) );
  uint aFec0 = vA->fec[ 0 ]; /* A's complete full-root FEC 0 */
  FD_TEST( aFec0!=UINT_MAX );

  /* Version B shares FEC set 0 with A (identical full root), diverges at
     set 1. */
  blk_t blkB[1] = {{ .slot = slot, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blkB->fec_root[ 0 ] = blkA->fec_root[ 0 ];
  blkB->fec_root[ 1 ] = mkhash( 0xDD1UL );
  blk_build( blkB );
  FD_TEST( !fd_hash_eq( &blkB->block_id, &blkA->block_id ) );

  ulong mark = req_cnt;
  deliver_votor( ctx, FD_VOTOR_SIG_REPAIR, slot, &blkB->block_id );
  fd_chainer_slotv_t * vB = fd_chainer_slot_version_query( ctx->chainer, slot, &blkB->block_id );
  FD_TEST( vB && vB!=vA );

  pump( ctx );
  req_t * meta_req = req_find( mark, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot, UINT_MAX, &blkB->block_id );
  FD_TEST( meta_req );
  respond_parent_fec_count( ctx, blkB, meta_req->nonce, 0 );
  FD_TEST( vB->complete_idx==2U*FD_FEC_SHRED_CNT-1U );

  pump( ctx );
  req_t * root0 = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slot, 0U, &blkB->block_id );
  FD_TEST( root0 );

  /* B's FecSetRoot response for set 0.  The 20-byte-padded root misses
     A's full-root FEC, so B gets its own distinct sentinel rather than
     sharing A's entry. */
  respond_fec_root( ctx, blkB, 0U, root0->nonce, 0 );
  FD_TEST( vB->fec[ 0 ]!=UINT_MAX );
  FD_TEST( vB->fec[ 0 ]!=aFec0 ); /* distinct 20-byte-prefix sentinel */

  /* B requests set-0 shreds (its sentinel is incomplete). */
  pump( ctx );
  req_t * s0 = req_find( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot, 0U, &blkB->block_id );
  FD_TEST( s0 );

  /* Serve one set-0 shred carrying the full root.  after_alpen_shred
     accepts it (20-byte compare) and fd_chainer_fec_rekey, seeing A's
     full-root FEC already exists, merges B onto it and releases the
     sentinel. */
  ulong rmark = rep_cnt;
  serve_shred_request( ctx, blkB, s0, &blkB->fec_root[ 0 ] );
  pump( ctx );

  FD_TEST( vB->fec[ 0 ]==aFec0 );                          /* merged onto A's FEC */
  FD_TEST( vA->fec[ 0 ]==aFec0 );                          /* A still owns it */
  FD_TEST( slot_version_cnt( ctx->chainer, slot )==2UL );  /* no stray version */
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );
  FD_TEST( rep_cnt>rmark );                                /* FEC 0 re-delivered under B */
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) FD_TEST( fd_chainer_shred_test( ctx->chainer, vB, i ) );

  FD_LOG_NOTICE(( "pass: test_fec_rekey_merge" ));
}

/* =====================================================================
   Test 2c: notar-fallback for the same block still in flight from
   turbine (the race described in fd_rotor_tile.h).

   Turbine delivers FEC sets 0 and 1 of a 3-set block unverified
   ({verified=0, block_id=null}), then a notar-fallback cert arrives for
   the very same block.  The turbine block_id is not computable yet, so
   we cannot tell it is the same block: the turbine version is abandoned
   and the cert version re-delivers the prefix verified.  The remaining
   shreds then arrive through turbine: they fill the shared FEC, and the
   final set is delivered exactly once, verified, under the cert
   version.  The turbine version must never deliver its slot-complete
   FEC: replay would re-key its {slot, 0} bank onto the {slot, block_id}
   the cert version's bank already occupies. */

static void
test_notar_fallback_same_block( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  ulong slot = SNAP_SLOT+1UL;
  blk_t blk[1] = {{ .slot = slot, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 3U }};
  blk->fec_root[ 0 ] = mkhash( 0xEE0UL );
  blk->fec_root[ 1 ] = mkhash( 0xEE1UL );
  blk->fec_root[ 2 ] = mkhash( 0xEE2UL );
  blk_build( blk );

  /* Turbine delivers sets 0 and 1; set 2 has not arrived (*blip*). */

  for( uint k=0U; k<2U; k++ ) {
    for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
      uint  idx   = k*FD_FEC_SHRED_CNT+i;
      uchar flags = (uchar)( i==FD_FEC_SHRED_CNT-1U ? blk_fec_flags( blk, k ) : 0 );
      deliver_shred( ctx, slot, idx, flags, &blk->fec_root[ k ], 0U, SHRED_SIG_SRC_TURBINE,
                     blk->parent_slot, &blk->parent_block_id );
    }
    deliver_fec_complete( ctx, slot, k*FD_FEC_SHRED_CNT, blk_fec_flags( blk, k ), &blk->fec_root[ k ] );
  }
  pump( ctx );
  FD_TEST( rep_cnt==2UL );
  rep_expect( 0UL, slot, 0U,               &blk->fec_root[ 0 ], NULL, 0 );
  rep_expect( 1UL, slot, FD_FEC_SHRED_CNT, &blk->fec_root[ 1 ], NULL, 0 );
  FD_TEST( !rep_log[ 0 ].known_id && !rep_log[ 1 ].known_id );

  /* Notar-fallback cert for the same block abandons the in-flight
     turbine version. */

  ulong mark = req_cnt;
  deliver_votor( ctx, FD_VOTOR_SIG_REPAIR, slot, &blk->block_id );
  fd_hash_t zero = {0};
  fd_chainer_slotv_t * vT = fd_chainer_slot_version_query( ctx->chainer, slot, &zero );
  FD_TEST( vT && vT->turbine && vT->abandoned );
  fd_chainer_slotv_t * vC = fd_chainer_slot_version_query( ctx->chainer, slot, &blk->block_id );
  FD_TEST( vC && vC!=vT && !vC->turbine );

  /* Metadata teaches the cert version its shape and ancestry. */

  pump( ctx );
  req_t * meta_req = req_find( mark, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot, UINT_MAX, &blk->block_id );
  FD_TEST( meta_req );
  respond_parent_fec_count( ctx, blk, meta_req->nonce, 0 );
  FD_TEST( vC->complete_idx==3U*FD_FEC_SHRED_CNT-1U );
  FD_TEST( vC->connected );

  /* Root responses: the shared sets 0 and 1 complete immediately from
     local data and are re-delivered verified under the cert version;
     set 2's sentinel awaits shreds. */

  pump( ctx );
  ulong rep_mark = rep_cnt;
  for( uint k=0U; k<3U; k++ ) {
    req_t * root_req = req_find( mark, AG_REPAIR_KIND_FEC_ROOT, slot, k*FD_FEC_SHRED_CNT, &blk->block_id );
    FD_TEST( root_req );
    respond_fec_root( ctx, blk, k*FD_FEC_SHRED_CNT, root_req->nonce, 0 );
  }
  pump( ctx );
  FD_TEST( rep_cnt==rep_mark+2UL );
  rep_expect( rep_mark,     slot, 0U,               &blk->fec_root[ 0 ], &blk->block_id, 0 );
  rep_expect( rep_mark+1UL, slot, FD_FEC_SHRED_CNT, &blk->fec_root[ 1 ], &blk->block_id, 0 );
  FD_TEST( rep_log[ rep_mark ].known_id && rep_log[ rep_mark+1UL ].known_id );

  /* The remaining set arrives through turbine (not repair): its shreds
     fill the cert version's sentinel (same root), and the slot-complete
     FEC is delivered exactly once -- verified, under the cert version.
     The abandoned turbine version never delivers it and never finalizes
     a block id. */

  rep_mark = rep_cnt;
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    uint  idx   = 2U*FD_FEC_SHRED_CNT+i;
    uchar flags = (uchar)( i==FD_FEC_SHRED_CNT-1U ? blk_fec_flags( blk, 2U ) : 0 );
    deliver_shred( ctx, slot, idx, flags, &blk->fec_root[ 2 ], 0U, SHRED_SIG_SRC_TURBINE,
                   blk->parent_slot, &blk->parent_block_id );
  }
  deliver_fec_complete( ctx, slot, 2U*FD_FEC_SHRED_CNT, blk_fec_flags( blk, 2U ), &blk->fec_root[ 2 ] );
  pump( ctx );

  FD_TEST( rep_cnt==rep_mark+1UL );
  rep_expect( rep_mark, slot, 2U*FD_FEC_SHRED_CNT, &blk->fec_root[ 2 ], &blk->block_id, 1 );
  FD_TEST( rep_log[ rep_mark ].known_id );
  FD_TEST( fd_chainer_highest_repaired_slot( ctx->chainer )==slot );
  FD_TEST( fd_hash_check_zero( &vT->block_id ) );        /* never finalized */
  FD_TEST( slot_version_cnt( ctx->chainer, slot )==2UL ); /* cert version + abandoned anchor */

  /* Exactly one slot-complete delivery across the whole run, and
     everything delivered after the cert arrived is verified: replay's
     turbine bank (keyed {slot, 0}) never re-keys, so it can never
     collide with the cert bank keyed {slot, block_id}. */

  ulong sc_cnt = 0UL;
  for( ulong i=0UL; i<rep_cnt; i++ ) {
    if( rep_log[ i ].slot==slot && rep_log[ i ].slot_complete ) sc_cnt++;
    if( i>=2UL ) FD_TEST( rep_log[ i ].known_id );
  }
  FD_TEST( sc_cnt==1UL );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* Rooting the block prunes the abandoned anchor. */

  deliver_votor( ctx, FD_VOTOR_SIG_ROOTED, slot, &blk->block_id );
  FD_TEST( ctx->chainer->root==slot );
  FD_TEST( slot_version_cnt( ctx->chainer, slot )==1UL );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  FD_LOG_NOTICE(( "pass: test_notar_fallback_same_block" ));
}

/* =====================================================================
   Test 3: block-id-only repair (catchup mode).

   With ctx->block_id_repair_only set, every legacy positional emission
   is suppressed: repair is driven purely by votor cert block ids.  No
   turbine data exists at all; the whole block is discovered and filled
   via getParentAndFecSetCount / getFecSetRoot / ShredForBlockId.  A
   corrupt ParentFecSetCount proof is rejected and counted, and the
   block-id orphan pass re-requests the metadata.  Once the block is
   complete, the turbine-side bookkeeping finalizes to the same block id
   as the cert and both versions deliver; rooting prunes down to the
   canonical one. */

static void
test_block_id_repair_only( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );
  ctx->block_id_repair_only = 1;

  ulong slot = SNAP_SLOT+1UL;
  blk_t blk[1] = {{ .slot = slot, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0xCC0UL );
  blk->fec_root[ 1 ] = mkhash( 0xCC1UL );
  blk_build( blk );

  /* Notar-fallback cert with no local data: after_votor_notar_fallback
     requests the metadata, and the block-id orphan pass issues its own
     (duplicate) request for the unresolved ancestry on the next credit. */

  deliver_votor( ctx, FD_VOTOR_SIG_REPAIR, slot, &blk->block_id );
  fd_chainer_slotv_t * vC = fd_chainer_slot_version_query( ctx->chainer, slot, &blk->block_id );
  FD_TEST( vC );
  pump( ctx );

  FD_TEST( req_count( 0UL, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot )>=2UL );
  req_t * meta0 = req_find( 0UL,                                  AG_REPAIR_KIND_PARENT_FEC_COUNT, slot, UINT_MAX, &blk->block_id );
  req_t * meta1 = req_find( (ulong)(meta0-req_log)+1UL,           AG_REPAIR_KIND_PARENT_FEC_COUNT, slot, UINT_MAX, &blk->block_id );
  FD_TEST( meta0 && meta1 );

  /* A corrupt proof is rejected: counted, and the version learns
     nothing.  The duplicate request then succeeds. */

  respond_parent_fec_count( ctx, blk, meta0->nonce, 1 /* corrupt */ );
  FD_TEST( ctx->metrics->failed_parent_fec_count_cnt==1UL );
  FD_TEST( vC->complete_idx==UINT_MAX );

  respond_parent_fec_count( ctx, blk, meta1->nonce, 0 );
  FD_TEST( vC->complete_idx==2U*FD_FEC_SHRED_CNT-1U );
  FD_TEST( vC->connected );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  pump( ctx );
  req_t * root0 = req_find( 0UL, AG_REPAIR_KIND_FEC_ROOT, slot, 0U,               &blk->block_id );
  req_t * root1 = req_find( 0UL, AG_REPAIR_KIND_FEC_ROOT, slot, FD_FEC_SHRED_CNT, &blk->block_id );
  FD_TEST( root0 && root1 );
  respond_fec_root( ctx, blk, 0U,               root0->nonce, 0 );
  respond_fec_root( ctx, blk, FD_FEC_SHRED_CNT, root1->nonce, 0 );

  /* The whole block is requested via ShredForBlockId. */

  ulong mark = req_cnt;
  pump( ctx );
  FD_TEST( req_count( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot )==2UL*FD_FEC_SHRED_CNT );
  for( uint i=0U; i<2U*FD_FEC_SHRED_CNT; i++ )
    FD_TEST( req_find( mark, AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID, slot, i, &blk->block_id ) );

  uint served[ BLK_FEC_MAX ] = {0};
  serve_shred_requests( ctx, mark, blk, UINT_MAX, NULL, served );
  pump( ctx );

  /* Repair shreds still land on turbine-side bookkeeping, but the
     turbine version of the slot was created abandoned (the cert version
     predates it), so it only anchors the roots and shred bitmaps: it
     never delivers and never finalizes a block id.  Every FEC is
     delivered exactly once, under the cert version, verified and
     carrying the cert block id. */

  FD_TEST( fd_chainer_highest_repaired_slot( ctx->chainer )==slot );
  FD_TEST( rep_cnt==2UL );
  rep_expect( 0UL, slot, 0U,               &blk->fec_root[ 0 ], &blk->block_id, 0 );
  rep_expect( 1UL, slot, FD_FEC_SHRED_CNT, &blk->fec_root[ 1 ], &blk->block_id, 1 );
  FD_TEST( rep_log[ 0 ].known_id );
  FD_TEST( rep_log[ 1 ].known_id );

  /* Both versions are tracked (the abandoned turbine anchor plus the
     cert version); rooting below prunes down to the canonical one. */

  FD_TEST( slot_version_cnt( ctx->chainer, slot )==2UL );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  /* block-id-only mode never emitted a legacy positional request. */

  for( ulong i=0UL; i<req_cnt; i++ )
    FD_TEST( req_log[ i ].kind==AG_REPAIR_KIND_PARENT_FEC_COUNT ||
             req_log[ i ].kind==AG_REPAIR_KIND_FEC_ROOT         ||
             req_log[ i ].kind==AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID );

  deliver_votor( ctx, FD_VOTOR_SIG_ROOTED, slot, &blk->block_id );
  FD_TEST( ctx->chainer->root==slot );
  FD_TEST( slot_version_cnt( ctx->chainer, slot )==1UL );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  FD_LOG_NOTICE(( "pass: test_block_id_repair_only" ));
}

/* =====================================================================
   Test 4: fd_inflight popped-set logic.

   Directly exercises the inflight table (independent of the tile
   pipeline): a shred request moved to the popped set by a redispatch is
   still visible to the query iterator and consumable by take, and a
   metadata request likewise survives a pop into the popped set and is
   matchable by a late response.  These are the paths that let a
   response arriving after its request timed out still be recognized. */

static void
test_inflight_popped( fd_wksp_t * wksp ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_inflights_align(), fd_inflights_footprint(), 1UL );
  FD_TEST( mem );
  fd_inflights_t * inf = fd_inflights_join( fd_inflights_new( mem, 1234UL ) );
  FD_TEST( inf );

  /* Count entries the query iterator visits for a key, across both the
     outstanding and popped sets. */
# define QCOUNT( n, s, i ) __extension__({                                                        \
    ulong _c = 0UL;                                                                               \
    for( fd_inflight_t * _e = fd_inflights_request_query( inf, (n), (s), (i) );                   \
                         _e; _e = fd_inflights_request_query_next( inf, _e ) ) _c++;              \
    _c; })

  /* --- Shred inflights: query/pop/take span the popped set --- */

  fd_pubkey_t peer     = *(fd_pubkey_t *)fd_type_pun( mkhash( 0x9E ).uc );
  fd_hash_t   block_id = mkhash( 0xB1 );
  ulong slot = 5UL, idx = 7UL, nonce = 99UL;

  /* Two requests sharing one (slot, idx, nonce) key -- the version-blind
     rnonce case.  Both are outstanding, popped is empty. */
  fd_inflights_request_insert( inf, nonce, &peer, slot, idx, &block_id );
  fd_inflights_request_insert( inf, nonce, &peer, slot, idx, &block_id );
  FD_TEST( inf->popped_cnt==0UL );
  FD_TEST( QCOUNT( nonce, slot, idx )==2UL );

  /* query returns an entry carrying the request's block_id (used by the
     tile to verify a ShredForBlockId response against the version). */
  fd_inflight_t * q = fd_inflights_request_query( inf, nonce, slot, idx );
  FD_TEST( q && fd_hash_eq( &q->block_id, &block_id ) );

  /* Redispatch pops the oldest to the popped set; the iterator still
     sees both (one outstanding, one popped). */
  ulong pn, ps, pi; fd_hash_t pb;
  fd_inflights_request_pop( inf, &pn, &ps, &pb, &pi );
  FD_TEST( pn==nonce && ps==slot && pi==idx );
  FD_TEST( inf->popped_cnt==1UL );
  FD_TEST( QCOUNT( nonce, slot, idx )==2UL );

  /* Pop the second one too: the key now lives only in the popped set,
     and query must fall back to it. */
  fd_inflights_request_pop( inf, &pn, &ps, &pb, &pi );
  FD_TEST( inf->popped_cnt==2UL );
  FD_TEST( QCOUNT( nonce, slot, idx )==2UL );

  /* take a popped entry: released from the popped set, popped_cnt and
     pool free adjust. */
  ulong free0 = fd_inflight_pool_free( inf->pool );
  q = fd_inflights_request_query( inf, nonce, slot, idx );
  FD_TEST( q );
  FD_TEST( fd_inflights_request_remove( inf, q )>0L );
  FD_TEST( inf->popped_cnt==1UL );
  FD_TEST( fd_inflight_pool_free( inf->pool )==free0+1UL );
  FD_TEST( QCOUNT( nonce, slot, idx )==1UL );

  /* take the last popped entry: the key is now empty. */
  q = fd_inflights_request_query( inf, nonce, slot, idx );
  FD_TEST( q );
  fd_inflights_request_remove( inf, q );
  FD_TEST( inf->popped_cnt==0UL );
  FD_TEST( QCOUNT( nonce, slot, idx )==0UL );
  FD_TEST( !fd_inflights_request_query( inf, nonce, slot, idx ) );

  /* take an OUTSTANDING entry: must not touch popped_cnt. */
  fd_inflights_request_insert( inf, nonce, &peer, slot, idx, NULL );
  q = fd_inflights_request_query( inf, nonce, slot, idx );
  FD_TEST( q && fd_hash_check_zero( &q->block_id ) ); /* NULL block_id -> zero */
  fd_inflights_request_remove( inf, q );
  FD_TEST( inf->popped_cnt==0UL );
  FD_TEST( !fd_inflights_request_query( inf, nonce, slot, idx ) );

  /* --- Metadata inflights: pop -> popped, match spans popped --- */

  fd_hash_t bid = mkhash( 0xC7 );

  /* A match while outstanding removes it from the outstanding set. */
  fd_meta_inflights_request_insert( inf, 1000UL, AG_REPAIR_KIND_PARENT_FEC_COUNT, slot, &bid, 0U );
  FD_TEST( inf->ag_popped_cnt==0UL );
  fd_meta_inflight_t * m = fd_meta_inflights_request_match( inf, 1000UL );
  FD_TEST( m && m->nonce==1000UL && m->slot==slot && m->kind==AG_REPAIR_KIND_PARENT_FEC_COUNT );
  fd_meta_inflight_pool_ele_release( inf->ag_pool, m );
  FD_TEST( !fd_meta_inflights_request_match( inf, 1000UL ) ); /* consumed */

  /* A redispatch pops the request to the popped set (preserving its
     fields); a late response to that nonce still matches there. */
  fd_meta_inflights_request_insert( inf, 2000UL, AG_REPAIR_KIND_FEC_ROOT, slot, &bid, 32U );
  ulong mn, msl; uint mk, mf; fd_hash_t mb;
  fd_meta_inflights_request_pop( inf, &mn, &mk, &msl, &mb, &mf );
  FD_TEST( mn==2000UL && mk==AG_REPAIR_KIND_FEC_ROOT && msl==slot && mf==32U && fd_hash_eq( &mb, &bid ) );
  FD_TEST( inf->ag_popped_cnt==1UL );

  m = fd_meta_inflights_request_match( inf, 2000UL );
  FD_TEST( m && m->nonce==2000UL && m->fec_set_idx==32U && fd_hash_eq( &m->block_id, &bid ) );
  FD_TEST( inf->ag_popped_cnt==0UL ); /* match decremented the popped count */
  fd_meta_inflight_pool_ele_release( inf->ag_pool, m );
  FD_TEST( !fd_meta_inflights_request_match( inf, 2000UL ) ); /* consumed from popped */

  /* An unknown nonce matches nothing in either set. */
  FD_TEST( !fd_meta_inflights_request_match( inf, 0xDEADBEEFUL ) );

# undef QCOUNT
  fd_wksp_free_laddr( inf );
  FD_LOG_NOTICE(( "pass: test_inflight_popped" ));
}

/* ---------------------------------------------------------------------
   deliver_from_root: a one-shot flag that makes the next chainer
   delivery re-publish the entire ancestry path of FECs from the chainer
   root down to (and including) that FEC, root-first, drained one FEC per
   after_credit. */

static void
test_deliver_from_root( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  /* Three-slot fork chained off the snapshot root (SNAP_SLOT):
       101 (2 FEC sets) <- 102 (2 FEC sets) <- 103 (1 FEC set).
     Chain each block's parent_block_id to its parent's computed id. */

  blk_t blk1[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk1->fec_root[ 0 ] = mkhash( 0xD100UL );
  blk1->fec_root[ 1 ] = mkhash( 0xD101UL );
  blk_build( blk1 );

  blk_t blk2[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = SNAP_SLOT+1UL, .parent_block_id = blk1->block_id, .fec_cnt = 2U }};
  blk2->fec_root[ 0 ] = mkhash( 0xD200UL );
  blk2->fec_root[ 1 ] = mkhash( 0xD201UL );
  blk_build( blk2 );

  blk_t blk3[1] = {{ .slot = SNAP_SLOT+3UL, .parent_slot = SNAP_SLOT+2UL, .parent_block_id = blk2->block_id, .fec_cnt = 1U }};
  blk3->fec_root[ 0 ] = mkhash( 0xD300UL );
  blk_build( blk3 );

  /* Deliver 101 and 102 normally (deliver_from_root off): each FEC set
     is published once, in arrival order, and the chainer out_queue is
     fully drained. */

  deliver_turbine_block( ctx, blk1 );
  pump( ctx );
  deliver_turbine_block( ctx, blk2 );
  pump( ctx );

  FD_TEST( rep_cnt==4UL );                                    /* 2 + 2 FEC sets */
  FD_TEST( out_queue_empty( ctx->chainer->out_queue ) );
  FD_TEST( out_queue_empty( ctx->deliver_queue ) );
  ulong base = rep_cnt;

  /* Arm the one-shot flag and deliver 103.  Its single (slot-complete)
     FEC lands on the chainer out_queue but nothing is published until
     after_credit runs. */

  ctx->deliver_from_root = 1;
  deliver_turbine_block( ctx, blk3 );
  FD_TEST( rep_cnt==base );

  /* First after_credit consumes the chainer delivery and, because the
     flag is set, queues the whole root->103 path onto deliver_queue
     instead of publishing.  The flag is cleared and nothing is published
     this iteration. */

  tick( ctx );
  FD_TEST( rep_cnt==base );                                   /* enqueue only, no publish */
  FD_TEST( ctx->deliver_from_root==0 );                       /* one-shot */
  FD_TEST( !out_queue_empty( ctx->deliver_queue ) );

  /* The path drains one FEC per after_credit, root-first: 101's FEC sets
     (0, then 32), 102's (0, 32), then the 103 target FEC (0). */

  ulong exp_slot[ 5 ] = { SNAP_SLOT+1UL, SNAP_SLOT+1UL, SNAP_SLOT+2UL, SNAP_SLOT+2UL, SNAP_SLOT+3UL };
  uint  exp_fec [ 5 ] = { 0U, FD_FEC_SHRED_CNT, 0U, FD_FEC_SHRED_CNT, 0U };
  for( ulong j=0UL; j<5UL; j++ ) {
    ulong before = rep_cnt;
    tick( ctx );
    FD_TEST( rep_cnt==before+1UL );                           /* exactly one FEC per call */
    FD_TEST( rep_log[ before ].slot==exp_slot[ j ] );
    FD_TEST( rep_log[ before ].fec_set_idx==exp_fec[ j ] );
  }

  FD_TEST( rep_cnt==base+5UL );                               /* whole path re-delivered */
  FD_TEST( out_queue_empty( ctx->deliver_queue ) );

  /* Each FEC carries the fields publish_fec would set.  In the
     deliver_from_root path the block_id is ALWAYS populated with the
     version's finalized block id -- including mid-slot FECs, which the
     normal turbine publish path leaves zero until the slot-complete FEC
     (see test_deliver_from_root_populates_block_id).  Only the last FEC
     set of each block is slot-complete. */
  rep_expect( base+0UL, SNAP_SLOT+1UL, 0U,               &blk1->fec_root[ 0 ], &blk1->block_id, 0 );
  rep_expect( base+1UL, SNAP_SLOT+1UL, FD_FEC_SHRED_CNT, &blk1->fec_root[ 1 ], &blk1->block_id, 1 );
  rep_expect( base+2UL, SNAP_SLOT+2UL, 0U,               &blk2->fec_root[ 0 ], &blk2->block_id, 0 );
  rep_expect( base+3UL, SNAP_SLOT+2UL, FD_FEC_SHRED_CNT, &blk2->fec_root[ 1 ], &blk2->block_id, 1 );
  rep_expect( base+4UL, SNAP_SLOT+3UL, 0U,               &blk3->fec_root[ 0 ], &blk3->block_id, 1 );

  /* Draining is complete: nothing further is published, and the flag
     stays clear (subsequent deliveries publish normally). */
  ulong after = rep_cnt;
  tick( ctx );
  FD_TEST( rep_cnt==after );
  FD_TEST( ctx->deliver_from_root==0 );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  FD_LOG_NOTICE(( "pass: test_deliver_from_root" ));
}

/* ---------------------------------------------------------------------
   test_deliver_from_root_arming: deliver_from_root is armed ONLY by
   REPLAY_SIG_MISSING_FEC on the replay in-link.  before_frag filters
   every other sig on that link, so after_frag (which sets the flag
   unconditionally for IN_KIND_REPLAY) is only ever reached for the
   MISSING_FEC signal.  This is the entry point of the whole recovery
   round-trip: replay drops a FEC, publishes MISSING_FEC, rotor arms. */

static void
test_deliver_from_root_arming( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  ulong RIDX = 5UL; /* a spare in-link index; NET/SHRED/VOTOR/SIGN use 0..3 */
  ctx->in_kind[ RIDX ] = IN_KIND_REPLAY;

  /* before_frag: only REPLAY_SIG_MISSING_FEC passes (returns 0). */
  FD_TEST(  before_frag( ctx, RIDX, 0UL, REPLAY_SIG_SLOT_COMPLETED )!=0 );
  FD_TEST(  before_frag( ctx, RIDX, 0UL, REPLAY_SIG_ROOT_ADVANCED  )!=0 );
  FD_TEST(  before_frag( ctx, RIDX, 0UL, REPLAY_SIG_DROP_BANK_REF  )!=0 );
  FD_TEST( !before_frag( ctx, RIDX, 0UL, REPLAY_SIG_MISSING_FEC    )    );

  /* after_frag for the MISSING_FEC frag arms the one-shot.  The frag is
     zero-length (see notify_rotor_fec), so during_frag reads nothing. */
  FD_TEST( ctx->deliver_from_root==0 );
  during_frag( ctx, RIDX, 0UL, REPLAY_SIG_MISSING_FEC, 0UL /*chunk*/, 0UL /*sz*/, 0UL /*ctl*/ );
  FD_TEST( !ctx->skip_frag );
  after_frag( ctx, RIDX, 0UL, REPLAY_SIG_MISSING_FEC, 0UL, 0UL, 0UL, NULL );
  FD_TEST( ctx->deliver_from_root==1 );

  FD_LOG_NOTICE(( "pass: test_deliver_from_root_arming" ));
}

/* ---------------------------------------------------------------------
   test_deliver_from_root_degenerate: the base case of the ancestry walk
   in full_fec_path_queue -- the target FEC's block is a DIRECT child of
   the chainer root, so the walk terminates immediately at the root and
   the queued path is exactly the target block's own FECs [0, target].
   Exercises the loop boundary (slotv->slot > chainer->root). */

static void
test_deliver_from_root_degenerate( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  /* A single 2-FEC block chained directly off the snapshot root. */
  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0xC100UL );
  blk->fec_root[ 1 ] = mkhash( 0xC101UL );
  blk_build( blk );

  /* Arm the one-shot BEFORE the block is delivered, so the block itself
     is the re-delivery target (not a buffered ancestor).  Its two FEC
     completions land on the chainer out_queue; nothing publishes yet. */
  ctx->deliver_from_root = 1;
  deliver_turbine_block( ctx, blk );
  FD_TEST( rep_cnt==0UL );
  FD_TEST( !out_queue_empty( ctx->chainer->out_queue ) );

  /* First after_credit consumes the first delivered FEC (fec 0) and,
     because the flag is set, queues the root->target path.  The walk
     starts at the target (slot SNAP_SLOT+1) whose parent is the root
     (slot SNAP_SLOT): the loop runs exactly once and stops, so the path
     is just the target FEC 0 (target caps at the delivered FEC). */
  tick( ctx );
  FD_TEST( rep_cnt==0UL );                       /* enqueue only */
  FD_TEST( ctx->deliver_from_root==0 );          /* one-shot cleared */
  FD_TEST( !out_queue_empty( ctx->deliver_queue ) );

  /* Drain: FEC 0 from the queued path, then FEC 32 from the chainer
     out_queue's second (still-pending) delivery -- one per after_credit. */
  tick( ctx );
  FD_TEST( rep_cnt==1UL );
  rep_expect( 0UL, blk->slot, 0U, &blk->fec_root[ 0 ], &blk->block_id, 0 ); /* deliver path populates block_id */
  FD_TEST( out_queue_empty( ctx->deliver_queue ) );

  tick( ctx );
  FD_TEST( rep_cnt==2UL );
  rep_expect( 1UL, blk->slot, FD_FEC_SHRED_CNT, &blk->fec_root[ 1 ], &blk->block_id, 1 );

  /* Nothing else re-delivered; flag stays clear. */
  tick( ctx );
  FD_TEST( rep_cnt==2UL );
  FD_TEST( ctx->deliver_from_root==0 );
  FD_TEST( !fd_chainer_verify( ctx->chainer ) );

  FD_LOG_NOTICE(( "pass: test_deliver_from_root_degenerate" ));
}

/* ---------------------------------------------------------------------
   test_deliver_queue_priority: after_credit drains the deliver_queue
   (the re-delivered root->target path) FULLY -- one FEC per call --
   before consuming any fresh chainer delivery.  This is the ordering
   guarantee the recovery relies on: replay must see the missing
   ancestry rebuilt in order before newer FECs resume. */

static void
test_deliver_queue_priority( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  /* root <- blk1 (2 FECs) <- blk2 (1 FEC) <- blk3 (1 FEC). */
  blk_t blk1[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk1->fec_root[ 0 ] = mkhash( 0xE100UL );
  blk1->fec_root[ 1 ] = mkhash( 0xE101UL );
  blk_build( blk1 );

  blk_t blk2[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = SNAP_SLOT+1UL, .parent_block_id = blk1->block_id, .fec_cnt = 1U }};
  blk2->fec_root[ 0 ] = mkhash( 0xE200UL );
  blk_build( blk2 );

  blk_t blk3[1] = {{ .slot = SNAP_SLOT+3UL, .parent_slot = SNAP_SLOT+2UL, .parent_block_id = blk2->block_id, .fec_cnt = 1U }};
  blk3->fec_root[ 0 ] = mkhash( 0xE300UL );
  blk_build( blk3 );

  /* blk1 delivered normally (published, drained). */
  deliver_turbine_block( ctx, blk1 );
  pump( ctx );
  FD_TEST( rep_cnt==2UL );
  FD_TEST( out_queue_empty( ctx->chainer->out_queue ) );
  ulong base = rep_cnt;

  /* Arm the one-shot, then deliver blk2 AND blk3 without running
     after_credit.  Both land on the chainer out_queue (blk2_0, blk3_0)
     while deliver_from_root is still set. */
  ctx->deliver_from_root = 1;
  deliver_turbine_block( ctx, blk2 );
  deliver_turbine_block( ctx, blk3 );
  FD_TEST( rep_cnt==base );

  /* tick 1: pop blk2_0; flag set -> queue the root->blk2 path
     [blk1_0, blk1_32, blk2_0] onto deliver_queue; blk2_0 consumed, not
     published.  blk3_0 remains on the chainer out_queue untouched. */
  tick( ctx );
  FD_TEST( rep_cnt==base );
  FD_TEST( ctx->deliver_from_root==0 );
  FD_TEST( !out_queue_empty( ctx->deliver_queue ) );
  FD_TEST( !out_queue_empty( ctx->chainer->out_queue ) ); /* blk3 still pending */

  /* ticks 2..4: the deliver_queue drains root-first, one FEC per call.
     blk3 (the fresh chainer delivery) must NOT be published while the
     deliver_queue is non-empty. */
  ulong exp_slot[ 3 ] = { SNAP_SLOT+1UL, SNAP_SLOT+1UL, SNAP_SLOT+2UL };
  uint  exp_fec [ 3 ] = { 0U, FD_FEC_SHRED_CNT, 0U };
  for( ulong j=0UL; j<3UL; j++ ) {
    ulong before = rep_cnt;
    tick( ctx );
    FD_TEST( rep_cnt==before+1UL );                       /* exactly one per call */
    FD_TEST( rep_log[ before ].slot==exp_slot[ j ] );
    FD_TEST( rep_log[ before ].fec_set_idx==exp_fec[ j ] );
    FD_TEST( rep_log[ before ].slot!=blk3->slot );        /* fresh delivery held back */
  }
  FD_TEST( out_queue_empty( ctx->deliver_queue ) );

  /* tick 5: only now, with deliver_queue empty, does the fresh chainer
     delivery (blk3) publish. */
  tick( ctx );
  FD_TEST( rep_cnt==base+4UL );
  rep_expect( base+3UL, blk3->slot, 0U, &blk3->fec_root[ 0 ], &blk3->block_id, 1 );

  /* Field-level check of the re-delivered path.  The deliver_from_root
     path populates block_id on every FEC, including the mid-slot one. */
  rep_expect( base+0UL, blk1->slot, 0U,               &blk1->fec_root[ 0 ], &blk1->block_id, 0 );
  rep_expect( base+1UL, blk1->slot, FD_FEC_SHRED_CNT, &blk1->fec_root[ 1 ], &blk1->block_id, 1 );
  rep_expect( base+2UL, blk2->slot, 0U,               &blk2->fec_root[ 0 ], &blk2->block_id, 1 );

  FD_TEST( !fd_chainer_verify( ctx->chainer ) );
  FD_LOG_NOTICE(( "pass: test_deliver_queue_priority" ));
}

/* ---------------------------------------------------------------------
   test_deliver_from_root_liveness: two liveness properties of the
   one-shot, and the fallacies they guard against.

   (1) Recovery is DELIVERY-triggered, not self-triggered.  Arming
       deliver_from_root does nothing on its own: full_fec_path_queue
       only runs when the chainer next delivers a FEC (out_queue
       non-empty).  With an empty out_queue, after_credit publishes
       nothing and the flag persists.  FALLACY SURFACED: if a fork goes
       quiescent immediately after an eviction (no new FECs delivered),
       the re-delivery never fires and replay stays drained until the
       next FEC arrives.  Recovery piggybacks on the next delivery.

   (2) A voided (equivocation-deduped) delivery -- a sentinel out_queue
       entry with slotv_idx==UINT_MAX, which the chainer pushes when it
       merges an equivocating version (see fd_chainer.c) -- is consumed
       by publish_fec_replay WITHOUT consuming the one-shot.  So the flag
       correctly waits for a REAL delivery: the round trip cannot be
       silently defeated by a multi-version slot voiding the delivery
       that happened to be next in line. */

static void
test_deliver_from_root_liveness( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  /* (1) Armed but no chainer delivery: inert. */
  FD_TEST( out_queue_empty( ctx->chainer->out_queue ) );
  ctx->deliver_from_root = 1;
  for( ulong i=0UL; i<8UL; i++ ) {
    ulong before = pub_cnt;
    tick( ctx );
    FD_TEST( pub_cnt==before );                 /* nothing published */
  }
  FD_TEST( ctx->deliver_from_root==1 );          /* flag persists, un-consumed */
  FD_TEST( rep_cnt==0UL );
  FD_TEST( out_queue_empty( ctx->deliver_queue ) );

  /* (2) A sentinel delivery (voided by equivocation dedup) must NOT
     consume the one-shot. */
  out_queue_push_tail( ctx->chainer->out_queue, (out_ele_t){ .slotv_idx = UINT_MAX, .fec_idx = 0U } );
  tick( ctx );
  FD_TEST( rep_cnt==0UL );                       /* sentinel publishes nothing */
  FD_TEST( ctx->deliver_from_root==1 );          /* one-shot survives the sentinel */
  FD_TEST( out_queue_empty( ctx->chainer->out_queue ) );
  FD_TEST( out_queue_empty( ctx->deliver_queue ) );

  /* A subsequent REAL delivery then triggers the path, proving the flag
     was still live after the sentinel.  Deliver a block off the root. */
  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 1U }};
  blk->fec_root[ 0 ] = mkhash( 0xF100UL );
  blk_build( blk );
  deliver_turbine_block( ctx, blk );
  FD_TEST( rep_cnt==0UL );

  tick( ctx );                                   /* consumes fec 0, queues path */
  FD_TEST( ctx->deliver_from_root==0 );          /* NOW consumed */
  FD_TEST( !out_queue_empty( ctx->deliver_queue ) );

  tick( ctx );                                   /* drains the single path FEC */
  FD_TEST( rep_cnt==1UL );
  rep_expect( 0UL, blk->slot, 0U, &blk->fec_root[ 0 ], &blk->block_id, 1 );

  FD_TEST( !fd_chainer_verify( ctx->chainer ) );
  FD_LOG_NOTICE(( "pass: test_deliver_from_root_liveness" ));
}

/* ---------------------------------------------------------------------
   test_deliver_from_root_populates_block_id: in the deliver_from_root
   (recovery redelivery) path, every re-published FEC must carry a
   NON-ZERO block_id -- including mid-slot FEC sets, which the normal
   turbine publish path leaves zero until the slot-complete FEC (see
   test_deliver_from_root, base+0/base+2 asserted NULL there).

   Replay depends on this: on recovery it dedups redelivered FECs by
   (slot, block_id) so it can SKIP blocks it has already replayed.  A
   zero block_id on an already-replayed ancestor FEC would defeat the
   skip, so the redelivery must name the block explicitly. */

static void
test_deliver_from_root_populates_block_id( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  /* blk1 (2 FEC sets) <- blk2 (1 FEC set), both off the snapshot root. */
  blk_t blk1[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk1->fec_root[ 0 ] = mkhash( 0xE100UL );
  blk1->fec_root[ 1 ] = mkhash( 0xE101UL );
  blk_build( blk1 );

  blk_t blk2[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = SNAP_SLOT+1UL, .parent_block_id = blk1->block_id, .fec_cnt = 1U }};
  blk2->fec_root[ 0 ] = mkhash( 0xE200UL );
  blk_build( blk2 );

  /* Deliver blk1 normally so it is complete & buffered in the chainer. */
  deliver_turbine_block( ctx, blk1 );
  pump( ctx );
  FD_TEST( rep_cnt==2UL );
  ulong base = rep_cnt;

  /* Arm the one-shot and deliver blk2, then drain the whole redelivered
     root->blk2 path. */
  ctx->deliver_from_root = 1;
  deliver_turbine_block( ctx, blk2 );
  tick( ctx );                                  /* enqueue path, publishes nothing */
  FD_TEST( rep_cnt==base );
  FD_TEST( ctx->deliver_from_root==0 );

  while( !out_queue_empty( ctx->deliver_queue ) ) tick( ctx );

  /* Path: blk1 fec 0 (mid-slot, NOT slot-complete), blk1 fec 1
     (slot-complete), blk2 fec 0 (slot-complete). */
  FD_TEST( rep_cnt==base+3UL );

  /* THE CONTRACT: every redelivered FEC carries a non-zero block_id,
     equal to its block's finalized block_id -- even the mid-slot FEC
     that the normal publish path would leave zero. */
  fd_hash_t zero = {0};
  for( ulong i=base; i<rep_cnt; i++ ) FD_TEST( !fd_hash_eq( &rep_log[ i ].block_id, &zero ) );

  FD_TEST( rep_log[ base+0UL ].slot==blk1->slot && rep_log[ base+0UL ].fec_set_idx==0U && rep_log[ base+0UL ].slot_complete==0 );
  FD_TEST( fd_hash_eq( &rep_log[ base+0UL ].block_id, &blk1->block_id ) );  /* zero in normal publish */
  FD_TEST( fd_hash_eq( &rep_log[ base+1UL ].block_id, &blk1->block_id ) );
  FD_TEST( fd_hash_eq( &rep_log[ base+2UL ].block_id, &blk2->block_id ) );

  /* ... but redelivery never marks a turbine version known: replay keys
     it by {slot, 0} until the slot-complete FEC, like the live copy. */
  for( ulong i=base; i<rep_cnt; i++ ) FD_TEST( !rep_log[ i ].known_id );

  FD_TEST( !fd_chainer_verify( ctx->chainer ) );
  FD_LOG_NOTICE(( "pass: test_deliver_from_root_populates_block_id" ));
}

/* ---------------------------------------------------------------------
   test_deliver_from_root_known_id: the known_id contract.  known_id is
   set iff the version is votor-driven (a cert version, see
   test_block_id_repair_only).  A turbine version is NEVER marked known,
   not even when redelivered from root, because replay keys a turbine
   block by {slot, 0} until it has processed the slot-complete FEC and a
   redelivered copy must key the same way as the live turbine FECs of
   the same block.  block_id is populated whenever the chainer knows it:
   on the slot-complete FEC in the normal path, and on every redelivered
   FEC of a version whose id is known.  An INCOMPLETE turbine version
   has no id yet, so its redelivered FECs carry a zero block_id.

   The bug this pins down: a redelivered FEC 0 of an incomplete turbine
   block marked known made replay key the block by id, so the live
   turbine FECs 32/64 (looking up {slot, 0}) dropped and the child's
   FEC 0 attached in sched before its parent finished delivering. */

static void
test_deliver_from_root_known_id( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );
  fd_hash_t zero = {0};

  /* blk1 (2 FEC sets) <- blk2 (3 FEC sets, delivered piecemeal) <- blk3 (1 FEC set) */
  blk_t blk1[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk1->fec_root[ 0 ] = mkhash( 0xA100UL );
  blk1->fec_root[ 1 ] = mkhash( 0xA101UL );
  blk_build( blk1 );

  blk_t blk2[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = SNAP_SLOT+1UL, .parent_block_id = blk1->block_id, .fec_cnt = 3U }};
  blk2->fec_root[ 0 ] = mkhash( 0xA200UL );
  blk2->fec_root[ 1 ] = mkhash( 0xA201UL );
  blk2->fec_root[ 2 ] = mkhash( 0xA202UL );
  blk_build( blk2 );

  blk_t blk3[1] = {{ .slot = SNAP_SLOT+3UL, .parent_slot = SNAP_SLOT+2UL, .parent_block_id = blk2->block_id, .fec_cnt = 1U }};
  blk3->fec_root[ 0 ] = mkhash( 0xA300UL );
  blk_build( blk3 );

  /* Normal turbine delivery of a complete block: never known, block_id
     only on the slot-complete FEC. */
  deliver_turbine_block( ctx, blk1 );
  pump( ctx );
  FD_TEST( rep_cnt==2UL );
  rep_expect( 0UL, blk1->slot, 0U,               &blk1->fec_root[ 0 ], NULL,            0 );
  rep_expect( 1UL, blk1->slot, FD_FEC_SHRED_CNT, &blk1->fec_root[ 1 ], &blk1->block_id, 1 );
  FD_TEST( !rep_log[ 0 ].known_id && !rep_log[ 1 ].known_id );

  /* blk2's first FEC set only: the block is incomplete in the chainer. */
  deliver_turbine_fec_set( ctx, blk2, 0U );
  pump( ctx );
  FD_TEST( rep_cnt==3UL );
  rep_expect( 2UL, blk2->slot, 0U, &blk2->fec_root[ 0 ], NULL, 0 );
  FD_TEST( !rep_log[ 2 ].known_id );

  /* Redelivery from root with the INCOMPLETE blk2 as the target: arm,
     then deliver blk2's second FEC set (still not slot-complete).  The
     path is blk1 fec 0, blk1 fec 32, blk2 fec 0, blk2 fec 32. */
  ctx->deliver_from_root = 1;
  deliver_turbine_fec_set( ctx, blk2, 1U );
  tick( ctx );                                  /* enqueue path, publishes nothing */
  FD_TEST( ctx->deliver_from_root==0 );
  FD_TEST( rep_cnt==3UL );
  while( !out_queue_empty( ctx->deliver_queue ) ) tick( ctx );
  FD_TEST( rep_cnt==7UL );

  /* Complete ancestor: id populated on every FEC, still not known. */
  rep_expect( 3UL, blk1->slot, 0U,               &blk1->fec_root[ 0 ], &blk1->block_id, 0 );
  rep_expect( 4UL, blk1->slot, FD_FEC_SHRED_CNT, &blk1->fec_root[ 1 ], &blk1->block_id, 1 );
  FD_TEST( !rep_log[ 3 ].known_id && !rep_log[ 4 ].known_id );

  /* Incomplete target: id unknown so block_id stays zero, and known_id
     is clear, so replay keys it {slot, 0} exactly like the live turbine
     FECs it already received for this block. */
  rep_expect( 5UL, blk2->slot, 0U,               &blk2->fec_root[ 0 ], NULL, 0 );
  rep_expect( 6UL, blk2->slot, FD_FEC_SHRED_CNT, &blk2->fec_root[ 1 ], NULL, 0 );
  FD_TEST( !rep_log[ 5 ].known_id && !rep_log[ 6 ].known_id );

  /* Completing blk2 normally publishes the slot-complete FEC with the
     id, still not known. */
  deliver_turbine_fec_set( ctx, blk2, 2U );
  pump( ctx );
  FD_TEST( rep_cnt==8UL );
  rep_expect( 7UL, blk2->slot, 2U*FD_FEC_SHRED_CNT, &blk2->fec_root[ 2 ], &blk2->block_id, 1 );
  FD_TEST( !rep_log[ 7 ].known_id );

  /* Redelivery with the now COMPLETE blk2 on the path (target blk3):
     every FEC carries its block's id, none is marked known. */
  ctx->deliver_from_root = 1;
  deliver_turbine_block( ctx, blk3 );
  tick( ctx );
  FD_TEST( ctx->deliver_from_root==0 );
  while( !out_queue_empty( ctx->deliver_queue ) ) tick( ctx );
  FD_TEST( rep_cnt==14UL );                     /* blk1 x2, blk2 x3, blk3 x1 */
  for( ulong i=8UL; i<rep_cnt; i++ ) {
    FD_TEST( !rep_log[ i ].known_id );
    FD_TEST( !fd_hash_eq( &rep_log[ i ].block_id, &zero ) );
  }
  rep_expect( 10UL, blk2->slot, 0U,                  &blk2->fec_root[ 0 ], &blk2->block_id, 0 );
  rep_expect( 11UL, blk2->slot, FD_FEC_SHRED_CNT,    &blk2->fec_root[ 1 ], &blk2->block_id, 0 );
  rep_expect( 12UL, blk2->slot, 2U*FD_FEC_SHRED_CNT, &blk2->fec_root[ 2 ], &blk2->block_id, 1 );
  rep_expect( 13UL, blk3->slot, 0U,                  &blk3->fec_root[ 0 ], &blk3->block_id, 1 );

  FD_TEST( !fd_chainer_verify( ctx->chainer ) );
  FD_LOG_NOTICE(( "pass: test_deliver_from_root_known_id" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_turbine_shreds( wksp );

  fd_wksp_reset( wksp, 1U );
  test_votor_notar_fallback( wksp );

  fd_wksp_reset( wksp, 1U );
  test_fec_rekey_merge( wksp );

  fd_wksp_reset( wksp, 1U );
  test_notar_fallback_same_block( wksp );

  fd_wksp_reset( wksp, 1U );
  test_block_id_repair_only( wksp );

  fd_wksp_reset( wksp, 1U );
  test_inflight_popped( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_from_root( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_from_root_arming( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_from_root_degenerate( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_queue_priority( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_from_root_liveness( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_from_root_populates_block_id( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_from_root_known_id( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
