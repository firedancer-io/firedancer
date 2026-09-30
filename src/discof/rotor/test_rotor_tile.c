/* Closed-loop harness for the rotor tile.  fd_rotor_tile.c is included
   with fd_stem_publish mocked to a recorder, then the rest of the
   validator is played around it: sign frags are echoed back with a
   dummy signature, repair_net packets are parsed into a request log,
   shred frags are fed in as the shred tile would, and metadata
   responses are crafted with real double-merkle proofs.  Replay
   publishes are recorded and asserted on. */

#include "../../disco/topo/fd_topo.h"   /* pulls in fd_stem.h so the static inline parses */
#include "../../disco/shred/fd_shred_tile.h"

#define TEST_OUT_MAX (8UL)
static void * test_out_mem[ TEST_OUT_MAX ];

#define OUT_IDX_NET    (0UL)
#define OUT_IDX_REPLAY (1UL)
#define OUT_IDX_SIGN   (2UL)
#define OUT_IDX_RSERVE (3UL)

#define IN_IDX_NET    (0UL)
#define IN_IDX_SHRED  (1UL)
#define IN_IDX_VOTOR  (2UL)
#define IN_IDX_SIGN   (3UL)
#define IN_IDX_REPLAY (4UL)
#define IN_IDX_GOSSIP (5UL)

typedef struct {
  ulong out_idx;
  ulong sig;
  ulong sz;
  uchar data[ 2048 ];
} pub_t;

#define PUB_MAX (16384UL)
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

#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub )  \
  do { (void)(stem); (void)(ctl); (void)(tsorig); (void)(tspub);              \
       test_stem_publish( (out_idx), (sig), (chunk), (sz) ); } while(0)

#include "fd_rotor_tile.c"

#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"

/* Every packet the tile sent on repair_net, parsed back. */

typedef struct {
  uint      kind;
  uint      nonce;
  ulong     slot;
  uint      idx;      /* shred idx, or fec_set_idx for FEC_ROOT */
  fd_hash_t block_id; /* alpenglow kinds only */
} req_t;

#define REQ_MAX (16384UL)
static req_t req_log[ REQ_MAX ];
static ulong req_cnt;

#define REP_MAX (512UL)
static fd_rotor_replay_fec_t rep_log[ REP_MAX ];
static ulong                 rep_cnt;

/* drain plays every unprocessed publish: sign requests are answered
   with a dummy signature (which publishes the packet, picked up by the
   same loop), net packets are parsed into req_log, replay frags into
   rep_log. */

static void
drain( ctx_t * ctx ) {
  static uchar sigbuf[ 64 ];
  while( pub_cursor<pub_cnt ) {
    pub_t rec = pub_log[ pub_cursor++ ]; /* copy: the log grows as we iterate */

    if( rec.out_idx==OUT_IDX_SIGN ) {

      memset( sigbuf, 0xAB, sizeof(sigbuf) );
      handle_sign( ctx, IN_IDX_SIGN, rec.sig, sigbuf, NULL );

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

      FD_TEST( rec.sig==ROTOR_SIG_FEC_REPLAY );
      FD_TEST( rec.sz==sizeof(fd_rotor_replay_fec_t) );
      FD_TEST( rep_cnt<REP_MAX );
      fd_memcpy( &rep_log[ rep_cnt++ ], rec.data, sizeof(fd_rotor_replay_fec_t) );

    } else if( rec.out_idx==OUT_IDX_RSERVE ) {

      FD_TEST( rec.sig==ROTOR_SIG_BLOCK );
      FD_TEST( rec.sz>=FD_ROTOR_BLOCK_SZ( 0 ) );
    } else {
      FD_LOG_ERR(( "unexpected out_idx %lu", rec.out_idx ));
    }
  }
}

/* tick runs one after_credit and plays the sign tile / collects output. */

static void
tick( ctx_t * ctx ) {
  ulong cr_avail[ TEST_OUT_MAX ] = { [ OUT_IDX_REPLAY ] = ULONG_MAX };
  fd_stem_context_t stem = { .cr_avail = cr_avail, .now = fd_tickcount() };
  int charge_busy = 0;
  int poll_in     = 1;
  after_credit( ctx, &stem, &poll_in, &charge_busy );
  drain( ctx );
}

/* pump ticks until an iteration produces nothing new and every queue is
   drained.  The schedulor is not drained: a parked block is due in the
   future, so ticking cannot empty it. */

static void
pump( ctx_t * ctx ) {
  for( ulong i=0UL; i<200000UL; i++ ) {
    ulong before = pub_cnt;
    tick( ctx );
    if( pub_cnt==before &&
        toss_queue_empty( ctx->toss_queue ) &&
        out_queue_empty( ctx->rotor->out_queue ) &&
        out_queue_empty( ctx->redeliver ) ) return;
  }
  FD_LOG_ERR(( "pump did not quiesce" ));
}

/* force_check makes a block's check due now.  Insert is
   insert-if-absent, so a parked check has to be dropped first; the live
   tile just waits for the timeout. */

static void
force_check( ctx_t * ctx, ulong slot, fd_hash_t const * block_id ) {
  fd_schedulor_block_remove( ctx->schedulor, slot, block_id );
  fd_schedulor_block_insert( ctx->schedulor, slot, block_id, 0L );
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, slot, block_id ) );
}

/* Query helpers */

static req_t *
req_find( ulong from, uint kind, ulong slot, uint idx, fd_hash_t const * block_id ) {
  for( ulong i=from; i<req_cnt; i++ ) {
    req_t * r = &req_log[ i ];
    if( r->kind!=kind || r->slot!=slot                    ) continue;
    if( idx!=UINT_MAX && r->idx!=idx                      ) continue;
    if( block_id && !fd_hash_eq( &r->block_id, block_id ) ) continue;
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

/* mkhash returns a distinct, deterministic, never-zero hash for n. */

static fd_hash_t
mkhash( ulong n ) {
  fd_hash_t h;
  memset( h.uc, 0, sizeof(fd_hash_t) );
  for( ulong i=0UL; i<8UL; i++ ) h.uc[ i ] = (uchar)( n>>(i*8UL) );
  h.uc[ 8 ] = 0xa5;
  return h;
}

/* A block's id is the double merkle root over its FEC set roots plus a
   final parent-info leaf (see finalize_block_id in fd_rotor.c).
   blk_build computes it the same way and extracts the inclusion proof
   for every leaf, so tests can craft verifiable metadata responses. */

#define BLK_FEC_MAX (8UL)
#define BLK_TREE_LAYER_CNT (6UL)

typedef struct {
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t parent_block_id;
  uint      fec_cnt;
  fd_hash_t fec_root[ BLK_FEC_MAX ];
  fd_hash_t block_id;
  ulong     proof_len;
  uchar     proof[ BLK_FEC_MAX+1UL ][ AG_MAX_FEC_PROOF_NODE_CNT*FD_SHRED_MERKLE_NODE_SZ ];
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
  fd_sha256_append( sha, &b->parent_slot,       sizeof(ulong)     );
  fd_sha256_append( sha, b->parent_block_id.uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &b->fec_cnt,           sizeof(uint)      );
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

/* blk_fec_flags returns the data-shred flags on the last shred of FEC
   set k. */

static uchar
blk_fec_flags( blk_t const * b, uint k ) {
  return (uchar)( k==b->fec_cnt-1U ? FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE
                                   : FD_SHRED_DATA_FLAG_DATA_COMPLETE );
}

/* Inbound frags.  Reliable links go through before_frag then
   returnable_frag; net frags are staged in ctx->net_buf and pushed
   through after_frag, the path during_frag feeds. */

static uchar * test_in_mem[ 6 ];
static ulong test_tsorig;

static void
deliver_frag( ctx_t * ctx, ulong in_idx, ulong sig, void const * msg, ulong sz ) {
  FD_TEST( !before_frag( ctx, in_idx, 0UL, sig ) );
  fd_memcpy( test_in_mem[ in_idx ], msg, sz );
  FD_TEST( !returnable_frag( ctx, in_idx, 0UL, sig, 0UL /* chunk */, sz, 0UL, test_tsorig ? test_tsorig : fd_frag_meta_ts_comp( fd_tickcount() ), 0UL, NULL ) );
  drain( ctx );
}

static void
deliver_net_response( ctx_t * ctx, uchar const * payload, ulong payload_sz ) {
  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, 0x0A000001U, 8000 );
  FD_TEST( sizeof(fd_ip4_udp_hdrs_t)+payload_sz<=FD_NET_MTU );
  fd_memcpy( ctx->net_buf,                           hdrs,    sizeof(fd_ip4_udp_hdrs_t) );
  fd_memcpy( ctx->net_buf+sizeof(fd_ip4_udp_hdrs_t), payload, payload_sz               );
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
  fd_memcpy( buf+off, parent_block_id->uc, sizeof(fd_hash_t)        ); off += sizeof(fd_hash_t);
  FD_STORE( ulong, buf+off, proof_sz                                ); off += 8UL;
  fd_memcpy( buf+off, proof, proof_sz                               ); off += proof_sz;
  FD_STORE( uint,  buf+off, nonce                                   ); off += 4UL;
  return off;
}

static ulong
ser_fec_root_res( uchar * buf, fd_hash_t const * root,
                  uchar const * proof, ulong proof_len, uint nonce ) {
  ulong proof_sz = proof_len*FD_SHRED_MERKLE_NODE_SZ;
  ulong off      = 0UL;
  FD_STORE( uint,  buf+off, AG_REPAIR_RESPONSE_FEC_SET_ROOT ); off += 4UL;
  fd_memcpy( buf+off, root->uc, FD_SHRED_MERKLE_NODE_SZ     ); off += FD_SHRED_MERKLE_NODE_SZ;
  FD_STORE( ulong, buf+off, proof_sz                        ); off += 8UL;
  fd_memcpy( buf+off, proof, proof_sz                       ); off += proof_sz;
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

/* Shred tile simulation */

/* mk_block_header_marker serializes a BlockHeaderV1 marker into buf
   (see fd_block_marker_de). */

static ulong
mk_block_header_marker( uchar * buf, ulong parent_slot, fd_hash_t const * parent_block_id ) {
  FD_TEST( parent_block_id );
  ulong off = 0UL;
  FD_STORE( ulong,  buf+off, 0UL         ); off += 8UL;
  FD_STORE( ushort, buf+off, (ushort)1   ); off += 2UL;
  buf[ off++ ] = (uchar)FD_BLOCK_MARKER_SERDE_TAG_HEADER;
  FD_STORE( ushort, buf+off, (ushort)41  ); off += 2UL;
  buf[ off++ ] = (uchar)1;
  FD_STORE( ulong,  buf+off, parent_slot ); off += 8UL;
  fd_memcpy( buf+off, parent_block_id->uc, sizeof(fd_hash_t) ); off += sizeof(fd_hash_t);
  return off;
}

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

  deliver_frag( ctx, IN_IDX_SHRED, (ulong)src, base, sizeof(fd_shred_base_t) );
}

/* deliver_code_shred feeds one coding shred of a FEC set the way
   shred_out does.  res is the fec_resolver result the shred tile tags
   the frag with (SHRED_SIG_RESULT_DUPLICATE for a shred the resolver
   already had). */

static void
deliver_code_shred( ctx_t * ctx, ulong slot, uint fec_set_idx, uint idx, fd_hash_t const * mr, uint src, int res ) {
  static fd_shred_base_t base[1];
  memset( base, 0, sizeof(fd_shred_base_t) );
  base->merkle_root = *mr;

  fd_shred_t * shred = &base->shred;
  shred->variant     = fd_shred_variant( FD_SHRED_TYPE_MERKLE_CODE, 5 );
  shred->slot        = slot;
  shred->idx         = idx;
  shred->fec_set_idx = fec_set_idx;
  shred->code.idx    = (ushort)idx;

  deliver_frag( ctx, IN_IDX_SHRED, ( (ulong)(uint)res<<32 ) | (ulong)src, base, sizeof(fd_shred_base_t) );
}

static void
deliver_fec_complete_sig( ctx_t * ctx, ulong slot, uint fec_set_idx, uchar flags, fd_hash_t const * mr, ulong sig ) {
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
  deliver_frag( ctx, IN_IDX_SHRED, sig, &msg, sizeof(msg) );
}

static void
deliver_fec_complete( ctx_t * ctx, ulong slot, uint fec_set_idx, uchar flags, fd_hash_t const * mr ) {
  deliver_fec_complete_sig( ctx, slot, fec_set_idx, flags, mr, SHRED_SIG_FEC_COMPLETE );
}

static void
deliver_fec_evicted( ctx_t * ctx, ulong slot, uint fec_set_idx, fd_hash_t const * mr ) {
  fd_fec_evicted_t msg = { .slot = slot, .fec_set_idx = fec_set_idx, .merkle_root = *mr };
  deliver_frag( ctx, IN_IDX_SHRED, SHRED_SIG_FEC_EVICTED, &msg, sizeof(msg) );
}

static void
deliver_votor( ctx_t * ctx, ulong slot, fd_hash_t const * block_id ) {
  fd_votor_repair_t msg = { .slot = slot, .block_id = *block_id };
  deliver_frag( ctx, IN_IDX_VOTOR, FD_VOTOR_SIG_REPAIR, &msg, sizeof(msg) );
}

static void
deliver_replay_root( ctx_t * ctx, ulong slot, fd_hash_t const * block_id ) {
  fd_replay_root_advanced_t msg = { .slot = slot, .block_id = *block_id };
  deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_ROOT_ADVANCED, &msg, sizeof(msg) );
}

static void
deliver_replay_missing_fec( ctx_t * ctx ) {
  ulong msg = 0UL;
  deliver_frag( ctx, IN_IDX_REPLAY, REPLAY_SIG_MISSING_FEC, &msg, sizeof(msg) );
}

/* deliver_turbine_fec_set feeds every shred of FEC set k plus its
   completion, the way the shred tile does. */

static void
deliver_turbine_fec_set( ctx_t * ctx, blk_t const * b, uint k ) {
  FD_TEST( k<b->fec_cnt );
  uchar flags = blk_fec_flags( b, k );
  for( uint i=0U; i<FD_FEC_SHRED_CNT; i++ ) {
    uint idx = k*FD_FEC_SHRED_CNT+i;
    deliver_shred( ctx, b->slot, idx, (uchar)( i==FD_FEC_SHRED_CNT-1U ? flags : 0 ), &b->fec_root[ k ],
                   0U, SHRED_SIG_SRC_TURBINE, b->parent_slot, &b->parent_block_id );
  }
  deliver_fec_complete( ctx, b->slot, k*FD_FEC_SHRED_CNT, flags, &b->fec_root[ k ] );
}

static void
deliver_turbine_block( ctx_t * ctx, blk_t const * b ) {
  for( uint k=0U; k<b->fec_cnt; k++ ) deliver_turbine_fec_set( ctx, b, k );
}

/* serve_shred_requests answers every ShredForBlockId request for block
   b in req_log[from..) with a repair shred carrying the set's real
   root, emitting a FEC completion once a set is fully served.
   served[k] accumulates across calls.  Returns the count answered. */

static ulong
serve_shred_requests( ctx_t * ctx, ulong from, blk_t const * b, uint * served ) {
  ulong answered = 0UL;
  for( ulong i=from; i<req_cnt; i++ ) {
    req_t const * r = &req_log[ i ];
    if( r->kind!=AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID ) continue;
    if( r->slot!=b->slot                           ) continue;
    if( !fd_hash_eq( &r->block_id, &b->block_id )  ) continue;

    uint k = r->idx/FD_FEC_SHRED_CNT;
    FD_TEST( k<b->fec_cnt );
    int   last  = ( (r->idx&(FD_FEC_SHRED_CNT-1U))==FD_FEC_SHRED_CNT-1U );
    uchar flags = (uchar)( last ? blk_fec_flags( b, k ) : 0 );
    deliver_shred( ctx, b->slot, r->idx, flags, &b->fec_root[ k ], r->nonce, SHRED_SIG_SRC_REPAIR,
                   b->parent_slot, &b->parent_block_id );
    served[ k ]++;
    if( served[ k ]==FD_FEC_SHRED_CNT ) {
      deliver_fec_complete( ctx, b->slot, k*FD_FEC_SHRED_CNT, blk_fec_flags( b, k ), &b->fec_root[ k ] );
      pump( ctx ); /* publish queued deliveries, so per-FEC order is deterministic */
    }
    answered++;
  }
  return answered;
}

/* Setup.  Mirrors what unprivileged_init assembles, with test-sized
   parameters, flat buffers for the dcaches and one sign tile. */

#define TEST_SLOT_MAX  (32UL)
#define TEST_BLOCK_MAX (TEST_SLOT_MAX*FD_ROTOR_SLOT_VER_MAX)
#define TEST_PEER_MAX  (128UL)
static int lg_sign_depth_test = 6;

#define SNAP_SLOT (100UL)
static fd_hash_t snap_bid;
static fd_pubkey_t peer_key[ 2 ];

static void
setup_ctx( ctx_t * ctx, fd_wksp_t * wksp ) {
  memset( ctx, 0, sizeof(*ctx) );
  fd_event_tl = NULL;
  fd_clock_tile_init( ctx->clock );

  pub_cnt = 0UL; pub_cursor = 0UL;
  req_cnt = 0UL;
  rep_cnt = 0UL;
  test_tsorig = 0UL;
  memset( test_out_mem, 0, sizeof(test_out_mem) );

  FD_TEST( fd_rng_secure( &ctx->repair_seed, sizeof(ulong) ) );
  FD_TEST( fd_rng_secure( ctx->repair_nonce_ss, sizeof(fd_rnonce_ss_t) ) );

  ulong redeliver_max = TEST_BLOCK_MAX * ( FD_SHRED_BLK_MAX/FD_FEC_SHRED_CNT );

  void * rotor_mem     = fd_wksp_alloc_laddr( wksp, fd_rotor_align(),     fd_rotor_footprint    ( TEST_SLOT_MAX, FD_SHRED_BLK_MAX ), 1UL );
  void * schedulor_mem = fd_wksp_alloc_laddr( wksp, fd_schedulor_align(), fd_schedulor_footprint( TEST_BLOCK_MAX ),                  1UL );
  void * requestor_mem = fd_wksp_alloc_laddr( wksp, fd_requestor_align(), fd_requestor_footprint(),                                  1UL );
  void * policy_mem    = fd_wksp_alloc_laddr( wksp, fd_policy_align(),    fd_policy_footprint   ( TEST_PEER_MAX ),                   1UL );
  void * rtt_mem       = fd_wksp_alloc_laddr( wksp, fd_inflights_align(), fd_inflights_footprint(),                                  1UL );
  void * signs_map_mem = fd_wksp_alloc_laddr( wksp, fd_signs_map_align(), fd_signs_map_footprint( lg_sign_depth_test ),              1UL );
  void * toss_mem      = fd_wksp_alloc_laddr( wksp, toss_queue_align(),   toss_queue_footprint  (),                                  1UL );
  void * repair_mem    = fd_wksp_alloc_laddr( wksp, fd_repair_align(),    fd_repair_footprint   (),                                  1UL );
  void * redeliver_mem = fd_wksp_alloc_laddr( wksp, out_queue_align(),    out_queue_footprint   ( redeliver_max ),                   1UL );
  void * store_mem     = fd_wksp_alloc_laddr( wksp, fd_store_align(),     fd_store_footprint    ( 1024UL, 64UL, 0UL, 0UL, 0UL ),     1UL );
  FD_TEST( rotor_mem && schedulor_mem && requestor_mem && policy_mem && rtt_mem && signs_map_mem && toss_mem && repair_mem && redeliver_mem && store_mem );

  ctx->rotor      = fd_rotor_join    ( fd_rotor_new    ( rotor_mem,     TEST_SLOT_MAX, FD_SHRED_BLK_MAX, ctx->repair_seed     ) );
  ctx->schedulor  = fd_schedulor_join( fd_schedulor_new( schedulor_mem, TEST_BLOCK_MAX, fd_clock_epoch_w( ctx->clock->epoch ), ctx->repair_seed ) );
  ctx->requestor  = fd_requestor_join( fd_requestor_new( requestor_mem                                                        ) );
  ctx->policy     = fd_policy_join   ( fd_policy_new   ( policy_mem,    TEST_PEER_MAX, ctx->repair_seed, ctx->repair_nonce_ss ) );
  ctx->rtt        = fd_inflights_join( fd_inflights_new( rtt_mem,       ctx->repair_seed+1234UL                               ) );
  ctx->signs_map  = fd_signs_map_join( fd_signs_map_new( signs_map_mem, lg_sign_depth_test, 0UL                               ) );
  ctx->toss_queue = toss_queue_join  ( toss_queue_new  ( toss_mem                                                             ) );
  ctx->protocol   = fd_repair_join   ( fd_repair_new   ( repair_mem,    &ctx->identity_public_key                             ) );
  ctx->redeliver  = out_queue_join   ( out_queue_new   ( redeliver_mem, redeliver_max                                         ) );
  ctx->store      = fd_store_join    ( fd_store_new    ( store_mem,     1024UL, 64UL, 0UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL   ) );
  FD_TEST( ctx->rotor && ctx->schedulor && ctx->requestor && ctx->policy && ctx->rtt && ctx->signs_map && ctx->toss_queue && ctx->protocol && ctx->redeliver && ctx->store );
  FD_TEST( fd_store_map_ljoin( ctx->store, ctx->store_map ) );
  ctx->receive_event = fd_wksp_alloc_laddr( wksp, alignof(fd_event_block_received_t), sizeof(fd_event_block_received_t), 1UL );
  FD_TEST( ctx->receive_event );

  /* Out links.  fd_chunk_to_laddr( mem, 0 )==mem, so chunk0=0 over a
     flat buffer behaves like a compact dcache. */

  ulong dcache_sz = 65536UL;
  void * net_dcache    = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  void * replay_dcache = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  void * sign_dcache   = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  void * rserve_dcache = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  FD_TEST( net_dcache && replay_dcache && sign_dcache && rserve_dcache );
  ulong wmark = (dcache_sz>>FD_CHUNK_LG_SZ)-(2048UL>>FD_CHUNK_LG_SZ)-1UL;

  ctx->net_out_ctx->idx    = OUT_IDX_NET;
  ctx->net_out_ctx->mem    = net_dcache;
  ctx->net_out_ctx->chunk0 = 0UL;
  ctx->net_out_ctx->wmark  = wmark;
  ctx->net_out_ctx->chunk  = 0UL;

  ctx->replay_out_ctx->idx    = OUT_IDX_REPLAY;
  ctx->replay_out_ctx->mem    = replay_dcache;
  ctx->replay_out_ctx->chunk0 = 0UL;
  ctx->replay_out_ctx->wmark  = wmark;
  ctx->replay_out_ctx->chunk  = 0UL;

  ctx->rserve_out_ctx->idx    = OUT_IDX_RSERVE;
  ctx->rserve_out_ctx->mem    = rserve_dcache;
  ctx->rserve_out_ctx->chunk0 = 0UL;
  ctx->rserve_out_ctx->wmark  = wmark;
  ctx->rserve_out_ctx->chunk  = 0UL;

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
  test_out_mem[ OUT_IDX_RSERVE ] = rserve_dcache;

  /* In links */

  ulong in_buf_sz = 32768UL;
  FD_TEST( sizeof(fd_gossip_update_message_t)<=in_buf_sz );
  ctx->in_kind[ IN_IDX_NET    ] = IN_KIND_NET;
  ctx->in_kind[ IN_IDX_SHRED  ] = IN_KIND_SHRED;
  ctx->in_kind[ IN_IDX_VOTOR  ] = IN_KIND_VOTOR;
  ctx->in_kind[ IN_IDX_SIGN   ] = IN_KIND_SIGN;
  ctx->in_kind[ IN_IDX_REPLAY ] = IN_KIND_REPLAY;
  ctx->in_kind[ IN_IDX_GOSSIP ] = IN_KIND_GOSSIP;
  for( ulong i=IN_IDX_SHRED; i<=IN_IDX_GOSSIP; i++ ) {
    void * buf = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, in_buf_sz, 1UL );
    FD_TEST( buf );
    test_in_mem[ i ]          = buf;
    ctx->in_links[ i ].mem    = buf;
    ctx->in_links[ i ].chunk0 = 0UL;
    ctx->in_links[ i ].wmark  = (in_buf_sz>>FD_CHUNK_LG_SZ)-1UL;
    ctx->in_links[ i ].mtu    = in_buf_sz;
  }
  test_in_mem[ IN_IDX_SIGN ] = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, in_buf_sz, 1UL );
  FD_TEST( test_in_mem[ IN_IDX_SIGN ] );

  fd_ip4_udp_hdr_init( ctx->intake_hdr, 0UL, 0U, 1234 );
  fd_histf_join( fd_histf_new( ctx->metrics->response_latency,
                               FD_MHIST_MIN( ROTOR, RESPONSE_LATENCY_NANOS ),
                               FD_MHIST_MAX( ROTOR, RESPONSE_LATENCY_NANOS ) ) );

  ctx->turbine_slot0     = ULONG_MAX;
  ctx->pending_key_next  = 0UL;
  ctx->ag_nonce          = 0U;

  /* Snapshot: root the rotor the way handle_snap does. */

  snap_bid = mkhash( 0xB1D100UL );
  fd_rotor_init( ctx->rotor, SNAP_SLOT, &snap_bid, report_block_received, ctx );
  FD_TEST( !fd_rotor_verify( ctx->rotor ) );

  /* Two repair peers, as if discovered via gossip. */

  peer_key[ 0 ] = *(fd_pubkey_t *)fd_type_pun( mkhash( 0xEE01UL ).uc );
  peer_key[ 1 ] = *(fd_pubkey_t *)fd_type_pun( mkhash( 0xEE02UL ).uc );
  fd_ip4_port_t addr0 = { .addr = 0x0A000002U, .port = 9001 };
  fd_ip4_port_t addr1 = { .addr = 0x0A000003U, .port = 9002 };
  FD_TEST( fd_policy_peer_upsert( ctx->policy, &peer_key[ 0 ], &addr0 ) );
  FD_TEST( fd_policy_peer_upsert( ctx->policy, &peer_key[ 1 ], &addr1 ) );
}

/* deliver_gossip_peers feeds n contact-info frags the way the gossip
   tile does, so the tile's own peer bookkeeping runs. */

static void
deliver_gossip_peers( ctx_t * ctx, ulong n ) {
  for( ulong i=0UL; i<n; i++ ) {
    static fd_gossip_update_message_t msg[1];
    memset( msg, 0, sizeof(fd_gossip_update_message_t) );
    msg->tag = FD_GOSSIP_UPDATE_TAG_CONTACT_INFO;
    fd_hash_t key = mkhash( 0xEF00UL+i ); /* distinct from the setup peers */
    fd_memcpy( msg->origin, key.uc, sizeof(fd_hash_t) );
    fd_gossip_socket_t * sock = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR ];
    sock->is_ipv6 = 0;
    sock->ip4     = 0x0A000004U+(uint)i;
    sock->port    = (ushort)( 9100U+i );
    deliver_frag( ctx, IN_IDX_GOSSIP, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, msg, sizeof(fd_gossip_update_message_t) );
    pump( ctx ); /* drain the per-peer warmup request */
  }
}

/* Catchup seeding waits for enough peers to spread the burst over.
   Below the threshold the first turbine shred fixes the target and
   seeds nothing; the gossip frag that crosses the peer count sends one
   Shred and one HighestShred per slot between the root and the target,
   exactly once. */

static void
test_catchup_seed( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+4UL, .parent_slot = SNAP_SLOT+3UL, .parent_block_id = mkhash( 0x140UL ), .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0x141UL );
  blk->fec_root[ 1 ] = mkhash( 0x142UL );
  blk_build( blk );

  deliver_shred( ctx, blk->slot, 0U, 0, &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_TURBINE,
                 blk->parent_slot, &blk->parent_block_id );
  FD_TEST( ctx->turbine_slot0==blk->slot );
  FD_TEST( !ctx->catchup_seeded );                      /* two peers is below the threshold */
  pump( ctx );
  FD_TEST( !req_find( 0UL, FD_REPAIR_KIND_HIGHEST_SHRED, SNAP_SLOT+1UL, 0U, NULL ) );

  ulong from = req_cnt;
  deliver_gossip_peers( ctx, 64UL );                    /* gossip catches up, crossing the threshold */
  FD_TEST( ctx->catchup_seeded );

  /* one of each kind for every slot between the root and the target */
  for( ulong slot=SNAP_SLOT+1UL; slot<blk->slot; slot++ ) {
    FD_TEST( req_find( from, FD_REPAIR_KIND_SHRED,         slot, 0U, NULL ) );
    FD_TEST( req_find( from, FD_REPAIR_KIND_HIGHEST_SHRED, slot, 0U, NULL ) );
  }

  /* and never again */
  ulong after = req_cnt;
  deliver_gossip_peers( ctx, 4UL );
  FD_TEST( req_count( after, FD_REPAIR_KIND_HIGHEST_SHRED, SNAP_SLOT+1UL )==0UL );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: catchup seeding waits for peers and fires once" ));
}

/* A turbine block arrives shred by shred.  The shred-0 marker names the
   parent, the first turbine shred fixes the catchup target, each FEC
   set delivers to replay in order, the block_id is finalized to an
   independently computed double-merkle root, complete_ts is stamped,
   and the version's tally counts the shreds by source. */

static void
test_turbine_block( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0xA0UL );
  blk->fec_root[ 1 ] = mkhash( 0xA1UL );
  blk_build( blk );

  deliver_turbine_fec_set( ctx, blk, 0U );
  FD_TEST( ctx->turbine_slot0==blk->slot );
  FD_TEST( ctx->current_slot==blk->slot );
  FD_TEST( !fd_rotor_verify( ctx->rotor ) );

  fd_rotor_blk_t * v0 = fd_rotor_slot_query( ctx->rotor, blk->slot );
  FD_TEST( v0 && v0->turbine );
  FD_TEST( v0->buffered_idx==FD_FEC_SHRED_CNT-1U );
  FD_TEST( v0->parent_slot==SNAP_SLOT );                    /* from the shred-0 marker */
  FD_TEST( fd_hash_eq( &v0->parent_block_id, &snap_bid ) );
  FD_TEST( v0->connected );
  FD_TEST( !v0->metrics.last_shred_ts );                              /* not whole yet */

  pump( ctx );
  rep_expect( 0UL, blk->slot, 0U, &blk->fec_root[ 0 ], NULL, 0 );
  FD_TEST( rep_cnt==1UL );

  deliver_turbine_fec_set( ctx, blk, 1U );
  pump( ctx );

  FD_TEST( fd_rotor_block_complete( v0 ) );
  FD_TEST( v0->metrics.last_shred_ts );                               /* stamped on completion */
  FD_TEST( fd_hash_eq( &v0->block_id, &blk->block_id ) );   /* matches the independent computation */
  FD_TEST( fd_rotor_slot_version_query( ctx->rotor, blk->slot, &blk->block_id )==v0 );
  FD_TEST( fd_rotor_highest_repaired_slot( ctx->rotor )==blk->slot );

  FD_TEST( rep_cnt==2UL );
  rep_expect( 1UL, blk->slot, FD_FEC_SHRED_CNT, &blk->fec_root[ 1 ], &blk->block_id, 1 );

  /* the rotor's own per-version tally replaces the repair stats */
  FD_TEST( v0->metrics.turbine_cnt==2U*FD_FEC_SHRED_CNT );
  FD_TEST( v0->metrics.repair_cnt==0U );
  FD_TEST( ctx->metrics->fecs_delivered==2UL );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: turbine block delivers and finalizes" ));
}

/* Exercise the real event reporter independently of the mocked stem
   outputs: event links publish directly to an unreliable mcache. */

static void
enable_event_reporting( fd_wksp_t * wksp ) {
  static fd_event_reporter_t reporter[1];
  memset( reporter, 0, sizeof(reporter) );
  FD_TEST( fd_tile_rotor.max_event_sz );
  ulong mtu = fd_tile_rotor.max_event_sz( NULL );
  FD_TEST( mtu==sizeof(fd_event_block_received_t) );
  ulong depth = 128UL;
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  void * mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL );
  void * dcache_mem = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL );
  FD_TEST( mcache_mem && dcache_mem );
  reporter->mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
  void * dcache = fd_dcache_join( fd_dcache_new( dcache_mem, data_sz, 0UL ) );
  FD_TEST( reporter->mcache && dcache );
  reporter->depth     = depth;
  reporter->seq_store = fd_mcache_seq_laddr( reporter->mcache );
  reporter->mem       = wksp;
  reporter->chunk0    = fd_dcache_compact_chunk0( wksp, dcache );
  reporter->wmark     = fd_dcache_compact_wmark( wksp, dcache, mtu );
  reporter->chunk     = reporter->chunk0;
  reporter->mtu       = mtu;
  fd_event_tl = reporter;
}

static fd_event_block_received_t const *
expect_block_received( ulong seq ) {
  fd_event_reporter_t * r = fd_event_tl;
  FD_TEST( r && seq<r->seq );
  FD_TEST( fd_mcache_seq_query( r->seq_store )==r->seq );
  fd_frag_meta_t const * frag = &r->mcache[ fd_mcache_line_idx( seq, r->depth ) ];
  FD_TEST( frag->seq==seq );
  FD_TEST( FD_EVENT_SIG_TYPE( frag->sig )==21UL );
  fd_event_block_received_t const * ev = fd_chunk_to_laddr_const( r->mem, frag->chunk );
  FD_TEST( ev->fec_sets_cnt<=FD_EVENT_BLOCK_RECEIVED_FEC_SETS_MAX );
  FD_TEST( FD_EVENT_SIG_SZ( frag->sig )==fd_event_block_received_footprint( ev ) );
  /* These fields need new bookkeeping and remain zero for now. */
  FD_TEST( !ev->equivocation_detected_shred );
  for( ulong i=0UL; i<ev->fec_sets_cnt; i++ ) {
    fd_event_block_received_fec_sets_t const * f = &ev->fec_sets[ i ];
    FD_TEST( !f->fec_duplicate_shred_count );
    FD_TEST( !(f->fec_repair_shreds_received & ~f->fec_data_shreds_received) );
    FD_TEST( f->fec_source_repair==!!f->fec_repair_shreds_received );
  }
  return ev;
}

static void
test_block_received_event( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );
  enable_event_reporting( wksp );
  memset( ctx->receive_event, 0xA5, sizeof(fd_event_block_received_t) );

  /* Leave an earlier slot incomplete so root advancement must emit its
     row.  Complete the next slot out of order, independently of replay. */
  blk_t incomplete = { .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U };
  incomplete.fec_root[ 0 ] = mkhash( 0xEC00UL );
  incomplete.fec_root[ 1 ] = mkhash( 0xEC01UL );
  blk_build( &incomplete );
  deliver_turbine_fec_set( ctx, &incomplete, 0U );
  FD_TEST( fd_event_tl->seq==0UL );

  blk_t complete = { .slot = SNAP_SLOT+2UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U };
  complete.fec_root[ 0 ] = mkhash( 0xEC10UL );
  complete.fec_root[ 1 ] = mkhash( 0xEC11UL );
  blk_build( &complete );
  deliver_turbine_fec_set( ctx, &complete, 1U );
  FD_TEST( fd_event_tl->seq==0UL );
  deliver_turbine_fec_set( ctx, &complete, 0U );
  FD_TEST( fd_event_tl->seq==1UL );
  fd_event_block_received_t const * ev = expect_block_received( 0UL );
  FD_TEST( ev->slot==complete.slot && ev->parent_slot==SNAP_SLOT );
  FD_TEST( !memcmp( ev->parent_block_id, snap_bid.uc, 32UL ) );
  FD_TEST( !ev->cancelled && !ev->notarized && ev->slot_complete_flag );
  FD_TEST( ev->fec_set_count==2UL && ev->fec_sets_cnt==2UL );
  FD_TEST( ev->turbine_shred_received==2U*FD_FEC_SHRED_CNT );
  FD_TEST( !ev->repair_shred_received && !ev->recovered_shred_count && !ev->parity_shred_received );
  FD_TEST( ev->first_shred_received_time && ev->last_shred_received_time>=ev->first_shred_received_time );
  for( ulong k=0UL; k<2UL; k++ ) {
    FD_TEST( ev->fec_sets[ k ].fec_set_index==k*FD_FEC_SHRED_CNT );
    FD_TEST( !memcmp( ev->fec_sets[ k ].fec_merkle_root, complete.fec_root[ k ].uc, 32UL ) );
    FD_TEST( ev->fec_sets[ k ].fec_data_shreds_received==UINT_MAX );
    FD_TEST( !ev->fec_sets[ k ].fec_parity_shreds_received && !ev->fec_sets[ k ].fec_repair_shreds_received );
    FD_TEST( !ev->fec_sets[ k ].fec_final_shred_source_repair );
    FD_TEST( ev->fec_sets[ k ].fec_first_shred_received_nanos );
    FD_TEST( ev->fec_sets[ k ].fec_completed_nanos>=ev->fec_sets[ k ].fec_first_shred_received_nanos );
  }

  deliver_fec_complete( ctx, complete.slot, 0U, blk_fec_flags( &complete, 0U ), &complete.fec_root[ 0 ] );
  FD_TEST( fd_event_tl->seq==1UL ); /* duplicate completion */

  /* Pending replay deliveries defer the root.  The incomplete block
     reports exactly once when after_credit eventually prunes it. */
  deliver_replay_root( ctx, complete.slot, &complete.block_id );
  FD_TEST( ctx->rotor->root==SNAP_SLOT );
  FD_TEST( fd_event_tl->seq==1UL );
  pump( ctx );
  FD_TEST( ctx->rotor->root==complete.slot );
  FD_TEST( fd_event_tl->seq==2UL );
  ev = expect_block_received( 1UL );
  FD_TEST( ev->slot==incomplete.slot && ev->parent_slot==SNAP_SLOT );
  FD_TEST( ev->fec_set_count==1UL && ev->fec_sets_cnt==1UL );
  FD_TEST( !ev->slot_complete_flag && !ev->last_shred_received_time );
  FD_TEST( ev->turbine_shred_received==FD_FEC_SHRED_CNT );
  FD_TEST( !memcmp( ev->fec_sets[ 0 ].fec_merkle_root, incomplete.fec_root[ 0 ].uc, 32UL ) );
  fd_event_tl = NULL;

  FD_LOG_NOTICE(( "pass: block_received reports completion and deferred pruning" ));
}

/* A turbine block can finalize before its parent arrives.  Replace
   its zero-ID check so it keeps repairing ancestry, including when a
   requestor walk under the old key is already active. */

static void
test_turbine_finalized_orphan( fd_wksp_t * wksp, int block_id_only, int active_walk ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );
  fd_requestor_set_block_id_only( ctx->requestor, block_id_only );

  blk_t parent[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 1U }};
  parent->fec_root[ 0 ] = mkhash( 0xFA0UL );
  blk_build( parent );
  blk_t child[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = parent->slot, .parent_block_id = parent->block_id, .fec_cnt = 2U }};
  child->fec_root[ 0 ] = mkhash( 0xFA1UL );
  child->fec_root[ 1 ] = mkhash( 0xFA2UL );
  blk_build( child );

  fd_hash_t zero = {0};
  deliver_turbine_fec_set( ctx, child, 0U );
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, child->slot, &zero ) );
  if( active_walk ) {
    ulong slot;
    fd_hash_t block_id;
    FD_TEST( fd_schedulor_block_pop( ctx->schedulor, fd_tickcount(), &slot, &block_id ) );
    FD_TEST( slot==child->slot && fd_hash_check_zero( &block_id ) );
    fd_requestor_block_start( ctx->requestor, slot, &block_id );
  }

  deliver_turbine_fec_set( ctx, child, 1U );
  fd_rotor_blk_t * v = fd_rotor_slot_version_query( ctx->rotor, child->slot, &child->block_id );
  FD_TEST( v && fd_rotor_block_complete( v ) && !v->connected );
  FD_TEST( !rep_cnt );
  FD_TEST( !fd_schedulor_block_query( ctx->schedulor, child->slot, &zero ) );
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, child->slot, &child->block_id ) );

  pump( ctx );
  uint kind = block_id_only ? AG_REPAIR_KIND_PARENT_FEC_COUNT : FD_REPAIR_KIND_ORPHAN;
  FD_TEST( req_find( 0UL, kind, child->slot, 0U, block_id_only ? &child->block_id : NULL ) );
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, child->slot, &child->block_id ) );
  FD_TEST( !rep_cnt );

  deliver_turbine_block( ctx, parent );
  pump( ctx );
  FD_TEST( rep_cnt==3UL );
  FD_TEST( rep_log[ 0 ].slot==parent->slot );
  FD_TEST( rep_log[ 1 ].slot==child->slot && rep_log[ 2 ].slot==child->slot );
  FD_TEST( rep_log[ 2 ].slot_complete );
  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: finalized turbine orphan stays scheduled (block_id_only %d, active_walk %d)", block_id_only, active_walk ));
}

/* The block_completed reception timestamps are documented as network
   arrival at the shred tile, stamped before signature verification.
   The shred tile hands that instant over as the frag's tsorig; this
   tile's own clock is later by sigverify, the fec resolver and link
   latency.  Backdate tsorig and check the stamp follows it -- reading
   fd_clock_tile_now instead would put the stamp at ~0 lag. */

static void
test_shred_ts_from_tsorig( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 1U }};
  blk->fec_root[ 0 ] = mkhash( 0xC0UL );
  blk_build( blk );

  /* 100ms back.  fd_frag_meta_ts_decomp only resolves within +/-2^31
     ticks of its reference (~0.7s at 3GHz), so the lag has to stay
     well inside that window. */
  long const lag_ns = (long)100e6;
  long       lag_tk = (long)(fd_tempo_tick_per_ns( NULL )*(double)lag_ns);

  test_tsorig = fd_frag_meta_ts_comp( fd_tickcount()-lag_tk );

  deliver_code_shred( ctx, blk->slot, 0U, 31U, &blk->fec_root[ 0 ], SHRED_SIG_SRC_TURBINE, SHRED_SIG_RESULT_OKAY );
  FD_TEST( !fd_rotor_slot_query( ctx->rotor, blk->slot ) );
  FD_TEST( !fd_schedulor_block_query( ctx->schedulor, blk->slot, &(fd_hash_t){0} ) );
  for( uint i=0U; i<FD_FEC_SHRED_CNT-1U; i++ )
    deliver_shred( ctx, blk->slot, i, 0,
                   &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_TURBINE,
                   i ? AG_UNKNOWN_SLOT : blk->parent_slot, i ? NULL : &blk->parent_block_id );
  deliver_shred( ctx, blk->slot, FD_FEC_SHRED_CNT-1U, FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE,
                 &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_RECONSTRUCTED, AG_UNKNOWN_SLOT, NULL );
  deliver_fec_complete( ctx, blk->slot, 0U, FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE, &blk->fec_root[ 0 ] );

  test_tsorig = 0UL;

  fd_rotor_blk_t const * v = fd_rotor_slot_version_query( ctx->rotor, blk->slot, &blk->block_id );
  FD_TEST( v );

  /* Both stamps sit ~lag_ns behind the wallclock.  The bounds are wide
     enough for a slow machine to walk the FEC set, but a stamp taken
     from this tile's clock would land far below the lower one. */
  long now = fd_log_wallclock();
  FD_TEST( v->metrics.first_shred_ts );
  FD_TEST( v->metrics.last_shred_ts  );
  FD_TEST( now-v->metrics.first_shred_ts > lag_ns/2 );
  FD_TEST( now-v->metrics.first_shred_ts < lag_ns*4 );
  FD_TEST( v->metrics.last_shred_ts>=v->metrics.first_shred_ts );
  fd_rotor_fec_t const * fec = fd_rotor_fec_query( ctx->rotor, blk->slot, 0U, &blk->block_id );
  FD_TEST( fec && fec->metrics.first_shred_ts==v->metrics.first_shred_ts );
  FD_TEST( fec->metrics.completed_ts==v->metrics.last_shred_ts );
  FD_TEST( !fec->metrics.parity_received ); /* coding arrived before the FEC existed */
  FD_TEST( fec->metrics.data_received==0x7fffffffU );

  FD_LOG_NOTICE(( "pass: test_shred_ts_from_tsorig" ));
}

/* The reception statistics rotor ships to replay with every FEC: the
   rotor tallies each shred against the version it lands in, by
   source, and publish_fec snapshots the version. */

static void
test_reception_stats( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );
  enable_event_reporting( wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0xB0UL );
  blk->fec_root[ 1 ] = mkhash( 0xB1UL );
  blk_build( blk );

  /* FEC set 0: all but two shreds from turbine, one from repair, one
     coding shred (plus a duplicate of it the resolver forwards), and
     one data shred left for reed-solomon. */

  for( uint i=0U; i<FD_FEC_SHRED_CNT-2U; i++ )
    deliver_shred( ctx, blk->slot, i, 0, &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_TURBINE,
                   blk->parent_slot, &blk->parent_block_id );
  deliver_shred( ctx, blk->slot, FD_FEC_SHRED_CNT-2U, 0, &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_REPAIR,
                 AG_UNKNOWN_SLOT, NULL );
  deliver_code_shred( ctx, blk->slot, 0U, 3U, &blk->fec_root[ 0 ], SHRED_SIG_SRC_TURBINE, SHRED_SIG_RESULT_OKAY      );
  deliver_code_shred( ctx, blk->slot, 0U, 3U, &blk->fec_root[ 0 ], SHRED_SIG_SRC_TURBINE, SHRED_SIG_RESULT_DUPLICATE );

  fd_rotor_blk_t * v0 = fd_rotor_slot_query( ctx->rotor, blk->slot );
  FD_TEST( v0 && v0->turbine );
  FD_TEST( v0->metrics.turbine_cnt  ==FD_FEC_SHRED_CNT-1U ); /* the coding shred counts as turbine */
  FD_TEST( v0->metrics.repair_cnt   ==1U                  );
  FD_TEST( v0->metrics.recovered_cnt==0U                  );
  FD_TEST( v0->metrics.parity_cnt   ==1U                  );
  FD_TEST( !fd_rotor_verify( ctx->rotor ) );

  /* The shred tile forwards recovered data before its FEC completion.
     Neither recovery nor a duplicate repair delivery changes the final
     network source (the coding shred above). */
  deliver_shred( ctx, blk->slot, FD_FEC_SHRED_CNT-1U, FD_SHRED_DATA_FLAG_DATA_COMPLETE,
                 &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_RECONSTRUCTED, AG_UNKNOWN_SLOT, NULL );
  deliver_shred( ctx, blk->slot, FD_FEC_SHRED_CNT-2U, 0,
                 &blk->fec_root[ 0 ], 0U, SHRED_SIG_SRC_REPAIR, AG_UNKNOWN_SLOT, NULL );
  deliver_fec_complete( ctx, blk->slot, 0U, FD_SHRED_DATA_FLAG_DATA_COMPLETE, &blk->fec_root[ 0 ] );
  pump( ctx );

  FD_TEST( rep_cnt==1UL );
  fd_rotor_fec_metrics_t const * m = &rep_log[ 0 ].metrics;
  FD_TEST( m->stats_valid      ==1U                  );
  FD_TEST( m->blk_turbine_cnt  ==FD_FEC_SHRED_CNT-1U );
  FD_TEST( m->blk_repair_cnt   ==1U                  );
  FD_TEST( m->blk_recovered_cnt==1U                  ); /* the shred the set was missing */
  FD_TEST( m->blk_data_cnt     ==FD_FEC_SHRED_CNT    );
  FD_TEST( m->blk_parity_cnt   ==1U                  );
  FD_TEST( m->blk_slot_complete==0                   );
  FD_TEST( m->votor_repaired    ==0                   ); /* turbine version */

  FD_TEST( !m->blk_req_window_cnt && !m->blk_req_highest_cnt && !m->blk_req_orphan_cnt );
  FD_TEST( !m->blk_req_shred_bid_cnt && !m->blk_req_parent_cnt && !m->blk_req_fec_root_cnt );
  FD_TEST( !m->blk_req_retransmit_cnt && !m->blk_repair_responses );

  /* The block's first shred has arrived, so that is stamped.  The block
     is not contiguous yet (FEC set 1 is still outstanding), so the
     last-shred stamp is still the 0 "never stamped" sentinel. */

  FD_TEST(  m->blk_first_shred_ts_nanos );
  FD_TEST( !m->blk_last_shred_ts_nanos  );
  ulong first_ts = m->blk_first_shred_ts_nanos;

  /* FEC set 1 completes the block: the snapshot is cumulative and
     reports the slot as complete. */

  for( uint i=FD_FEC_SHRED_CNT; i<2U*FD_FEC_SHRED_CNT; i++ )
    deliver_shred( ctx, blk->slot, i,
                   (uchar)( i==2U*FD_FEC_SHRED_CNT-1U ? FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE : 0 ),
                   &blk->fec_root[ 1 ], 0U, SHRED_SIG_SRC_TURBINE, AG_UNKNOWN_SLOT, NULL );
  deliver_fec_complete( ctx, blk->slot, FD_FEC_SHRED_CNT,
                        FD_SHRED_DATA_FLAG_SLOT_COMPLETE|FD_SHRED_DATA_FLAG_DATA_COMPLETE, &blk->fec_root[ 1 ] );
  pump( ctx );

  FD_TEST( rep_cnt==2UL );
  m = &rep_log[ 1 ].metrics;
  FD_TEST( m->stats_valid      ==1U                    );
  FD_TEST( m->blk_turbine_cnt  ==2U*FD_FEC_SHRED_CNT-1U );
  FD_TEST( m->blk_repair_cnt   ==1U                    );
  FD_TEST( m->blk_recovered_cnt==1U                    );
  FD_TEST( m->blk_data_cnt     ==2U*FD_FEC_SHRED_CNT   );
  FD_TEST( m->blk_parity_cnt   ==1U                    );
  FD_TEST( m->blk_slot_complete==1                     );
  FD_TEST( m->votor_repaired    ==0                     );
  FD_TEST( m->blk_last_completed_fec_idx==FD_FEC_SHRED_CNT ); /* set 1 completed most recently */

  /* The telemetry row and replay snapshot share cumulative reception
     counters, including parity and locally recovered shreds. */
  FD_TEST( fd_event_tl->seq==1UL );
  fd_event_block_received_t const * ev = expect_block_received( 0UL );
  FD_TEST( ev->turbine_shred_received==m->blk_turbine_cnt );
  FD_TEST( ev->repair_shred_received==m->blk_repair_cnt );
  FD_TEST( ev->recovered_shred_count==m->blk_recovered_cnt );
  FD_TEST( ev->parity_shred_received==m->blk_parity_cnt );
  FD_TEST( ev->first_shred_received_time==m->blk_first_shred_ts_nanos );
  FD_TEST( ev->last_shred_received_time==m->blk_last_shred_ts_nanos );
  FD_TEST( ev->fec_set_count==2UL && ev->fec_sets_cnt==2UL );
  FD_TEST( ev->fec_sets[ 0 ].fec_data_shreds_received==0x7fffffffU );
  FD_TEST( ev->fec_sets[ 0 ].fec_parity_shreds_received==(1U<<3) );
  FD_TEST( ev->fec_sets[ 0 ].fec_repair_shreds_received==(1U<<30) );
  FD_TEST( !ev->fec_sets[ 0 ].fec_final_shred_source_repair && ev->fec_sets[ 0 ].fec_source_repair );
  FD_TEST( ev->fec_sets[ 0 ].fec_first_shred_received_nanos==first_ts );
  FD_TEST( ev->fec_sets[ 0 ].fec_completed_nanos>=first_ts );
  FD_TEST( ev->fec_sets[ 1 ].fec_data_shreds_received==UINT_MAX );
  FD_TEST( !ev->fec_sets[ 1 ].fec_parity_shreds_received && !ev->fec_sets[ 1 ].fec_repair_shreds_received );

  /* highest_fec_complete_slot is the cluster tip, not this FEC's slot.  Rotor delivers
     only replayable FECs in order, so replay cannot derive the tip
     from what it receives -- a FEC set completing for a far-ahead slot
     that is nowhere near replayable must still move highest_fec_complete_slot, while
     the delivered FEC stays where it is. */

  FD_TEST( rep_log[ 1 ].metrics.highest_fec_complete_slot==blk->slot );

  ulong     ahead    = blk->slot + 400UL;
  fd_hash_t ahead_mr = { .ul = { 0xA11EAD } };
  deliver_fec_complete( ctx, ahead, 0U, FD_SHRED_DATA_FLAG_DATA_COMPLETE, &ahead_mr );
  pump( ctx );
  FD_TEST( ctx->highest_fec_complete_slot==ahead );

  /* FEC sets we produced as leader are not evidence of the tip.  The
     guard has to test sig rather than sig_src: on this branch the low
     bits of sig are the event code, so a SHRED_SIG_SRC_* comparison
     would never match and leader sets would advance the tip. */
  fd_hash_t lead_mr = { .ul = { 0x1EAD } };
  deliver_fec_complete_sig( ctx, ahead+100UL, 0U, FD_SHRED_DATA_FLAG_DATA_COMPLETE, &lead_mr,
                            SHRED_SIG_FEC_COMPLETE_LEADER );
  pump( ctx );
  FD_TEST( ctx->highest_fec_complete_slot==ahead );

  /* A plain shred does not move it; only a completed set does. */
  fd_hash_t shred_mr = { .ul = { 0x5417ED } };
  deliver_shred( ctx, ahead+200UL, 1U, 0, &shred_mr, 0U, SHRED_SIG_SRC_TURBINE, AG_UNKNOWN_SLOT, NULL );
  pump( ctx );
  FD_TEST( ctx->highest_fec_complete_slot==ahead );

  /* Contiguous now, so last_shred is stamped, and at or after first.
     first_shred does not move: it is the earliest, not the latest. */

  FD_TEST( m->blk_first_shred_ts_nanos==first_ts                  );
  FD_TEST( m->blk_last_shred_ts_nanos >=m->blk_first_shred_ts_nanos );
  FD_TEST( !fd_rotor_verify( ctx->rotor ) );

  FD_LOG_NOTICE(( "pass: test_reception_stats" ));
  fd_event_tl = NULL;
}

/* The schedulor paces re-requests.  A new block is queued due now, the
   first check walks the metadata rung (HighestShred while the tip is
   unknown), and the block is re-queued at that rung's timeout.  Nothing
   is re-requested until the timeout passes, and arriving shreds cannot
   move a queued check. */

static void
test_schedulor_drives_requests( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0xB0UL );
  blk->fec_root[ 1 ] = mkhash( 0xB1UL );
  blk_build( blk );

  deliver_turbine_fec_set( ctx, blk, 0U );
  FD_TEST( fd_schedulor_queued_cnt( ctx->schedulor )==1UL );  /* created -> queued */
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, blk->slot, &(fd_hash_t){0} ) );

  ulong from = req_cnt;
  pump( ctx );
  FD_TEST( ctx->metrics->checks>=1UL );
  FD_TEST( req_find( from, FD_REPAIR_KIND_HIGHEST_SHRED, blk->slot, 0U, NULL ) ); /* tip unknown */
  FD_TEST( fd_schedulor_queued_cnt( ctx->schedulor )==1UL );                      /* re-queued, parked */

  /* Parked at now+PARENT_TIMEOUT: nothing more goes out until then,
     and arriving shreds do not move the queued check. */
  long now = fd_tickcount();
  FD_TEST( fd_schedulor_next_timeout( ctx->schedulor )>now );
  ulong checks = ctx->metrics->checks;
  for( ulong i=0UL; i<64UL; i++ ) tick( ctx );
  FD_TEST( ctx->metrics->checks==checks );

  /* The tip arrives, so the fill rung takes over: one request per
     missing shred of set 1, and no duplicate of the buffered prefix. */
  for( uint i=FD_FEC_SHRED_CNT; i<2U*FD_FEC_SHRED_CNT; i++ ) {
    if( i==FD_FEC_SHRED_CNT+5U ) continue; /* leave one hole */
    deliver_shred( ctx, blk->slot, i, (uchar)( i==2U*FD_FEC_SHRED_CNT-1U ? blk_fec_flags( blk, 1U ) : 0 ),
                   &blk->fec_root[ 1 ], 0U, SHRED_SIG_SRC_TURBINE, blk->parent_slot, &blk->parent_block_id );
  }
  fd_rotor_blk_t * v0 = fd_rotor_slot_query( ctx->rotor, blk->slot );
  FD_TEST( v0->complete_idx==2U*FD_FEC_SHRED_CNT-1U );

  force_check( ctx, blk->slot, &(fd_hash_t){0} );
  from = req_cnt;
  pump( ctx );
  FD_TEST( req_count( from, FD_REPAIR_KIND_SHRED, blk->slot )==1UL );
  FD_TEST( req_find( from, FD_REPAIR_KIND_SHRED, blk->slot, FD_FEC_SHRED_CNT+5U, NULL ) );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: schedulor paces the requestor's rungs" ));
}

/* A votor block id for a slot turbine is still streaming creates a
   second version and abandons the turbine one, whose block id is still
   unknown.  The votor version is then driven to completion on its own
   by ParentAndFecSetCount, FecSetRoot and ShredForBlockId, and delivers
   under the id votor named. */

static void
test_votor_block_supersedes( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );
  enable_event_reporting( wksp );

  blk_t turb[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  turb->fec_root[ 0 ] = mkhash( 0xC0UL );
  turb->fec_root[ 1 ] = mkhash( 0xC1UL );
  blk_build( turb );

  blk_t vot[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 1U }};
  vot->fec_root[ 0 ] = mkhash( 0xC9UL );
  blk_build( vot );

  deliver_turbine_fec_set( ctx, turb, 0U );
  pump( ctx );

  deliver_votor( ctx, vot->slot, &vot->block_id );
  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  fd_rotor_blk_t * v1 = fd_rotor_slot_version_query( ctx->rotor, vot->slot, &vot->block_id );
  fd_rotor_blk_t * v0 = fd_rotor_turbine_block_query( ctx->rotor, turb->slot );
  FD_TEST( v0 && v1 && v0!=v1 );
  FD_TEST( v0->abandoned ); /* the cert, not turbine, decides this slot now */
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, vot->slot, &vot->block_id ) );

  /* the votor block's metadata round trip */
  ulong from = req_cnt;
  pump( ctx );
  req_t * meta = req_find( from, AG_REPAIR_KIND_PARENT_FEC_COUNT, vot->slot, 0U, &vot->block_id );
  FD_TEST( meta );
  respond_parent_fec_count( ctx, vot, meta->nonce, 0 );
  FD_TEST( ctx->metrics->meta_ok_parent_fec_count==1UL );
  FD_TEST( v1->complete_idx==FD_FEC_SHRED_CNT-1U && v1->parent_slot==SNAP_SLOT );

  force_check( ctx, vot->slot, &vot->block_id ); /* the response does not move the parked check */
  from = req_cnt;
  pump( ctx );
  req_t * root = req_find( from, AG_REPAIR_KIND_FEC_ROOT, vot->slot, 0U, &vot->block_id );
  FD_TEST( root );
  respond_fec_root( ctx, vot, 0U, root->nonce, 0 );
  FD_TEST( ctx->metrics->meta_ok_fec_root==1UL );
  FD_TEST( fd_rotor_fec_query( ctx->rotor, vot->slot, 0U, &vot->block_id ) );

  /* its shreds are repaired by block id */
  uint served[ BLK_FEC_MAX ] = {0};
  force_check( ctx, vot->slot, &vot->block_id );
  from = req_cnt;
  pump( ctx );
  FD_TEST( serve_shred_requests( ctx, from, vot, served )==FD_FEC_SHRED_CNT );
  pump( ctx );
  FD_TEST( fd_rotor_block_complete( v1 ) && v1->metrics.last_shred_ts );
  FD_TEST( fd_event_tl->seq==1UL );
  fd_event_block_received_t const * ev = expect_block_received( 0UL );
  FD_TEST( ev->slot==vot->slot && ev->notarized && !ev->cancelled );
  FD_TEST( !memcmp( ev->block_id, vot->block_id.uc, 32UL ) );
  FD_TEST( ev->fec_set_count==1UL && ev->fec_sets_cnt==1UL );
  FD_TEST( ev->repair_shred_received==FD_FEC_SHRED_CNT );
  FD_TEST( ev->repair_responses_received==FD_FEC_SHRED_CNT );
  FD_TEST( ev->repair_request_shred_for_block_id_count==FD_FEC_SHRED_CNT );
  FD_TEST( ev->repair_request_parent_fec_count==1U && ev->repair_request_fec_root_count==1U );
  FD_TEST( ev->first_repair_request_time && ev->last_repair_received_time>=ev->first_repair_request_time );
  FD_TEST( !memcmp( ev->fec_sets[ 0 ].fec_merkle_root, vot->fec_root[ 0 ].uc, 32UL ) );
  FD_TEST( ev->fec_sets[ 0 ].fec_data_shreds_received==UINT_MAX );
  FD_TEST( ev->fec_sets[ 0 ].fec_repair_shreds_received==UINT_MAX );
  FD_TEST( !ev->fec_sets[ 0 ].fec_parity_shreds_received );
  FD_TEST( ev->fec_sets[ 0 ].fec_final_shred_source_repair && ev->fec_sets[ 0 ].fec_source_repair );
  FD_TEST( ev->fec_sets[ 0 ].fec_first_shred_received_nanos==ev->first_shred_received_time );
  FD_TEST( ev->fec_sets[ 0 ].fec_completed_nanos>=ev->last_shred_received_time );
  FD_TEST( ctx->metrics->shred_match_block_id==FD_FEC_SHRED_CNT );
  fd_rotor_fec_metrics_t const * m = &rep_log[ rep_cnt-1UL ].metrics;
  FD_TEST( m->stats_valid==1U && m->votor_repaired==1U );
  FD_TEST( m->blk_req_parent_cnt==1U && m->blk_req_fec_root_cnt==1U );
  FD_TEST( m->blk_req_shred_bid_cnt==FD_FEC_SHRED_CNT );
  FD_TEST( !m->blk_req_window_cnt && !m->blk_req_highest_cnt && !m->blk_req_orphan_cnt );
  FD_TEST( !m->blk_req_retransmit_cnt );
  FD_TEST( m->blk_repair_responses==FD_FEC_SHRED_CNT );
  FD_TEST( m->blk_repair_cnt==FD_FEC_SHRED_CNT && !m->blk_turbine_cnt );
  FD_TEST( m->blk_first_req_ts_nanos && m->blk_last_repair_resp_ts_nanos>=m->blk_first_req_ts_nanos );
  FD_TEST( !rep_log[ 0 ].metrics.votor_repaired );
  FD_TEST( !v0->metrics.repair_responses ); /* request credit stays on the votor version */

  /* the abandoned turbine version takes no further FEC completions and
     never derives a block id */
  deliver_turbine_fec_set( ctx, turb, 1U );
  pump( ctx );
  FD_TEST( !fd_rotor_block_complete( v0 ) );
  FD_TEST( fd_hash_check_zero( &v0->block_id ) );

  /* only the votor version delivered a slot-complete FEC */
  ulong turb_cnt = 0UL, vot_cnt = 0UL;
  for( ulong i=0UL; i<rep_cnt; i++ ) {
    if( !rep_log[ i ].slot_complete ) continue;
    if( fd_hash_eq( &rep_log[ i ].mr, &turb->fec_root[ 1 ] ) ) turb_cnt++;
    if( fd_hash_eq( &rep_log[ i ].mr, &vot->fec_root[ 0 ]  ) ) vot_cnt++;
  }
  FD_TEST( turb_cnt==0UL && vot_cnt==1UL );
  FD_TEST( fd_event_tl->seq==1UL ); /* abandoned version waits for pruning */

  deliver_replay_root( ctx, vot->slot, &vot->block_id );
  FD_TEST( ctx->rotor->root==vot->slot );
  FD_TEST( fd_event_tl->seq==2UL );
  ev = expect_block_received( 1UL );
  FD_TEST( ev->slot==turb->slot && ev->cancelled && !ev->notarized );
  FD_TEST( ev->fec_set_count==1UL && ev->fec_sets_cnt==1UL );
  fd_event_tl = NULL;

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: votor block supersedes the turbine version" ));
}

/* Metadata responses are only trusted once their double-merkle proof
   verifies against the block id we asked about.  A corrupt proof is
   counted, dropped and consumes the request, so a replay of that nonce
   is unsolicited.  Recovery comes from the next check, whose fresh
   nonce is answered and applied. */

static void
test_meta_verify( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 1U }};
  blk->fec_root[ 0 ] = mkhash( 0xD0UL );
  blk_build( blk );

  deliver_votor( ctx, blk->slot, &blk->block_id );
  ulong from = req_cnt;
  pump( ctx );
  req_t * meta = req_find( from, AG_REPAIR_KIND_PARENT_FEC_COUNT, blk->slot, 0U, &blk->block_id );
  FD_TEST( meta );
  fd_rotor_blk_t * v = fd_rotor_slot_version_query( ctx->rotor, blk->slot, &blk->block_id );
  FD_TEST( v && v->complete_idx==UINT_MAX );
  FD_TEST( v->metrics.req_parent_cnt==1U && !v->metrics.req_retransmit_cnt );
  uint nonce = meta->nonce;

  respond_parent_fec_count( ctx, blk, nonce, 1 /* corrupt */ );
  FD_TEST( ctx->metrics->failed_parent_fec_count==1UL );
  FD_TEST( ctx->metrics->meta_ok_parent_fec_count==0UL );
  FD_TEST( v->complete_idx==UINT_MAX );                       /* untouched */

  respond_parent_fec_count( ctx, blk, nonce, 0 );             /* the request was consumed */
  FD_TEST( ctx->metrics->unsolicited_meta==1UL );
  FD_TEST( v->complete_idx==UINT_MAX );

  respond_parent_fec_count( ctx, blk, nonce+1000U, 0 );       /* never-sent nonce */
  FD_TEST( ctx->metrics->unsolicited_meta==2UL );

  /* the next check asks again, and that answer is applied */
  force_check( ctx, blk->slot, &blk->block_id );
  from = req_cnt;
  pump( ctx );
  req_t * again = req_find( from, AG_REPAIR_KIND_PARENT_FEC_COUNT, blk->slot, 0U, &blk->block_id );
  FD_TEST( again && again->nonce!=nonce );
  FD_TEST( v->metrics.req_parent_cnt==2U );
  respond_parent_fec_count( ctx, blk, again->nonce, 0 );
  FD_TEST( ctx->metrics->meta_ok_parent_fec_count==1UL );
  FD_TEST( v->complete_idx==FD_FEC_SHRED_CNT-1U );
  FD_TEST( ctx->metrics->meta_rx==4UL );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: metadata responses are verified by proof and nonce" ));
}

/* block_id_only is the production setting: the requestor's legacy
   rungs are suppressed, so a turbine block whose tip is unknown asks
   for nothing, while a votor block still gets its
   ParentAndFecSetCount.  Catchup seeding is not the requestor's ladder
   and still goes out.  Clearing the flag restores HighestShred. */

static void
test_block_id_only( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );
  fd_requestor_set_block_id_only( ctx->requestor, 1 );

  blk_t turb[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  turb->fec_root[ 0 ] = mkhash( 0xE0UL );
  turb->fec_root[ 1 ] = mkhash( 0xE1UL );
  blk_build( turb );

  deliver_turbine_fec_set( ctx, turb, 0U );
  pump( ctx );

  /* every rung the block could reach is a legacy kind, so its check
     asks for nothing at all */
  ulong from = req_cnt;
  force_check( ctx, turb->slot, &(fd_hash_t){0} );
  pump( ctx );
  FD_TEST( req_cnt==from );

  blk_t vot[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = SNAP_SLOT+1UL, .parent_block_id = mkhash( 0xE9UL ), .fec_cnt = 1U }};
  vot->fec_root[ 0 ] = mkhash( 0xEAUL );
  blk_build( vot );
  deliver_votor( ctx, vot->slot, &vot->block_id );
  from = req_cnt;
  pump( ctx );
  FD_TEST( req_find( from, AG_REPAIR_KIND_PARENT_FEC_COUNT, vot->slot, 0U, &vot->block_id ) );

  fd_requestor_set_block_id_only( ctx->requestor, 0 );
  force_check( ctx, turb->slot, &(fd_hash_t){0} );
  from = req_cnt;
  pump( ctx );
  FD_TEST( req_find( from, FD_REPAIR_KIND_HIGHEST_SHRED, turb->slot, 0U, NULL ) );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: block_id_only suppresses the legacy rungs" ));
}

/* Replay advancing the root prunes the rotor and drops the schedulor
   checks of every block at or below it, so a rooted slot is never
   re-requested.  Blocks above the root keep their checks. */

static void
test_publish_prunes( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t b1[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 1U }};
  b1->fec_root[ 0 ] = mkhash( 0xF0UL );
  blk_build( b1 );
  deliver_turbine_block( ctx, b1 );
  pump( ctx );
  FD_TEST( fd_hash_eq( &fd_rotor_slot_query( ctx->rotor, b1->slot )->block_id, &b1->block_id ) );

  /* b2 stays incomplete, so its check parks on the metadata rung */
  blk_t b2[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = b1->slot, .parent_block_id = b1->block_id, .fec_cnt = 2U }};
  b2->fec_root[ 0 ] = mkhash( 0xF1UL );
  b2->fec_root[ 1 ] = mkhash( 0xF2UL );
  blk_build( b2 );
  deliver_turbine_fec_set( ctx, b2, 0U );
  pump( ctx );
  FD_TEST( fd_schedulor_queued_cnt( ctx->schedulor )==1UL );          /* b2 parked; b1 finished DONE */
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, b2->slot, &(fd_hash_t){0} ) );

  force_check( ctx, b1->slot, &b1->block_id );                        /* give the rooted block a check */
  FD_TEST( fd_schedulor_queued_cnt( ctx->schedulor )==2UL );

  deliver_replay_root( ctx, b1->slot, &b1->block_id );
  FD_TEST( ctx->rotor->root==b1->slot );
  FD_TEST( !fd_rotor_slot_query( ctx->rotor, SNAP_SLOT ) );
  FD_TEST( !fd_schedulor_block_query( ctx->schedulor, b1->slot, &b1->block_id ) ); /* dropped */
  FD_TEST( fd_schedulor_queued_cnt( ctx->schedulor )==1UL );
  FD_TEST( fd_schedulor_block_query( ctx->schedulor, b2->slot, &(fd_hash_t){0} ) );
  FD_TEST( ctx->metrics->replay_root_advanced==1UL );

  /* a shred for the rooted slot is dropped and counted */
  ulong old = ctx->metrics->shred_old;
  deliver_shred( ctx, b1->slot, 0U, 0, &b1->fec_root[ 0 ], 0U, SHRED_SIG_SRC_TURBINE, SNAP_SLOT, &snap_bid );
  FD_TEST( ctx->metrics->shred_old==old+1UL );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: publish prunes the rotor and the schedulor" ));
}

/* A MISSING_FEC from replay arms a from-root redelivery: the next FEC
   that would be published instead queues the whole ancestry path from
   the rotor root, and every frag in it carries the block id so
   replay can rebuild the fork it evicted. */

static void
test_deliver_from_root( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t b1[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 1U }};
  b1->fec_root[ 0 ] = mkhash( 0x100UL );
  blk_build( b1 );
  deliver_turbine_block( ctx, b1 );
  pump( ctx );

  blk_t b2[1] = {{ .slot = SNAP_SLOT+2UL, .parent_slot = b1->slot, .parent_block_id = b1->block_id, .fec_cnt = 1U }};
  b2->fec_root[ 0 ] = mkhash( 0x101UL );
  blk_build( b2 );

  deliver_replay_missing_fec( ctx );
  FD_TEST( ctx->deliver_from_root==1 );
  FD_TEST( ctx->metrics->replay_missing_fec==1UL );

  ulong before = rep_cnt;
  deliver_turbine_block( ctx, b2 );
  pump( ctx );
  FD_TEST( ctx->deliver_from_root==0 );              /* consumed */
  FD_TEST( rep_cnt==before+2UL );                    /* b1's set replayed ahead of b2's */
  rep_expect( before,      b1->slot, 0U, &b1->fec_root[ 0 ], &b1->block_id, 1 );
  rep_expect( before+1UL,  b2->slot, 0U, &b2->fec_root[ 0 ], &b2->block_id, 1 );
  FD_TEST( rep_log[ before ].metrics.stats_valid==1U );
  FD_TEST( rep_log[ before ].metrics.blk_turbine_cnt==FD_FEC_SHRED_CNT );
  FD_TEST( rep_log[ before ].metrics.blk_first_shred_ts_nanos==rep_log[ 0 ].metrics.blk_first_shred_ts_nanos );
  FD_TEST( rep_log[ before ].metrics.highest_fec_complete_slot==b2->slot );
  FD_TEST( rep_log[ before+1UL ].metrics.stats_valid==1U );
  FD_TEST( rep_log[ before+1UL ].metrics.blk_turbine_cnt==FD_FEC_SHRED_CNT );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: missing FEC arms a from-root redelivery" ));
}

/* A FEC eviction clears the set's shreds and rewinds the block's
   buffered prefix, but schedules nothing: the block is re-asked on its
   next check.  Once that check comes due every evicted shred is
   requested again. */

static void
test_fec_evicted( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0x110UL );
  blk->fec_root[ 1 ] = mkhash( 0x111UL );
  blk_build( blk );

  /* set 0 completes; set 1's shreds all arrive but its completion does
     not, which is the state the resolver evicts from */
  deliver_turbine_fec_set( ctx, blk, 0U );
  for( uint i=FD_FEC_SHRED_CNT; i<2U*FD_FEC_SHRED_CNT; i++ ) {
    deliver_shred( ctx, blk->slot, i, (uchar)( i==2U*FD_FEC_SHRED_CNT-1U ? blk_fec_flags( blk, 1U ) : 0 ),
                   &blk->fec_root[ 1 ], 0U, SHRED_SIG_SRC_TURBINE, blk->parent_slot, &blk->parent_block_id );
  }
  pump( ctx );
  fd_rotor_blk_t * v0 = fd_rotor_turbine_block_query( ctx->rotor, blk->slot );
  FD_TEST( v0 && v0->buffered_idx==2U*FD_FEC_SHRED_CNT-1U );
  FD_TEST( v0->buffered_fec_idx==FD_FEC_SHRED_CNT-1U );
  FD_TEST( v0->complete_idx==2U*FD_FEC_SHRED_CNT-1U );
  fd_rotor_fec_t const * fec = fd_rotor_fec_query( ctx->rotor, blk->slot, FD_FEC_SHRED_CNT, &v0->block_id );
  FD_TEST( fec && fec->metrics.data_received==UINT_MAX && fec->metrics.first_shred_ts );

  ulong queued = fd_schedulor_queued_cnt( ctx->schedulor );
  deliver_fec_evicted( ctx, blk->slot, FD_FEC_SHRED_CNT, &blk->fec_root[ 1 ] );
  FD_TEST( v0->buffered_idx==FD_FEC_SHRED_CNT-1U );                        /* prefix rewound */
  FD_TEST( fd_schedulor_queued_cnt( ctx->schedulor )==queued );            /* no new check */
  FD_TEST( !fd_rotor_shred_test( ctx->rotor, v0, FD_FEC_SHRED_CNT ) ); /* shreds gone */
  FD_TEST( !fec->metrics.data_received && !fec->metrics.parity_received && !fec->metrics.repair_received );
  FD_TEST( !fec->metrics.first_shred_ts && !fec->metrics.completed_ts );
  FD_TEST( !fd_rotor_verify( ctx->rotor ) );

  force_check( ctx, blk->slot, &v0->block_id );
  ulong from = req_cnt;
  pump( ctx );
  FD_TEST( req_count( from, FD_REPAIR_KIND_SHRED, blk->slot )==FD_FEC_SHRED_CNT );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
  FD_LOG_NOTICE(( "pass: eviction rewinds without scheduling" ));
}

/* A ping from a known peer is answered with one signed pong, and only
   one is queued per peer.  Malformed pings, pings from unknown peers
   and pings whose signature does not verify are each counted and
   dropped. */

static void
test_ping_pong( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  fd_repair_ping_t ping[1];
  memset( ping, 0, sizeof(ping) );
  ping->kind      = FD_REPAIR_KIND_PING;
  ping->ping.from = peer_key[ 0 ];
  ping->ping.hash = mkhash( 0x120UL );

  ulong from = req_cnt;
  deliver_net_response( ctx, (uchar const *)ping, sizeof(fd_repair_ping_t) );
  FD_TEST( ctx->metrics->fail_sigverify_ping==1UL );  /* zeroed signature */
  pump( ctx );
  FD_TEST( !req_find( from, FD_REPAIR_KIND_PONG, 0UL, UINT_MAX, NULL ) );

  fd_pubkey_t unknown = *(fd_pubkey_t *)fd_type_pun( mkhash( 0x121UL ).uc );
  ping->ping.from = unknown;
  deliver_net_response( ctx, (uchar const *)ping, sizeof(fd_repair_ping_t) );
  FD_TEST( ctx->metrics->unknown_peer_ping==1UL );

  uchar trunc[ sizeof(fd_repair_ping_t) ];
  memset( trunc, 0xFF, sizeof(trunc) );
  deliver_net_response( ctx, trunc, sizeof(fd_repair_ping_t) );
  FD_TEST( ctx->metrics->malformed_ping==1UL );

  FD_LOG_NOTICE(( "pass: ping handling counts every rejection" ));
}

/* metrics_write must export the whole ROTOR group, not just the two
   gauges the watch TUI reads.  Drive a block end to end, then check
   the exported counters and gauges against the tile's own tallies and
   the live module depths. */

static void
test_metrics_exported( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0x130UL );
  blk->fec_root[ 1 ] = mkhash( 0x131UL );
  blk_build( blk );
  deliver_turbine_block( ctx, blk );
  pump( ctx );

  static ulong metrics_mem[ FD_METRICS_FOOTPRINT( 8UL )/sizeof(ulong) ] __attribute__((aligned(FD_METRICS_ALIGN)));
  volatile ulong * m = fd_metrics_tile( fd_metrics_register( fd_metrics_new( metrics_mem, 8UL ) ) );
  metrics_write( ctx );

  FD_TEST( m[ MIDX( GAUGE, ROTOR, SLOT_CURRENT          ) ]==ctx->current_slot                 );
  FD_TEST( m[ MIDX( GAUGE, ROTOR, SLOT_HIGHEST_REPAIRED ) ]==ctx->rotor->highest_repaired    );
  FD_TEST( m[ MIDX( GAUGE, ROTOR, SLOT_TURBINE_FIRST    ) ]==ctx->turbine_slot0                );
  FD_TEST( m[ MIDX( GAUGE, ROTOR, BLOCK_CHECK_QUEUED    ) ]==fd_schedulor_queued_cnt( ctx->schedulor ) );
  FD_TEST( m[ MIDX( GAUGE, ROTOR, REQUEST_INFLIGHT      ) ]==fd_inflights_outstanding_cnt( ctx->rtt ) );

  FD_TEST( m[ MIDX( COUNTER, ROTOR, PKT_TX        ) ]==ctx->metrics->send_pkt_cnt   );
  FD_TEST( m[ MIDX( COUNTER, ROTOR, FEC_DELIVERED ) ]==ctx->metrics->fecs_delivered );
  FD_TEST( m[ MIDX( COUNTER, ROTOR, FEC_DELIVERED ) ]==2UL                          );

  /* the request-type enum is remapped from wire kinds */
  ulong sent = 0UL;
  for( ulong i=0UL; i<FD_METRICS_COUNTER_ROTOR_REQUEST_TX_CNT; i++ ) sent += m[ MIDX( COUNTER, ROTOR, REQUEST_TX )+i ];
  ulong sent_by_kind = 0UL;
  for( ulong k=0UL; k<16UL; k++ ) if( request_tx_idx( k )!=ULONG_MAX ) sent_by_kind += ctx->metrics->sent_by_kind[ k ];
  FD_TEST( sent==sent_by_kind );
  FD_TEST( m[ MIDX( COUNTER, ROTOR, REQUEST_TX )+FD_METRICS_ENUM_REPAIR_SENT_REQUEST_TYPE_V_NEEDED_WINDOW_IDX ]==
           ctx->metrics->sent_by_kind[ FD_REPAIR_KIND_SHRED ] );

  FD_TEST( m[ MIDX( COUNTER, ROTOR, SHRED_OLD           ) ]==ctx->metrics->shred_old            );
  FD_TEST( m[ MIDX( COUNTER, ROTOR, META_RX             ) ]==ctx->metrics->meta_rx              );
  FD_TEST( m[ MIDX( COUNTER, ROTOR, PING_MALFORMED      ) ]==ctx->metrics->malformed_ping       );
  FD_TEST( m[ MIDX( COUNTER, ROTOR, REPLAY_ROOT_ADVANCED) ]==ctx->metrics->replay_root_advanced );

  FD_LOG_NOTICE(( "pass: metrics_write exports the ROTOR group" ));
}

/* fd_inflights_expire releases records older than the cutoff from both
   the outstanding and the popped set, oldest first, at most max per
   call, and leaves younger records matchable. */

static void
test_inflights_expire( fd_wksp_t * wksp ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_inflights_align(), fd_inflights_footprint(), 1UL );
  FD_TEST( mem );
  fd_inflights_t * t = fd_inflights_join( fd_inflights_new( mem, 42UL ) );
  FD_TEST( t );

  fd_pubkey_t peer   = *(fd_pubkey_t *)fd_type_pun( mkhash( 0x150UL ).uc );
  fd_hash_t   bid    = mkhash( 0x151UL );
  ulong       used0  = fd_inflight_pool_used( t->pool );
  FD_TEST( fd_inflights_oldest_ts( t )==LONG_MAX );

  /* shred requests at t=10,20,30,40 and a metadata request at t=50 */
  for( ulong i=0UL; i<4UL; i++ ) fd_inflights_shred_insert( t, FD_REPAIR_KIND_SHRED, 0x80000000UL|(i+1UL), &peer, 200UL, i, NULL, NULL, 10L*(long)(i+1UL) );
  fd_inflights_meta_insert( t, 7UL, AG_REPAIR_KIND_PARENT_FEC_COUNT, &peer, 200UL, &bid, 0U, 50L );
  FD_TEST( fd_inflights_outstanding_cnt( t )==5UL );

  /* pop the oldest into the popped set, as the repair tile does */
  fd_inflight_t popped[1];
  FD_TEST( fd_inflights_should_drain( t, 10L+FD_REQLIM_DEDUP_TIMEOUT+1L ) );
  fd_inflights_pop( t, popped );
  FD_TEST( popped->key.idx==0U && t->popped_cnt==1UL && fd_inflights_outstanding_cnt( t )==4UL );
  FD_TEST( fd_inflights_oldest_ts( t )==10L );                          /* the popped head */

  FD_TEST( fd_inflights_expire( t, 10L, ULONG_MAX )==0UL );             /* strictly older only */
  FD_TEST( fd_inflights_expire( t, 35L, 1UL       )==1UL );             /* max honoured: popped t=10 */
  FD_TEST( t->popped_cnt==0UL && fd_inflights_outstanding_cnt( t )==4UL );
  FD_TEST( fd_inflights_oldest_ts( t )==20L );
  FD_TEST( fd_inflights_expire( t, 35L, ULONG_MAX )==2UL );             /* t=20, t=30 */
  FD_TEST( t->popped_cnt==0UL && fd_inflights_outstanding_cnt( t )==2UL );
  FD_TEST( fd_inflights_oldest_ts( t )==40L );
  FD_TEST( fd_inflight_pool_used( t->pool )==used0+2UL );

  /* survivors still match; expired ones do not */
  fd_pubkey_t got; fd_hash_t got_bid;
  FD_TEST( !fd_inflights_shred_match( t, FD_REPAIR_KIND_SHRED, 0x80000002UL, 200UL, 1UL, NULL, &got, &got_bid, 60L ) );
  FD_TEST(  fd_inflights_shred_match( t, FD_REPAIR_KIND_SHRED, 0x80000004UL, 200UL, 3UL, NULL, &got, &got_bid, 60L )==20L );
  FD_TEST( !memcmp( got.uc, peer.uc, sizeof(fd_pubkey_t) ) );

  FD_TEST( fd_inflights_expire( t, LONG_MAX, ULONG_MAX )==1UL );        /* the metadata record */
  fd_inflight_t out[1];
  FD_TEST( !fd_inflights_meta_match( t, 7UL, out ) );
  FD_TEST( fd_inflights_outstanding_cnt( t )==0UL && fd_inflight_pool_used( t->pool )==used0 );
  FD_TEST( fd_inflights_oldest_ts( t )==LONG_MAX );

  fd_wksp_free_laddr( mem );
  FD_LOG_NOTICE(( "pass: fd_inflights_expire releases aged records from both sets" ));
}

/* step_clock moves the tile clock forward by dt, as if the tile had been
   running (or parked) that long.  That ages in-flight records but not
   the schedulor's tickcount deadlines, so it also forces blk's check. */

static long
step_clock( ctx_t * ctx, long dt, blk_t const * blk ) {
  long now = fd_clock_tile_now( ctx->clock ) + dt;
  fd_clock_tile_set( ctx->clock, now );
  force_check( ctx, blk->slot, &(fd_hash_t){0} );
  return now;
}

/* Requests turbine beat or nobody answered are released after
   FD_ROTOR_INFLIGHT_TIMEOUT_NS, so the table stays bounded while retries
   of still-missing shreds keep matching their responses. */

static void
test_inflight_bounded( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0x160UL );
  blk->fec_root[ 1 ] = mkhash( 0x161UL );
  blk_build( blk );

  /* Set 0 whole; set 1 with its tip but holes at [HOLE0,HOLE0+8). */

# define HOLE0   (FD_FEC_SHRED_CNT+8U)
# define HOLE_N  (8U)
  deliver_turbine_fec_set( ctx, blk, 0U );
  for( uint i=FD_FEC_SHRED_CNT; i<2U*FD_FEC_SHRED_CNT; i++ ) {
    if( i>=HOLE0 && i<HOLE0+HOLE_N ) continue;
    deliver_shred( ctx, blk->slot, i, (uchar)( i==2U*FD_FEC_SHRED_CNT-1U ? blk_fec_flags( blk, 1U ) : 0 ),
                   &blk->fec_root[ 1 ], 0U, SHRED_SIG_SRC_TURBINE, blk->parent_slot, &blk->parent_block_id );
  }
  ulong from = req_cnt;
  pump( ctx );
  FD_TEST( req_count( from, FD_REPAIR_KIND_SHRED, blk->slot )==HOLE_N );
  FD_TEST( fd_inflights_outstanding_cnt( ctx->rtt )==HOLE_N );

  /* Two holes arrive by turbine first (their requests stay until they
     age out, so a late response still yields an RTT sample), two are
     answered by repair (retired on the match), four are never
     answered. */

  for( uint i=HOLE0; i<HOLE0+2U; i++ )
    deliver_shred( ctx, blk->slot, i, 0, &blk->fec_root[ 1 ], 0U, SHRED_SIG_SRC_TURBINE, blk->parent_slot, &blk->parent_block_id );
  for( uint i=HOLE0+2U; i<HOLE0+4U; i++ ) {
    req_t * r = req_find( from, FD_REPAIR_KIND_SHRED, blk->slot, i, NULL );
    FD_TEST( r );
    deliver_shred( ctx, blk->slot, i, 0, &blk->fec_root[ 1 ], r->nonce, SHRED_SIG_SRC_REPAIR, blk->parent_slot, &blk->parent_block_id );
  }
  FD_TEST( ctx->metrics->shred_match_positional==2UL && ctx->metrics->shred_match_miss==0UL );
  FD_TEST( fd_inflights_outstanding_cnt( ctx->rtt )==HOLE_N-2UL );
  uint stale_nonce = req_find( from, FD_REPAIR_KIND_SHRED, blk->slot, HOLE0+4U, NULL )->nonce;

  /* Each round re-asks for the four missing shreds; a round's requests
     live TIMEOUT/ROUND_NS+1 rounds, so the table levels off there (two
     higher until the first round's six records age out). */

# define ROUND_NS  (300000000L)
# define ROUNDS    (40UL)
  ulong steady   = (ulong)( FD_ROTOR_INFLIGHT_TIMEOUT_NS/ROUND_NS );
  ulong live_max = 4UL*( steady+1UL );
  ulong peak     = 0UL;
  for( ulong round=0UL; round<ROUNDS; round++ ) {
    step_clock( ctx, ROUND_NS, blk );
    from = req_cnt;
    pump( ctx );
    FD_TEST( req_count( from, FD_REPAIR_KIND_SHRED, blk->slot )==4UL );
    for( uint i=HOLE0+4U; i<HOLE0+HOLE_N; i++ ) FD_TEST( req_find( from, FD_REPAIR_KIND_SHRED, blk->slot, i, NULL ) );
    ulong cnt = fd_inflights_outstanding_cnt( ctx->rtt );
    if( round<steady ) FD_TEST( cnt==6UL+4UL*( round+1UL ) );
    else               FD_TEST( cnt==live_max              );
    peak = fd_ulong_max( peak, cnt );
  }
  FD_TEST( peak==live_max+2UL );                   /* levelled off, not 6+4*ROUNDS */
  FD_TEST( ctx->metrics->sent_by_kind[ FD_REPAIR_KIND_SHRED ]==HOLE_N+4UL*ROUNDS );

  /* A late answer to an expired request credits nobody: no RTT sample
     from a request long since retried.  The shred itself still lands. */

  ulong matched = ctx->metrics->shred_match_positional;
  deliver_shred( ctx, blk->slot, HOLE0+4U, 0, &blk->fec_root[ 1 ], stale_nonce, SHRED_SIG_SRC_REPAIR, blk->parent_slot, &blk->parent_block_id );
  FD_TEST( ctx->metrics->shred_match_positional==matched && ctx->metrics->shred_match_miss==1UL );

  /* The next round asks only for the three still missing, and the
     response to the current retry matches it. */

  step_clock( ctx, ROUND_NS, blk );
  from = req_cnt;
  pump( ctx );
  FD_TEST( req_count( from, FD_REPAIR_KIND_SHRED, blk->slot )==3UL );
  FD_TEST( !req_find( from, FD_REPAIR_KIND_SHRED, blk->slot, HOLE0+4U, NULL ) );
  req_t * retry = req_find( from, FD_REPAIR_KIND_SHRED, blk->slot, HOLE0+5U, NULL );
  FD_TEST( retry );
  deliver_shred( ctx, blk->slot, HOLE0+5U, 0, &blk->fec_root[ 1 ], retry->nonce, SHRED_SIG_SRC_REPAIR, blk->parent_slot, &blk->parent_block_id );
  FD_TEST( ctx->metrics->shred_match_positional==matched+1UL );

  /* Turbine fills the rest.  Nothing is re-asked, and once the last
     requests age out the table is empty. */

  for( uint i=HOLE0+6U; i<HOLE0+HOLE_N; i++ )
    deliver_shred( ctx, blk->slot, i, 0, &blk->fec_root[ 1 ], 0U, SHRED_SIG_SRC_TURBINE, blk->parent_slot, &blk->parent_block_id );
  step_clock( ctx, FD_ROTOR_INFLIGHT_TIMEOUT_NS+1L, blk );
  from = req_cnt;
  pump( ctx );
  for( ulong i=0UL; i<64UL; i++ ) tick( ctx );
  FD_TEST( !req_count( from, FD_REPAIR_KIND_SHRED, blk->slot ) );
  FD_TEST( fd_inflights_outstanding_cnt( ctx->rtt )==0UL );

  FD_TEST( !fd_rotor_verify( ctx->rotor ) );
# undef ROUNDS
# undef ROUND_NS
# undef HOLE_N
# undef HOLE0
  FD_LOG_NOTICE(( "pass: in-flight requests expire and the table stays bounded" ));
}

/* Park scheduling: after_credit leaves in idle_due when a fruitless
   pass can next make progress, and next_deadline hands it to the stem
   in the tickcount domain, capped by the oldest inflight record's
   expiry.  Work left over is due now, a queued check is due at its
   timeout, no sign credit waits for the sign frag, no replay credit
   polls, expiring inflight records is busy, and nothing pending parks
   untimed (so no busy spin on an idle tile). */

static void
test_park( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp );

  /* Idle: no blocks, nothing queued, the park is untimed. */
  pump( ctx );
  FD_TEST( !fd_schedulor_queued_cnt( ctx->schedulor ) );
  tick( ctx );
  FD_TEST( ctx->idle_due==LONG_MAX );
  FD_TEST( next_deadline( ctx )==LONG_MAX );

  /* A turbine block with its tip unknown: the check goes out and the
     block is re-queued, so the park is timed on the queued check. */
  blk_t blk[1] = {{ .slot = SNAP_SLOT+1UL, .parent_slot = SNAP_SLOT, .parent_block_id = snap_bid, .fec_cnt = 2U }};
  blk->fec_root[ 0 ] = mkhash( 0xC0UL );
  blk->fec_root[ 1 ] = mkhash( 0xC1UL );
  blk_build( blk );
  deliver_turbine_fec_set( ctx, blk, 0U );
  /* Each pass that does work (the FEC to replay, then the check) says
     retry now, so the stem never parks with work behind it. */
  ulong checks = ctx->metrics->checks;
  for( ulong i=0UL; i<8UL && ctx->metrics->checks==checks; i++ ) {
    ulong pubs = pub_cnt;
    tick( ctx );
    FD_TEST( pub_cnt>pubs );
    FD_TEST( next_deadline( ctx )<=fd_tickcount() );
  }
  FD_TEST( ctx->metrics->checks==checks+1UL );
  pump( ctx );
  long due = fd_schedulor_next_timeout( ctx->schedulor );
  FD_TEST( due!=LONG_MAX && due>fd_tickcount() );
  tick( ctx );
  FD_TEST( ctx->idle_due==due );
  FD_TEST( next_deadline( ctx )==due );

  /* A lapsed check is serviced on the next pass, which again says
     retry now. */
  checks = ctx->metrics->checks;
  force_check( ctx, blk->slot, &(fd_hash_t){0} );
  tick( ctx );
  FD_TEST( ctx->metrics->checks==checks+1UL );
  FD_TEST( next_deadline( ctx )<=fd_tickcount() );
  pump( ctx );
  tick( ctx );
  FD_TEST( ctx->idle_due==fd_schedulor_next_timeout( ctx->schedulor ) );

  /* No sign credits with a check due: only a sign frag can help, so
     the lapsed check sets no deadline.  The park is timed only on the
     expiry of the requests already sent. */
  force_check( ctx, blk->slot, &(fd_hash_t){0} );
  ctx->repair_sign_out_ctx[0].credits = 0UL;
  tick( ctx );
  FD_TEST( ctx->idle_due==LONG_MAX );
  long oldest = fd_inflights_oldest_ts( ctx->rtt );
  FD_TEST( oldest!=LONG_MAX );
  FD_TEST( next_deadline( ctx )==fd_clock_tile_wallclock_to_tickcount( ctx->clock, oldest+FD_ROTOR_INFLIGHT_TIMEOUT_NS+1L ) );
  FD_TEST( next_deadline( ctx )>fd_tickcount() );
  ctx->repair_sign_out_ctx[0].credits = ctx->repair_sign_out_ctx[0].max_credits;

  /* No replay credits: replay never rings rotor for them, so poll. */
  ulong cr_avail[ TEST_OUT_MAX ] = { [ OUT_IDX_REPLAY ] = 0UL };
  long now = fd_tickcount();
  fd_stem_context_t stem = { .cr_avail = cr_avail, .now = now };
  int charge_busy = 0;
  int poll_in     = 1;
  after_credit( ctx, &stem, &poll_in, &charge_busy );
  FD_TEST( !charge_busy );
  FD_TEST( ctx->idle_due==now+ns_to_ticks( ctx, REPLAY_CREDIT_POLL_NS ) );

  /* Credits back: the lapsed check is serviced on the next pass. */
  checks = ctx->metrics->checks;
  tick( ctx );
  FD_TEST( ctx->metrics->checks==checks+1UL );

  /* An empty table adds no deadline.  A request parks the tile no
     longer than its expiry, which is due once the clock passes it. */
  fd_inflights_expire( ctx->rtt, LONG_MAX, ULONG_MAX );
  FD_TEST( fd_inflights_oldest_ts( ctx->rtt )==LONG_MAX );
  ctx->idle_due = LONG_MAX;
  FD_TEST( next_deadline( ctx )==LONG_MAX );
  fd_pubkey_t peer = {0};
  long        sent = fd_clock_tile_now( ctx->clock );
  for( ulong i=0UL; i<9UL; i++ ) fd_inflights_shred_insert( ctx->rtt, FD_REPAIR_KIND_SHRED, 0x80000000UL|i, &peer, blk->slot, i, NULL, NULL, sent );
  long expiry = next_deadline( ctx );
  FD_TEST( expiry==fd_clock_tile_wallclock_to_tickcount( ctx->clock, sent+FD_ROTOR_INFLIGHT_TIMEOUT_NS+1L ) );
  FD_TEST( expiry>fd_tickcount() );

  /* The backlog goes four per pass, and every pass that expires any is
     busy, so the stem does not park with more behind it. */
  fd_clock_tile_set( ctx->clock, sent+FD_ROTOR_INFLIGHT_TIMEOUT_NS+1L );
  FD_TEST( next_deadline( ctx )<=fd_tickcount() );
  for( ulong i=0UL; i<4UL; i++ ) {
    stem.now    = fd_tickcount();
    charge_busy = 0;
    after_credit( ctx, &stem, &poll_in, &charge_busy ); /* no replay credits: only the expiry runs */
    FD_TEST( charge_busy==(i<3UL) ); /* 4, 4, 1, then none */
  }
  FD_TEST( !fd_inflights_outstanding_cnt( ctx->rtt ) );
  FD_TEST( next_deadline( ctx )==ctx->idle_due ); /* back to the replay credit poll */

  FD_LOG_NOTICE(( "pass: test_park" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_turbine_block( wksp );

  fd_wksp_reset( wksp, 1U );
  test_block_received_event( wksp );

  for( int block_id_only=0; block_id_only<2; block_id_only++ ) {
    for( int active_walk=0; active_walk<2; active_walk++ ) {
      fd_wksp_reset( wksp, 1U );
      test_turbine_finalized_orphan( wksp, block_id_only, active_walk );
    }
  }

  fd_wksp_reset( wksp, 1U );
  test_shred_ts_from_tsorig( wksp );

  fd_wksp_reset( wksp, 1U );
  test_reception_stats( wksp );

  fd_wksp_reset( wksp, 1U );
  test_catchup_seed( wksp );

  fd_wksp_reset( wksp, 1U );
  test_schedulor_drives_requests( wksp );

  fd_wksp_reset( wksp, 1U );
  test_votor_block_supersedes( wksp );

  fd_wksp_reset( wksp, 1U );
  test_meta_verify( wksp );

  fd_wksp_reset( wksp, 1U );
  test_block_id_only( wksp );

  fd_wksp_reset( wksp, 1U );
  test_publish_prunes( wksp );

  fd_wksp_reset( wksp, 1U );
  test_deliver_from_root( wksp );

  fd_wksp_reset( wksp, 1U );
  test_fec_evicted( wksp );

  fd_wksp_reset( wksp, 1U );
  test_ping_pong( wksp );

  fd_wksp_reset( wksp, 1U );
  test_metrics_exported( wksp );

  fd_wksp_reset( wksp, 1U );
  test_inflights_expire( wksp );

  fd_wksp_reset( wksp, 1U );
  test_inflight_bounded( wksp );

  fd_wksp_reset( wksp, 1U );
  test_park( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
