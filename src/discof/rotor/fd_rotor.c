#include "fd_rotor.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"

#define ROTOR_MAGIC (0xf17eda2ce7040001UL)
#define NIL UINT_MAX

/* Private entries only exist once their root is known.  Only the entry
   on roots owns received.  Output linkage is per version, like delivery. */
typedef struct {
  fd_hash_t merkle_root;
  uint      next, prev;
  uint      block, idx, received;
  uint      out_next, out_prev;
  uchar     owner, complete, slot_complete, data_complete, is_leader, queued;
} rotor_fec_t;

#define POOL_NAME rotor_fpool
#define POOL_T rotor_fec_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"
#define MAP_NAME rotor_roots
#define MAP_ELE_T rotor_fec_t
#define MAP_IDX_T uint
#define MAP_KEY merkle_root
#define MAP_KEY_T fd_hash_t
#define MAP_KEY_EQ(a,b) (!memcmp( (a)->uc, (b)->uc, FD_SHRED_MERKLE_NODE_SZ ))
#define MAP_KEY_HASH(k,s) fd_ulong_hash( fd_ulong_load_8( (k)->uc ) ^ (s) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

typedef struct {
  ulong slot;
  uint next, prev;
  fd_hash_t id, parent_id;
  ulong generation, parent_slot;
  uint parent_batch, required, end, delivered, recovered;
  uint gen_cursor, gen_next, gen_prev;
  uchar turbine, final, cancel, connected, metadata, generating;
  long first_ts, range_due;
} rotor_block_t;
#define POOL_NAME rotor_bpool
#define POOL_T rotor_block_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"
#define MAP_NAME rotor_blocks
#define MAP_ELE_T rotor_block_t
#define MAP_IDX_T uint
#define MAP_KEY slot
#define MAP_MULTI 1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* Generation + pool index is an internal compression of (slot, block_id).
   It is checked before every dereference, including signing acknowledgments.
   Seed probes use block=NIL and carry a slot instead. */
typedef struct {
  ulong generation, slot;
  uint block, kind, idx;
} rotor_key_t;
typedef struct {
  rotor_key_t key;
  uint next, prev, heap_pos;
  long due;
  ulong reservation;
  uchar state; /* 1 queued, 2 reserved/signing, 3 inflight */
} rotor_job_t;
#define POOL_NAME rotor_jpool
#define POOL_T rotor_job_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"
#define MAP_NAME rotor_jobs
#define MAP_ELE_T rotor_job_t
#define MAP_IDX_T uint
#define MAP_KEY key
#define MAP_KEY_T rotor_key_t
#define MAP_KEY_EQ(a,b) ((a)->generation==(b)->generation && (a)->slot==(b)->slot && (a)->block==(b)->block && (a)->kind==(b)->kind && (a)->idx==(b)->idx)
#define MAP_KEY_HASH(k,s) fd_ulong_hash( (s) ^ (k)->generation ^ fd_ulong_hash( (k)->slot ) ^ ((ulong)(k)->block<<32) ^ ((ulong)(k)->kind<<24) ^ (k)->idx )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

typedef struct {
  rotor_job_t * pool;
  rotor_jobs_t * map;
  uint * heap;
  ulong cnt, max;
} rotor_queue_t;

struct fd_rotor {
  ulong magic;
  fd_rotor_config_t config;
  rotor_block_t * blocks;
  rotor_blocks_t * block_map;
  rotor_fec_t * fecs;
  rotor_roots_t * roots;
  uint * table;
  uint * stack;
  uint * redeliver;
  ulong redeliver_cnt;
  uint redeliver_fec;
  int missing, borrowed, borrowed_redelivery;
  uint borrowed_fec;
  rotor_queue_t queue[2]; /* positional/named shred, all metadata */
  uint gen_head, gen_tail, out_head, out_tail;
  ulong fec_per_block, generation, reservation;
  ulong root, highest_delivered, first_turbine, seed_cursor;
  uint seed_phase, next_queue;
  ulong dropped, stale;
  int pending_root;
  ulong pending_slot;
  fd_hash_t root_id, pending_id;
  fd_store_t * store;
};

fd_rotor_config_t
fd_rotor_config_default( void ) {
  return (fd_rotor_config_t){ .block_max=FD_ROTOR_BLOCK_MAX_DEFAULT,
    .max_shreds=FD_SHRED_BLK_MAX, .shred_request_max=FD_ROTOR_SHRED_REQUEST_MAX_DEFAULT,
    .seed_window=20000UL, .turbine_grace=100000000L, .highest_delay=250000000L,
    .retry_delay=100000000L, .seed_peer_min=64UL };
}

ulong fd_rotor_align( void ) { return 128UL; }

ulong
fd_rotor_footprint( fd_rotor_config_t const * c ) {
  if( !c || c->block_max<2UL || c->block_max>=UINT_MAX || !c->max_shreds ||
      c->max_shreds>(1UL<<28) || c->max_shreds%32UL ||
      !c->shred_request_max || c->shred_request_max>=UINT_MAX ||
      c->seed_window>=UINT_MAX || c->turbine_grace<0L || c->highest_delay<0L || c->retry_delay<=0L ) return 0UL;
  ulong f = c->block_max*(c->max_shreds/32UL);
  ulong m = f+3UL*c->block_max+c->seed_window;
  if( f>=UINT_MAX || m>=UINT_MAX ) return 0UL;
  ulong bchains = rotor_blocks_chain_cnt_est( c->block_max );
  ulong fchains = rotor_roots_chain_cnt_est( f );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, 128UL, sizeof(fd_rotor_t) );
  l = FD_LAYOUT_APPEND( l, rotor_bpool_align(), rotor_bpool_footprint(c->block_max) );
  l = FD_LAYOUT_APPEND( l, rotor_blocks_align(), rotor_blocks_footprint(bchains) );
  l = FD_LAYOUT_APPEND( l, rotor_fpool_align(), rotor_fpool_footprint(f) );
  l = FD_LAYOUT_APPEND( l, rotor_roots_align(), rotor_roots_footprint(fchains) );
  l = FD_LAYOUT_APPEND( l, alignof(uint), f*sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(uint), c->block_max*sizeof(uint) );
  l = FD_LAYOUT_APPEND( l, alignof(uint), c->block_max*sizeof(uint) );
  for( uint q=0; q<2; q++ ) {
    ulong n = q ? m : c->shred_request_max;
    l = FD_LAYOUT_APPEND( l, rotor_jpool_align(), rotor_jpool_footprint(n) );
    l = FD_LAYOUT_APPEND( l, rotor_jobs_align(), rotor_jobs_footprint(rotor_jobs_chain_cnt_est(n)) );
    l = FD_LAYOUT_APPEND( l, alignof(uint), n*sizeof(uint) );
  }
  return FD_LAYOUT_FINI( l, 128UL );
}

void *
fd_rotor_new( void * mem, fd_rotor_config_t const * c, ulong seed, fd_store_t * store ) {
  ulong sz = fd_rotor_footprint( c );
  if( !mem || !sz || !fd_ulong_is_aligned((ulong)mem,128UL) ) return NULL;
  memset( mem, 0, sz );
  ulong f = c->block_max*(c->max_shreds/32UL);
  ulong m = f+3UL*c->block_max+c->seed_window;
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_rotor_t * r = FD_SCRATCH_ALLOC_APPEND( l, 128UL, sizeof(fd_rotor_t) );
  void * bp = FD_SCRATCH_ALLOC_APPEND( l, rotor_bpool_align(), rotor_bpool_footprint(c->block_max) );
  void * bm = FD_SCRATCH_ALLOC_APPEND( l, rotor_blocks_align(), rotor_blocks_footprint(rotor_blocks_chain_cnt_est(c->block_max)) );
  void * fp = FD_SCRATCH_ALLOC_APPEND( l, rotor_fpool_align(), rotor_fpool_footprint(f) );
  void * fm = FD_SCRATCH_ALLOC_APPEND( l, rotor_roots_align(), rotor_roots_footprint(rotor_roots_chain_cnt_est(f)) );
  r->table = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), f*sizeof(uint) );
  r->stack = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), c->block_max*sizeof(uint) );
  r->redeliver = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), c->block_max*sizeof(uint) );
  r->blocks = rotor_bpool_join( rotor_bpool_new( bp, c->block_max ) );
  r->block_map = rotor_blocks_join( rotor_blocks_new( bm, rotor_blocks_chain_cnt_est(c->block_max), seed ) );
  r->fecs = rotor_fpool_join( rotor_fpool_new( fp, f ) );
  r->roots = rotor_roots_join( rotor_roots_new( fm, rotor_roots_chain_cnt_est(f), seed ) );
  for( uint q=0; q<2; q++ ) {
    ulong n = q ? m : c->shred_request_max;
    void * jp = FD_SCRATCH_ALLOC_APPEND( l, rotor_jpool_align(), rotor_jpool_footprint(n) );
    void * jm = FD_SCRATCH_ALLOC_APPEND( l, rotor_jobs_align(), rotor_jobs_footprint(rotor_jobs_chain_cnt_est(n)) );
    r->queue[q].heap = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint), n*sizeof(uint) );
    r->queue[q].pool = rotor_jpool_join( rotor_jpool_new( jp, n ) );
    r->queue[q].map  = rotor_jobs_join( rotor_jobs_new( jm, rotor_jobs_chain_cnt_est(n), seed ) );
    r->queue[q].max = n;
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI(l,128UL)==(ulong)mem+sz );
  r->config = *c;
  r->store = store;
  r->fec_per_block = c->max_shreds/32UL;
  r->root = r->first_turbine = ULONG_MAX;
  r->gen_head = r->gen_tail = r->out_head = r->out_tail = NIL;
  r->magic = ROTOR_MAGIC;
  return mem;
}

fd_rotor_t * fd_rotor_join( void * mem ) {
  if( !mem || !fd_ulong_is_aligned((ulong)mem,128UL) ) return NULL;
  fd_rotor_t * r = mem;
  return r->magic==ROTOR_MAGIC ? r : NULL;
}
void * fd_rotor_leave( fd_rotor_t * r ) { return r; }
void * fd_rotor_delete( void * mem ) {
  fd_rotor_t * r = fd_rotor_join( mem );
  if( !r ) return NULL;
  r->magic = 0UL;
  return mem;
}

static uint
block_first( fd_rotor_t * r, ulong slot ) { return (uint)rotor_blocks_idx_query( r->block_map, &slot, NIL, r->blocks ); }

static rotor_block_t *
block_query( fd_rotor_t * r, ulong slot, fd_hash_t const * id ) {
  for( uint i=block_first(r,slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) ) {
    rotor_block_t * b = r->blocks+i;
    if( fd_hash_check_zero(id) ? b->turbine : fd_hash_eq(&b->id,id) ) return b;
  }
  /* Genesis is the only named anchor with a zero ID. */
  if( slot==r->root && fd_hash_eq(id,&r->root_id) ) {
    uint i=block_first(r,slot);
    if( i!=NIL ) return r->blocks+i;
  }
  return NULL;
}

static rotor_fec_t *
block_fec( fd_rotor_t * r, rotor_block_t * b, uint idx ) {
  if( idx>=r->config.max_shreds ) return NULL;
  uint i=r->table[ (ulong)(b-r->blocks)*r->fec_per_block+idx/32U ];
  return i==NIL ? NULL : r->fecs+i;
}

static rotor_fec_t *
root_query( fd_rotor_t * r, fd_hash_t const * mr ) { return rotor_roots_ele_query(r->roots,mr,NULL,r->fecs); }

static int
suppressed( fd_rotor_t * r, rotor_block_t * b ) {
  if( !b->turbine || !fd_hash_check_zero(&b->id) ) return 0;
  for( uint i=block_first(r,b->slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) )
    if( !r->blocks[i].turbine ) return 1;
  return 0;
}

static void
generation_remove( fd_rotor_t * r, rotor_block_t * b ) {
  if( !b->generating ) return;
  if( b->gen_prev==NIL ) r->gen_head=b->gen_next; else r->blocks[b->gen_prev].gen_next=b->gen_next;
  if( b->gen_next==NIL ) r->gen_tail=b->gen_prev; else r->blocks[b->gen_next].gen_prev=b->gen_prev;
  b->generating=0;
}

static void
generate( fd_rotor_t * r, rotor_block_t * b, long due ) {
  b->range_due = b->generating ? fd_long_min(b->range_due,due) : due;
  if( b->generating ) return;
  b->generating=1;
  b->gen_cursor=0U;
  b->gen_next=NIL;
  b->gen_prev=r->gen_tail;
  if( r->gen_tail==NIL ) r->gen_head=(uint)(b-r->blocks); else r->blocks[r->gen_tail].gen_next=(uint)(b-r->blocks);
  r->gen_tail=(uint)(b-r->blocks);
}

static rotor_block_t *
block_new( fd_rotor_t * r, ulong slot, fd_hash_t const * id, long now ) {
  rotor_block_t * b=block_query(r,slot,id);
  if( b ) return b;
  if( slot==ULONG_MAX || (r->root!=ULONG_MAX && slot<=r->root) ) return NULL;
  ulong cnt=0;
  for( uint i=block_first(r,slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) ) {
    if( r->blocks[i].final ) return NULL;
    cnt++;
  }
  if( cnt>=FD_ROTOR_VERSION_MAX || !rotor_bpool_free(r->blocks) ) return NULL;
  b=rotor_bpool_ele_acquire(r->blocks);
  memset(b,0,sizeof(*b));
  b->slot=slot;
  b->id=*id;
  b->turbine=(uchar)fd_hash_check_zero(id);
  b->generation=++r->generation;
  b->parent_slot=ULONG_MAX;
  b->parent_batch=b->end=NIL;
  b->first_ts=now;
  memset(r->table+(ulong)(b-r->blocks)*r->fec_per_block,0xff,r->fec_per_block*sizeof(uint));
  rotor_blocks_ele_insert(r->block_map,b,r->blocks);
  if( !b->turbine ) {
    for( uint i=block_first(r,slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) ) {
      rotor_block_t * t=r->blocks+i;
      if( t->turbine && fd_hash_check_zero(&t->id) ) t->cancel=1;
    }
  }
  generate(r,b,LONG_MAX);
  return b;
}

static rotor_fec_t *
fec_new( fd_rotor_t * r, rotor_block_t * b, uint idx, fd_hash_t const * mr ) {
  rotor_fec_t * owner=root_query(r,mr);
  if( owner && (r->blocks[owner->block].slot!=b->slot || owner->idx!=idx) ) return NULL;
  FD_TEST( rotor_fpool_free(r->fecs) ); /* dense table bounds private entries */
  rotor_fec_t * f=rotor_fpool_ele_acquire(r->fecs);
  memset(f,0,sizeof(*f));
  f->merkle_root=owner ? owner->merkle_root : *mr;
  f->block=(uint)(b-r->blocks);
  f->idx=idx;
  f->out_next=f->out_prev=NIL;
  if( owner ) {
    f->complete=owner->complete;
    f->slot_complete=owner->slot_complete;
    f->data_complete=owner->data_complete;
    f->is_leader=owner->is_leader;
  } else {
    f->owner=1;
    rotor_roots_ele_insert(r->roots,f,r->fecs);
  }
  r->table[(ulong)f->block*r->fec_per_block+idx/32U]=(uint)(f-r->fecs);
  return f;
}

/* Binary min heaps.  Stable tie order is slot, position, kind and pool
   index.  The two heaps alternate when both have due work. */
static int
job_before( rotor_queue_t * q, uint a, uint b ) {
  rotor_job_t * x=q->pool+a; rotor_job_t * y=q->pool+b;
  if( x->due!=y->due ) return x->due<y->due;
  if( x->key.slot!=y->key.slot ) return x->key.slot<y->key.slot;
  if( x->key.idx!=y->key.idx ) return x->key.idx<y->key.idx;
  if( x->key.kind!=y->key.kind ) return x->key.kind<y->key.kind;
  return a<b;
}

static void
heap_up( rotor_queue_t * q, ulong pos ) {
  uint idx=q->heap[pos];
  while( pos ) {
    ulong p=(pos-1UL)/2UL;
    if( !job_before(q,idx,q->heap[p]) ) break;
    q->heap[pos]=q->heap[p]; q->pool[q->heap[pos]].heap_pos=(uint)pos; pos=p;
  }
  q->heap[pos]=idx; q->pool[idx].heap_pos=(uint)pos;
}

static void
heap_push( rotor_queue_t * q, uint idx ) {
  q->heap[q->cnt]=idx;
  heap_up(q,q->cnt++);
}

static uint
heap_pop( rotor_queue_t * q ) {
  uint result=q->heap[0];
  uint idx=q->heap[--q->cnt];
  ulong p=0;
  while( 2UL*p+1UL<q->cnt ) {
    ulong c=2UL*p+1UL;
    if( c+1UL<q->cnt && job_before(q,q->heap[c+1UL],q->heap[c]) ) c++;
    if( !job_before(q,q->heap[c],idx) ) break;
    q->heap[p]=q->heap[c]; q->pool[q->heap[p]].heap_pos=(uint)p; p=c;
  }
  if( q->cnt ) { q->heap[p]=idx; q->pool[idx].heap_pos=(uint)p; }
  q->pool[result].heap_pos=NIL;
  return result;
}

static int
schedule( fd_rotor_t * r, rotor_block_t * b, ulong slot, uint kind, uint idx, long due ) {
  uint qi=(kind!=FD_REPAIR_KIND_SHRED && kind!=AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID);
  if( b && (b->cancel || suppressed(r,b)) ) return 1;
  if( r->config.block_id_only && (kind==FD_REPAIR_KIND_SHRED || kind==FD_REPAIR_KIND_ORPHAN || kind==FD_REPAIR_KIND_HIGHEST_SHRED) ) return 1;
  rotor_key_t key={ .generation=b ? b->generation : 0UL, .slot=slot,
    .block=b ? (uint)(b-r->blocks) : NIL, .kind=kind, .idx=idx };
  rotor_queue_t * q=r->queue+qi;
  rotor_job_t * j=rotor_jobs_ele_query(q->map,&key,NULL,q->pool);
  if( j ) {
    if( j->state==1 && due<j->due ) { j->due=due; heap_up(q,j->heap_pos); }
    return 1;
  }
  if( !rotor_jpool_free(q->pool) ) { if( !qi ) r->dropped++; return 0; }
  j=rotor_jpool_ele_acquire(q->pool);
  j->key=key; j->due=due; j->state=1; j->reservation=0;
  rotor_jobs_ele_insert(q->map,j,q->pool);
  heap_push(q,(uint)(j-q->pool));
  return 1;
}

static int
parent_present( fd_rotor_t * r, rotor_block_t * b ) {
  return b->parent_slot!=ULONG_MAX && block_query(r,b->parent_slot,&b->parent_id)!=NULL;
}

static int parent_impossible( fd_rotor_t * r, rotor_block_t * b );

static int
job_needed( fd_rotor_t * r, rotor_job_t * j, fd_rotor_request_t * out ) {
  rotor_key_t * k=&j->key;
  if( r->root==ULONG_MAX || k->slot<=r->root ) return 0;
  int positional=k->kind==FD_REPAIR_KIND_SHRED || k->kind==FD_REPAIR_KIND_HIGHEST_SHRED || k->kind==FD_REPAIR_KIND_ORPHAN;
  if( positional && r->config.block_id_only ) return 0;
  rotor_block_t * b=NULL;
  rotor_fec_t * f=NULL;
  if( k->block==NIL ) {
    /* Discovery probes stop once *any* version has taken over the slot. */
    if( k->slot-r->root>r->config.seed_window || block_first(r,k->slot)!=NIL ) return 0;
  } else {
    b=r->blocks+k->block;
    if( b->generation!=k->generation || b->slot!=k->slot || b->cancel || suppressed(r,b) || parent_impossible(r,b) ) return 0;
    switch( k->kind ) {
    case FD_REPAIR_KIND_ORPHAN:
      if( parent_present(r,b) ) return 0;
      break;
    case FD_REPAIR_KIND_HIGHEST_SHRED:
      if( b->end!=NIL ) return 0;
      break;
    case AG_REPAIR_KIND_PARENT_FEC_COUNT:
      if( b->metadata ) return 0;
      break;
    case AG_REPAIR_KIND_FEC_ROOT:
      if( !b->metadata || k->idx>=b->required || block_fec(r,b,k->idx) ) return 0;
      break;
    case FD_REPAIR_KIND_SHRED:
    case AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID:
      if( k->idx>=b->required || (b->end!=NIL && k->idx>b->end) ) return 0;
      f=block_fec(r,b,k->idx);
      if( !f ) {
        if( k->kind!=FD_REPAIR_KIND_SHRED || k->idx%32U ) return 0;
      } else {
        rotor_fec_t * o=root_query(r,&f->merkle_root);
        if( f->complete || (o->received & (1U<<(k->idx%32U))) ) return 0;
      }
      break;
    default: return 0;
    }
  }
  if( out ) {
    memset(out,0,sizeof(*out));
    out->kind=k->kind; out->slot=k->slot; out->idx=k->idx;
    if( b && !positional ) out->block_id=b->id;
    if( f ) out->fec_root=root_query(r,&f->merkle_root)->merkle_root;
    if( b && k->kind==FD_REPAIR_KIND_HIGHEST_SHRED ) out->idx=b->required ? b->required-1U : 0U;
  }
  return 1;
}

static void
job_release( rotor_queue_t * q, rotor_job_t * j ) {
  rotor_jobs_ele_remove_fast(q->map,j,q->pool);
  j->state=0;
  rotor_jpool_ele_release(q->pool,j);
}

/* Enqueue individual missing-shred requests.  A FEC has no fill job or
   deadline; only the request entries carry due times. */
static void
fill( fd_rotor_t * r, rotor_block_t * b, rotor_fec_t * f, long due ) {
  if( f->complete || b->cancel || suppressed(r,b) ) return;
  rotor_fec_t * o=root_query(r,&f->merkle_root);
  uint end=fd_uint_min(f->idx+32U,b->required);
  for( uint i=f->idx; i<end; i++ ) {
    if( !(o->received & (1U<<(i%32U))) )
      schedule(r,b,b->slot,b->turbine ? FD_REPAIR_KIND_SHRED : AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID,i,due);
  }
}

static void
out_remove( fd_rotor_t * r, rotor_fec_t * f ) {
  if( !f->queued ) return;
  if( f->out_prev==NIL ) r->out_head=f->out_next; else r->fecs[f->out_prev].out_next=f->out_next;
  if( f->out_next==NIL ) r->out_tail=f->out_prev; else r->fecs[f->out_next].out_prev=f->out_prev;
  f->queued=0;
  f->out_next=f->out_prev=NIL;
}

static void
block_drop( fd_rotor_t * r, rotor_block_t * b ) {
  generation_remove(r,b);
  for( uint k=0; k<r->fec_per_block; k++ ) {
    rotor_fec_t * f=block_fec(r,b,k*32U);
    if( !f ) continue;
    out_remove(r,f);
    if( f->owner ) {
      rotor_roots_ele_remove_fast(r->roots,f,r->fecs);
      rotor_fec_t * replacement=NULL;
      for( uint i=block_first(r,b->slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) ) {
        if( r->blocks+i==b ) continue;
        rotor_fec_t * s=block_fec(r,r->blocks+i,k*32U);
        if( s && !memcmp(s->merkle_root.uc,f->merkle_root.uc,FD_SHRED_MERKLE_NODE_SZ) ) { replacement=s; break; }
      }
      if( replacement ) {
        replacement->owner=1;
        replacement->received=f->received;
        replacement->merkle_root=f->merkle_root;
        rotor_roots_ele_insert(r->roots,replacement,r->fecs);
      } else if( r->store && f->complete ) {
        fd_store_map_t map[1];
        FD_TEST( fd_store_map_ljoin(r->store,map) );
        fd_store_remove(r->store,map,&f->merkle_root);
      }
    }
    rotor_fpool_ele_release(r->fecs,f);
  }
  rotor_blocks_ele_remove_fast(r->block_map,b,r->blocks);
  b->generation=0UL; /* invalidate queued and reserved requests before recycling */
  rotor_bpool_ele_release(r->blocks,b);
}

/* Named versions accept only verified metadata as their bound/parent.
   Turbine bounds are first-wins, and must end on an FEC boundary. */
static int
accept_end( rotor_block_t * b, uint end ) {
  if( end%32U!=31U || (b->end!=NIL && b->end!=end) || b->required>end+1U ) return 0;
  b->end=end;
  b->required=end+1U;
  return 1;
}

static int
parent_impossible( fd_rotor_t * r, rotor_block_t * b ) {
  if( b->parent_slot==ULONG_MAX ) return 0;
  if( b->parent_slot<r->root ) return 1;
  if( b->parent_slot==r->root ) return !fd_hash_eq(&b->parent_id,&r->root_id);
  for( uint i=block_first(r,b->parent_slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) )
    if( r->blocks[i].final && !fd_hash_eq(&r->blocks[i].id,&b->parent_id) ) return 1;
  return 0;
}

static void
finalize_id( fd_rotor_t * r, rotor_block_t * b ) {
  if( !b->turbine || !fd_hash_check_zero(&b->id) || suppressed(r,b) || b->end==NIL || b->parent_slot==ULONG_MAX ) return;
  uint cnt=(b->end+1U)/32U;
  for( uint k=0; k<cnt; k++ ) {
    rotor_fec_t * f=block_fec(r,b,k*32U);
    if( !f || !f->complete ) return;
  }
  uchar mem[ FD_BMTREE_COMMIT_FOOTPRINT(0UL) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree=fd_bmtree_commit_init(mem,20UL,FD_BMTREE_LONG_PREFIX_SZ,0UL);
  for( uint k=0; k<cnt; k++ ) {
    fd_bmtree_node_t leaf[1];
    memcpy(leaf->hash,block_fec(r,b,k*32U)->merkle_root.uc,32UL);
    fd_bmtree_commit_append(tree,leaf,1UL);
  }
  fd_bmtree_node_t leaf[1];
  fd_sha256_t sha[1];
  fd_sha256_init(sha);
  fd_sha256_append(sha,&b->parent_slot,sizeof(ulong));
  fd_sha256_append(sha,b->parent_id.uc,32UL);
  fd_sha256_append(sha,&cnt,sizeof(uint));
  fd_sha256_fini(sha,leaf->hash);
  fd_bmtree_commit_append(tree,leaf,1UL);
  memcpy(b->id.uc,fd_bmtree_commit_fini(tree),32UL);
}

/* Advance the changed version and wake its exact children when it
   completes or its connectivity changes.  Child lookup retains chainer's
   bounded block scan; ordinary data arrivals do not scan the live window. */
static void
advance_delivery( fd_rotor_t * r, rotor_block_t * changed ) {
  if( r->root==ULONG_MAX ) return;
  ulong n=0;
  r->stack[n++]=(uint)(changed-r->blocks);
  while( n ) {
    rotor_block_t * b=r->blocks+r->stack[--n];
    int was_connected=b->connected;
    uint was_delivered=b->delivered;
    finalize_id(r,b);
    if( b->slot>r->root ) {
      rotor_block_t * p=block_query(r,b->parent_slot,&b->parent_id);
      b->connected=(uchar)(p && p->connected);
      if( b->connected && p->end!=NIL && p->delivered==p->end+1U && !suppressed(r,b) ) {
        while( b->delivered<b->required ) {
          rotor_fec_t * f=block_fec(r,b,b->delivered);
          if( !f || !f->complete ) break;
          if( b->end!=NIL && f->idx+31U==b->end && fd_hash_check_zero(&b->id) ) break;
          FD_TEST(!f->queued);
          f->queued=1;
          f->out_prev=r->out_tail;
          f->out_next=NIL;
          if( r->out_tail==NIL ) r->out_head=(uint)(f-r->fecs); else r->fecs[r->out_tail].out_next=(uint)(f-r->fecs);
          r->out_tail=(uint)(f-r->fecs);
          b->delivered+=32U;
          if( b->end!=NIL && b->delivered==b->end+1U ) r->highest_delivered=fd_ulong_max(r->highest_delivered,b->slot);
        }
      }
    }
    if( b->slot!=r->root && was_connected==b->connected &&
        !(was_delivered!=b->delivered && b->end!=NIL && b->delivered==b->end+1U) ) continue;
    /* An unknown block ID is not an ancestry identity. */
    if( fd_hash_check_zero(&b->id) && b->slot!=r->root ) continue;
    for( rotor_blocks_iter_t it=rotor_blocks_iter_init(r->block_map,r->blocks);
         !rotor_blocks_iter_done(it,r->block_map,r->blocks);
         it=rotor_blocks_iter_next(it,r->block_map,r->blocks) ) {
      rotor_block_t * child=rotor_blocks_iter_ele(it,r->block_map,r->blocks);
      if( child->slot>b->slot && child->parent_slot==b->slot && fd_hash_eq(&child->parent_id,&b->id) ) {
        FD_TEST(n<r->config.block_max);
        r->stack[n++]=(uint)(child-r->blocks);
      }
    }
  }
}

int
fd_rotor_frag_snapshot( fd_rotor_t * r, ulong root, fd_hash_t const * id ) {
  if( r->root!=ULONG_MAX || root==ULONG_MAX ) return FD_ROTOR_IGNORE;
  rotor_block_t * b=block_new(r,root,id,0L);
  FD_TEST(b);
  generation_remove(r,b);
  b->turbine=0;
  b->end=0U; b->delivered=1U; b->connected=1;
  b->parent_slot=root; b->parent_id=*id;
  r->root=root; r->root_id=*id;
  r->highest_delivered=root;
  r->seed_cursor=root+1UL;
  return FD_ROTOR_ACCEPT;
}

int
fd_rotor_frag_genesis( fd_rotor_t * r ) {
  fd_hash_t zero={0};
  return fd_rotor_frag_snapshot(r,0UL,&zero);
}

int
fd_rotor_frag_shred( fd_rotor_t * r, fd_rotor_shred_t const * e, long now ) {
  if( r->root==ULONG_MAX || e->slot<=r->root ) {
    if( e->kind==FD_ROTOR_SHRED_COMPLETE && r->store ) {
      fd_store_map_t map[1];
      FD_TEST(fd_store_map_ljoin(r->store,map));
      fd_store_remove(r->store,map,&e->merkle_root);
    }
    return FD_ROTOR_IGNORE;
  }
  if( e->kind==FD_ROTOR_SHRED_DATA && e->src==FD_ROTOR_SRC_TURBINE && r->first_turbine==ULONG_MAX ) r->first_turbine=e->slot;
  fd_hash_t zero={0};
  if( e->kind==FD_ROTOR_SHRED_EQVOC || e->kind==FD_ROTOR_SHRED_INVALID ) {
    rotor_block_t * b=block_query(r,e->slot,&zero);
    if( b && fd_hash_check_zero(&b->id) ) b->cancel=1;
    return FD_ROTOR_ACCEPT;
  }
  if( e->kind==FD_ROTOR_SHRED_CODE ) return FD_ROTOR_IGNORE;
  if( e->idx>=r->config.max_shreds || fd_hash_check_zero(&e->merkle_root) ) return FD_ROTOR_IGNORE;
  uint k=e->idx&~31U;
  if( e->kind!=FD_ROTOR_SHRED_DATA && e->idx!=k ) return FD_ROTOR_IGNORE;
  if( e->has_parent && (e->parent_slot>=e->slot ||
      (fd_hash_check_zero(&e->parent_id) && !(e->parent_slot==r->root && fd_hash_check_zero(&r->root_id)))) ) return FD_ROTOR_IGNORE;
  if( e->kind==FD_ROTOR_SHRED_DATA && e->slot_complete && e->idx%32U!=31U ) return FD_ROTOR_IGNORE;
  rotor_fec_t * owner=root_query(r,&e->merkle_root);
  if( owner && (r->blocks[owner->block].slot!=e->slot || owner->idx!=k) ) return FD_ROTOR_IGNORE;
  if( !owner ) {
    if( e->kind!=FD_ROTOR_SHRED_DATA ) {
      if( e->kind==FD_ROTOR_SHRED_COMPLETE && r->store ) {
        fd_store_map_t map[1]; FD_TEST(fd_store_map_ljoin(r->store,map));
        fd_store_remove(r->store,map,&e->merkle_root);
      }
      return FD_ROTOR_IGNORE;
    }
    rotor_block_t * b=block_query(r,e->slot,&zero);
    if( !b ) {
      if( block_first(r,e->slot)!=NIL ) return FD_ROTOR_IGNORE;
      b=block_new(r,e->slot,&zero,now);
      if( !b ) return FD_ROTOR_AGAIN;
    }
    if( !fd_hash_check_zero(&b->id) || suppressed(r,b) || block_fec(r,b,k) || (b->end!=NIL && k>b->end) ) return FD_ROTOR_IGNORE;
    if( e->slot_complete && (b->required>e->idx+1U || (b->end!=NIL && b->end!=e->idx)) ) return FD_ROTOR_IGNORE;
    owner=fec_new(r,b,k,&e->merkle_root);
    FD_TEST(owner);
  }
  if( e->kind==FD_ROTOR_SHRED_EVICTED ) {
    if( owner->complete ) return FD_ROTOR_IGNORE; /* completed store data outlives resolver */
    owner->received=0U;
  } else if( e->kind==FD_ROTOR_SHRED_COMPLETE ) {
    if( owner->complete ) return FD_ROTOR_ACCEPT; /* flags/accounting are one-time */
  } else if( e->kind!=FD_ROTOR_SHRED_DATA ) return FD_ROTOR_IGNORE;

  uint recovered=e->kind==FD_ROTOR_SHRED_COMPLETE ? (uint)fd_uint_popcnt(~owner->received) : 0U;
  if( e->kind==FD_ROTOR_SHRED_COMPLETE ) owner->received=UINT_MAX;
  if( e->kind==FD_ROTOR_SHRED_DATA ) owner->received|=1U<<(e->idx%32U);
  for( uint i=block_first(r,e->slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) ) {
    rotor_block_t * b=r->blocks+i;
    rotor_fec_t * f=block_fec(r,b,k);
    if( !f || memcmp(f->merkle_root.uc,e->merkle_root.uc,FD_SHRED_MERKLE_NODE_SZ) ) continue;
    f->merkle_root=e->merkle_root;
    uint old_required=b->required;
    int parent_changed=0;
    if( b->turbine ) {
      b->required=fd_uint_max(b->required,k+32U);
      if( e->slot_complete ) accept_end(b,k+31U);
    }
    if( e->kind==FD_ROTOR_SHRED_COMPLETE ) {
      f->complete=1;
      f->slot_complete=(uchar)!!e->slot_complete;
      f->data_complete=(uchar)!!e->data_complete;
      f->is_leader=(uchar)!!e->is_leader;
      b->recovered+=recovered;
    }
    if( e->has_parent && b->turbine && !b->metadata &&
        (b->parent_batch==NIL || e->idx>b->parent_batch) ) {
      parent_changed=1;
      b->parent_slot=e->parent_slot; b->parent_id=e->parent_id; b->parent_batch=e->idx;
    }
    long due=now;
    if( e->kind==FD_ROTOR_SHRED_DATA && e->src==FD_ROTOR_SRC_TURBINE ) due+=r->config.turbine_grace;
    fill(r,b,f,due);
    if( b->generating || b->required!=old_required || parent_changed ) generate(r,b,due);
  }
  if( e->kind==FD_ROTOR_SHRED_COMPLETE || e->has_parent || e->slot_complete ) {
    for( uint i=block_first(r,e->slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) ) {
      rotor_block_t * b=r->blocks+i;
      rotor_fec_t * f=block_fec(r,b,k);
      if( f && !memcmp(f->merkle_root.uc,e->merkle_root.uc,FD_SHRED_MERKLE_NODE_SZ) ) advance_delivery(r,b);
    }
  }
  return FD_ROTOR_ACCEPT;
}

int
fd_rotor_frag_net( fd_rotor_t * r, fd_rotor_net_t const * e, long now ) {
  if( r->root==ULONG_MAX || e->slot<=r->root || fd_hash_check_zero(&e->block_id) ) return FD_ROTOR_IGNORE;
  rotor_block_t * b=block_query(r,e->slot,&e->block_id);
  if( !b ) return FD_ROTOR_IGNORE;
  if( e->kind==AG_REPAIR_KIND_PARENT_FEC_COUNT ) {
    if( !e->fec_count || e->fec_count>r->fec_per_block || e->parent_slot>=e->slot ||
        (fd_hash_check_zero(&e->parent_id) && !(e->parent_slot==r->root && fd_hash_check_zero(&r->root_id))) ) return FD_ROTOR_IGNORE;
    uint end=e->fec_count*32U-1U;
    if( b->metadata ) return b->end==end && b->parent_slot==e->parent_slot && fd_hash_eq(&b->parent_id,&e->parent_id);
    if( !accept_end(b,end) ) return FD_ROTOR_IGNORE;
    b->metadata=1;
    b->parent_slot=e->parent_slot; b->parent_id=e->parent_id;
    generate(r,b,now);
  } else if( e->kind==AG_REPAIR_KIND_FEC_ROOT ) {
    if( !b->metadata || e->fec_idx%32U || e->fec_idx>=b->required ) return FD_ROTOR_IGNORE;
    fd_hash_t mr={0}; memcpy(mr.uc,e->root_prefix,FD_SHRED_MERKLE_NODE_SZ);
    if( fd_hash_check_zero(&mr) ) return FD_ROTOR_IGNORE;
    rotor_fec_t * f=block_fec(r,b,e->fec_idx);
    if( f && memcmp(f->merkle_root.uc,mr.uc,FD_SHRED_MERKLE_NODE_SZ) ) return FD_ROTOR_IGNORE;
    if( !f ) f=fec_new(r,b,e->fec_idx,&mr);
    if( !f ) return FD_ROTOR_IGNORE; /* same root at a different slot/position */
    fill(r,b,f,now);
  } else return FD_ROTOR_IGNORE;
  advance_delivery(r,b);
  return FD_ROTOR_ACCEPT;
}

int
fd_rotor_frag_votor( fd_rotor_t * r, ulong slot, fd_hash_t const * id, int is_final, long now ) {
  if( r->root==ULONG_MAX || slot<=r->root || fd_hash_check_zero(id) ) return FD_ROTOR_IGNORE;
  if( is_final && (r->borrowed || r->redeliver_cnt) ) return FD_ROTOR_AGAIN;
  for( uint i=block_first(r,slot); i!=NIL; i=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks) )
    if( r->blocks[i].final && !fd_hash_eq(&r->blocks[i].id,id) ) return FD_ROTOR_IGNORE;
  rotor_block_t * winner=block_query(r,slot,id);
  if( is_final ) {
    for( uint i=block_first(r,slot); i!=NIL; ) {
      rotor_block_t * b=r->blocks+i;
      uint next=(uint)rotor_blocks_idx_next_const(i,NIL,r->blocks);
      if( b!=winner ) block_drop(r,b);
      i=next;
    }
  }
  if( !winner ) winner=block_new(r,slot,id,now);
  if( !winner ) return FD_ROTOR_AGAIN;
  if( is_final ) winner->final=1;
  generate(r,winner,now);
  advance_delivery(r,winner);
  if( is_final ) {
    for( rotor_blocks_iter_t it=rotor_blocks_iter_init(r->block_map,r->blocks);
         !rotor_blocks_iter_done(it,r->block_map,r->blocks);
         it=rotor_blocks_iter_next(it,r->block_map,r->blocks) ) {
      rotor_block_t * child=rotor_blocks_iter_ele(it,r->block_map,r->blocks);
      if( child->slot>slot && child->parent_slot==slot ) {
        if( parent_impossible(r,child) ) child->cancel=1;
        advance_delivery(r,child);
      }
    }
  }
  return FD_ROTOR_ACCEPT;
}

static void
apply_root( fd_rotor_t * r, long now ) {
  if( !r->pending_root || r->out_head!=NIL || r->borrowed || r->redeliver_cnt ) return;
  ulong slot=r->pending_slot;
  fd_hash_t id=r->pending_id;
  /* Iteration cannot survive map removal, so gather the bounded block list. */
  ulong n=0;
  for( rotor_blocks_iter_t it=rotor_blocks_iter_init(r->block_map,r->blocks);
       !rotor_blocks_iter_done(it,r->block_map,r->blocks);
       it=rotor_blocks_iter_next(it,r->block_map,r->blocks) ) {
    rotor_block_t * b=rotor_blocks_iter_ele(it,r->block_map,r->blocks);
    if( b->slot<=slot ) r->stack[n++]=(uint)(b-r->blocks);
  }
  for( ulong i=0; i<n; i++ ) block_drop(r,r->blocks+r->stack[i]);
  rotor_block_t * b=block_new(r,slot,&id,now);
  FD_TEST(b);
  generation_remove(r,b);
  b->turbine=0; b->end=0U; b->delivered=1U; b->connected=1;
  b->parent_slot=slot; b->parent_id=id;
  r->root=slot; r->root_id=id;
  r->highest_delivered=fd_ulong_max(r->highest_delivered,slot);
  if( r->seed_cursor<=slot ) { r->seed_cursor=slot+1UL; r->seed_phase=0; }
  r->pending_root=0;
  for( rotor_blocks_iter_t it=rotor_blocks_iter_init(r->block_map,r->blocks);
       !rotor_blocks_iter_done(it,r->block_map,r->blocks);
       it=rotor_blocks_iter_next(it,r->block_map,r->blocks) ) {
    rotor_block_t * child=rotor_blocks_iter_ele(it,r->block_map,r->blocks);
    if( child==b ) continue;
    child->connected=0;
    if( parent_impossible(r,child) ) child->cancel=1;
  }
  advance_delivery(r,b);
}

int
fd_rotor_frag_replay_root( fd_rotor_t * r, ulong slot, fd_hash_t const * id, long now ) {
  if( r->root==ULONG_MAX || slot<=r->root || !block_query(r,slot,id) ) return FD_ROTOR_IGNORE;
  if( r->pending_root && slot<r->pending_slot ) return FD_ROTOR_IGNORE;
  r->pending_root=1; r->pending_slot=slot; r->pending_id=*id;
  apply_root(r,now);
  return FD_ROTOR_ACCEPT;
}

void fd_rotor_frag_replay_missing( fd_rotor_t * r ) { r->missing=1; }

void
fd_rotor_set_block_id_only( fd_rotor_t * r, int enabled, long now ) {
  if( !!enabled==!!r->config.block_id_only ) return;
  r->config.block_id_only=!!enabled;
  if( enabled ) return;
  r->seed_cursor=r->root==ULONG_MAX ? 0UL : r->root+1UL;
  r->seed_phase=0;
  for( rotor_blocks_iter_t it=rotor_blocks_iter_init(r->block_map,r->blocks);
       !rotor_blocks_iter_done(it,r->block_map,r->blocks);
       it=rotor_blocks_iter_next(it,r->block_map,r->blocks) ) {
    rotor_block_t * b=rotor_blocks_iter_ele(it,r->block_map,r->blocks);
    if( b->slot<=r->root || !b->turbine ) continue;
    generate(r,b,now);
    /* Explicit configuration change reconsiders suppressed data work. */
    for( uint k=0; k<b->required; k+=32U ) {
      rotor_fec_t * f=block_fec(r,b,k);
      if( f ) fill(r,b,f,now);
    }
  }
}

void
fd_rotor_advance( fd_rotor_t * r, long now, ulong peer_cnt, ulong budget ) {
  apply_root(r,now);
  if( r->root==ULONG_MAX ) return;
  /* A continuation is bounded by one FEC position per step.  Rotation
     gives sibling versions equal generation opportunities.  A full
     metadata queue leaves this cursor pending; shred enqueue failure
     advances it, as required by the explicit drop policy. */
  ulong gen_budget=(budget+1UL)/2UL;
  while( gen_budget-- && r->gen_head!=NIL ) {
    rotor_block_t * b=r->blocks+r->gen_head;
    uint cursor=b->gen_cursor;
    int done=0;
    if( b->slot<=r->root || b->cancel || suppressed(r,b) ) done=1;
    else if( parent_impossible(r,b) ) { b->cancel=1; done=1; }
    else if( cursor==0U ) {
      if( b->parent_slot!=ULONG_MAX && !parent_present(r,b) ) {
        if( !block_new(r,b->parent_slot,&b->parent_id,now) ) {
          /* Keep parent discovery pending when block capacity is full. */
          schedule(r,b,b->slot,b->turbine ? FD_REPAIR_KIND_ORPHAN : AG_REPAIR_KIND_PARENT_FEC_COUNT,0U,now);
        }
      }
      if( b->turbine ) {
        if( b->parent_slot==ULONG_MAX ) schedule(r,b,b->slot,FD_REPAIR_KIND_SHRED,0U,now);
        b->gen_cursor++;
      } else if( b->metadata || schedule(r,b,b->slot,AG_REPAIR_KIND_PARENT_FEC_COUNT,0U,now) ) b->gen_cursor++;
    } else if( cursor==1U ) {
      if( !b->turbine || parent_present(r,b) || schedule(r,b,b->slot,FD_REPAIR_KIND_ORPHAN,0U,now) ) b->gen_cursor++;
    } else if( cursor==2U ) {
      if( !b->turbine || b->end!=NIL || schedule(r,b,b->slot,FD_REPAIR_KIND_HIGHEST_SHRED,0U,b->first_ts+r->config.highest_delay) ) b->gen_cursor++;
    } else {
      uint idx=(cursor-3U)*32U;
      if( idx>=b->required ) done=1;
      else {
        rotor_fec_t * f=block_fec(r,b,idx);
        if( f ) b->gen_cursor++;
        else if( b->turbine ) { schedule(r,b,b->slot,FD_REPAIR_KIND_SHRED,idx,b->range_due); b->gen_cursor++; }
        else if( !b->metadata || schedule(r,b,b->slot,AG_REPAIR_KIND_FEC_ROOT,idx,b->range_due) ) b->gen_cursor++;
      }
    }
    int parent_pending=!b->cancel && b->parent_slot!=ULONG_MAX && !parent_present(r,b) && !parent_impossible(r,b);
    generation_remove(r,b);
    if( !done || parent_pending ) {
      long due=b->range_due;
      uint next=done ? 0U : b->gen_cursor;
      generate(r,b,due);
      b->gen_cursor=next;
    }
  }
  ulong seed_budget=budget/2UL;
  if( r->config.block_id_only || peer_cnt<r->config.seed_peer_min || r->first_turbine==ULONG_MAX ) return;
  ulong limit=r->root+fd_ulong_min(r->config.seed_window,ULONG_MAX-r->root-1UL);
  limit=fd_ulong_min(limit,r->first_turbine);
  while( seed_budget-- && r->seed_cursor<=limit ) {
    ulong slot=r->seed_cursor;
    if( block_first(r,slot)!=NIL ) { r->seed_cursor++; r->seed_phase=0; continue; }
    if( !r->seed_phase ) {
      schedule(r,NULL,slot,FD_REPAIR_KIND_SHRED,0U,now);
      r->seed_phase=1;
    } else if( schedule(r,NULL,slot,FD_REPAIR_KIND_HIGHEST_SHRED,0U,now) ) {
      r->seed_phase=0; r->seed_cursor++;
    } else break;
  }
}

int
fd_rotor_request_next( fd_rotor_t * r, long now, ulong budget, fd_rotor_request_t * out, fd_rotor_token_t * token ) {
  while( budget-- ) {
    uint qi=r->next_queue;
    rotor_queue_t * q=r->queue+qi;
    if( !q->cnt || q->pool[q->heap[0]].due>now ) { qi^=1U; q=r->queue+qi; }
    if( !q->cnt || q->pool[q->heap[0]].due>now ) return 0;
    r->next_queue=qi^1U;
    uint idx=heap_pop(q);
    rotor_job_t * j=q->pool+idx;
    if( !job_needed(r,j,out) ) { r->stale++; job_release(q,j); continue; }
    j->state=2;
    j->reservation=++r->reservation;
    *token=(fd_rotor_token_t){ .generation=j->reservation, .idx=idx, .queue=qi };
    return 1;
  }
  return 0;
}

void
fd_rotor_request_sent( fd_rotor_t * r, fd_rotor_token_t token, int sent, long now ) {
  if( token.queue>1U ) return;
  rotor_queue_t * q=r->queue+token.queue;
  if( token.idx>=q->max ) return;
  rotor_job_t * j=q->pool+token.idx;
  if( j->state!=2 || j->reservation!=token.generation ) return;
  if( !job_needed(r,j,NULL) || (sent && j->key.block==NIL) ) { job_release(q,j); return; }
  j->state=(uchar)(sent ? 3 : 1);
  j->due=now+(sent ? r->config.retry_delay : 0L);
  heap_push(q,token.idx);
}

int
fd_rotor_delivery_next( fd_rotor_t * r, fd_rotor_delivery_t * out ) {
  if( r->out_head==NIL ) return 0;
  if( r->missing && !r->borrowed && !r->redeliver_cnt ) {
    rotor_block_t * b=r->blocks+r->fecs[r->out_head].block;
    while( b && b->slot>r->root ) {
      FD_TEST(r->redeliver_cnt<r->config.block_max);
      r->redeliver[r->redeliver_cnt++]=(uint)(b-r->blocks);
      b=block_query(r,b->parent_slot,&b->parent_id);
    }
    r->redeliver_fec=0U;
    r->missing=0;
  }
  if( !r->borrowed ) {
    while( r->redeliver_cnt ) {
      rotor_block_t * b=r->blocks+r->redeliver[r->redeliver_cnt-1UL];
      uint limit=r->fecs[r->out_head].block==(uint)(b-r->blocks) ? r->fecs[r->out_head].idx : b->delivered;
      if( r->redeliver_fec>=limit ) { r->redeliver_cnt--; r->redeliver_fec=0U; continue; }
      rotor_fec_t * f=block_fec(r,b,r->redeliver_fec);
      FD_TEST(f && f->complete);
      r->borrowed_fec=(uint)(f-r->fecs);
      r->borrowed_redelivery=1;
      break;
    }
    if( !r->redeliver_cnt ) { r->borrowed_fec=r->out_head; r->borrowed_redelivery=0; }
    r->borrowed=1;
  }
  rotor_fec_t * f=r->fecs+r->borrowed_fec;
  rotor_block_t * b=r->blocks+f->block;
  *out=(fd_rotor_delivery_t){ .slot=b->slot, .block_id=b->id, .parent_slot=b->parent_slot,
    .parent_id=b->parent_id, .fec_idx=f->idx, .merkle_root=f->merkle_root,
    .turbine=b->turbine, .slot_complete=b->end!=NIL && f->idx+31U==b->end,
    .data_complete=f->data_complete, .is_leader=f->is_leader, .redelivery=r->borrowed_redelivery };
  return 1;
}

void
fd_rotor_delivery_pop( fd_rotor_t * r, long now ) {
  FD_TEST(r->borrowed);
  if( r->borrowed_redelivery ) r->redeliver_fec+=32U;
  else out_remove(r,r->fecs+r->borrowed_fec);
  r->borrowed=0;
  apply_root(r,now);
}

int
fd_rotor_block_query( fd_rotor_t * r, ulong slot, fd_hash_t const * id, fd_rotor_block_info_t * out ) {
  rotor_block_t * b=block_query(r,slot,id);
  if( !b ) return 0;
  *out=(fd_rotor_block_info_t){ .block_id=b->id, .parent_slot=b->parent_slot, .required_shreds=b->required,
    .complete_idx=b->end, .delivered_shreds=b->delivered, .recovered_cnt=b->recovered,
    .turbine=b->turbine, .cancel=b->cancel, .final=b->final, .connected=b->connected };
  return 1;
}

int
fd_rotor_fec_query( fd_rotor_t * r, ulong slot, fd_hash_t const * id, uint idx, fd_rotor_fec_info_t * out ) {
  rotor_block_t * b=block_query(r,slot,id);
  if( !b || idx%32U ) return 0;
  rotor_fec_t * f=block_fec(r,b,idx);
  if( !f ) return 0;
  *out=(fd_rotor_fec_info_t){ .merkle_root=f->merkle_root, .received=root_query(r,&f->merkle_root)->received,
    .complete=f->complete, .owner=f->owner };
  return 1;
}

void
fd_rotor_stats( fd_rotor_t const * r, fd_rotor_stats_t * out ) {
  *out=(fd_rotor_stats_t){ .blocks=rotor_bpool_used(r->blocks), .fecs=rotor_fpool_used(r->fecs),
    .shred_requests=rotor_jpool_used(r->queue[0].pool), .other_requests=rotor_jpool_used(r->queue[1].pool),
    .other_request_max=r->queue[1].max, .shred_dropped=r->dropped, .stale_popped=r->stale,
    .highest_delivered=r->highest_delivered };
}

int
fd_rotor_verify( fd_rotor_t * r ) {
  if( !r || r->magic!=ROTOR_MAGIC ) return -1;
  if( rotor_blocks_verify(r->block_map,r->config.block_max,r->blocks) ||
      rotor_roots_verify(r->roots,r->config.block_max*r->fec_per_block,r->fecs) ) return -1;
  ulong fec_cnt=0;
  for( rotor_blocks_iter_t it=rotor_blocks_iter_init(r->block_map,r->blocks);
       !rotor_blocks_iter_done(it,r->block_map,r->blocks);
       it=rotor_blocks_iter_next(it,r->block_map,r->blocks) ) {
    rotor_block_t * b=rotor_blocks_iter_ele(it,r->block_map,r->blocks);
    if( b->slot<r->root || !b->generation || b->required>r->config.max_shreds ) return -1;
    if( b->slot==r->root ) continue;
    if( b->parent_slot!=ULONG_MAX && b->parent_slot>=b->slot ) return -1;
    if( b->end!=NIL && (b->end+1U!=b->required || b->end%32U!=31U) ) return -1;
    for( uint k=0; k<r->fec_per_block; k++ ) {
      rotor_fec_t * f=block_fec(r,b,k*32U);
      if( !f ) continue;
      fec_cnt++;
      rotor_fec_t * o=root_query(r,&f->merkle_root);
      if( !o || !o->owner || (f->owner && o!=f) || (!f->owner && f->received) ||
          o->idx!=k*32U || r->blocks[o->block].slot!=b->slot || f->block!=(uint)(b-r->blocks) ||
          f->complete!=o->complete || (f->complete && o->received!=UINT_MAX) ) return -1;
    }
  }
  if( fec_cnt!=rotor_fpool_used(r->fecs) ) return -1;
  for( uint qi=0; qi<2; qi++ ) {
    rotor_queue_t * q=r->queue+qi;
    if( q->cnt>rotor_jpool_used(q->pool) || rotor_jobs_verify(q->map,q->max,q->pool) ) return -1;
    for( ulong i=0; i<q->cnt; i++ ) {
      uint idx=q->heap[i];
      if( idx>=q->max || q->pool[idx].heap_pos!=i || q->pool[idx].state==2 || !q->pool[idx].state ) return -1;
      if( i && job_before(q,idx,q->heap[(i-1UL)/2UL]) ) return -1;
    }
  }
  ulong n=0;
  uint prev=NIL;
  for( uint i=r->out_head; i!=NIL; i=r->fecs[i].out_next ) {
    if( ++n>fec_cnt || !r->fecs[i].queued || !r->fecs[i].complete || r->fecs[i].out_prev!=prev ) return -1;
    prev=i;
  }
  if( prev!=r->out_tail ) return -1;
  n=0; prev=NIL;
  for( uint i=r->gen_head; i!=NIL; i=r->blocks[i].gen_next ) {
    if( ++n>rotor_bpool_used(r->blocks) || !r->blocks[i].generating || r->blocks[i].gen_prev!=prev ) return -1;
    prev=i;
  }
  return prev==r->gen_tail ? 0 : -1;
}
