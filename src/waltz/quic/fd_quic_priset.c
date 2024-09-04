/* #include this file in fd_quic.c */

/* This defines priset, a set of connections ordered by priority */
#include "fd_quic_priset.h"

/* Compare function */
/* Order such that leftmost nodes have lowest priority */
/* and are first to be reclaimed when needed */
static int
priset_cmp_impl( const fd_quic_priset_key_t * left,
                 const fd_quic_priset_key_t * right ) {
  int cmp_has_stream =   (int)left->has_at_least_one_stream
                       - (int)right->has_at_least_one_stream;
  if( cmp_has_stream != 0 ) {
    return cmp_has_stream;
  }

  /* TODO determine priority for connections */

  return 0;
}

#define POOL_T        fd_quic_priset_node_t
#define POOL_NAME     priset_pool
#include "../../util/tmpl/fd_pool.c"

#define TREAP_T        fd_quic_priset_node_t
#define TREAP_QUERY_T  fd_quic_priset_key_t *
#define TREAP_NAME     priset
#define TREAP_CMP(u,v) priset_cmp_impl( (u), &(v)->key )
#define TREAP_LT(u,v)  ( priset_cmp_impl( &(u)->key, &(v)->key ) < 0 )
#include "../../util/tmpl/fd_treap.c"

FD_PROTOTYPES_BEGIN

static void
priset_key_init( fd_quic_priset_key_t *       priset_key,
                 fd_quic_conn_t const *       conn,
                 ulong                        now,
                 fd_qos_t *                   qos,
                 fd_qos_entry_t *             qos_entry );

static void
priset_conn_insert( fd_quic_state_t * state,
                    fd_quic_conn_t *  conn );

static void
priset_conn_remove( fd_quic_state_t * state,
                    fd_quic_conn_t *  conn );

static void
priset_key_update(  fd_quic_state_t * state,
                    fd_quic_conn_t *  conn );

static float
ema_fetch( float * ema,
           long    last_update_time,
           long    now );

static void
ema_update( float * ema,
            float   addend,
            long    last_update_time,
            long    now );

FD_PROTOTYPES_END


/* Initializes the priority ordering key based on connection */
/* and ip address info */
/* `qos_entry` is to avoid an extra lookup in the event caller */
/* has already done the work */
static void
priset_key_init( fd_quic_priset_key_t *       priset_key,
                 fd_quic_conn_t const *       conn,
                 ulong                        now,
                 fd_qos_t *                   qos,
                 fd_qos_entry_t *             qos_entry ) {
  /* ensure whole structure is zero */
  memset( priset_key, 0, sizeof( *priset_key ) );

  /* fetch IP address info from qos map and use it to populate */
  /* the related priority fields */
  if( FD_LIKELY( !qos_entry ) ) {
  FD_DEBUG( if( conn->orig_peer_ip_addr == 0 ) __asm__( "int $3" ); )
  FD_DEBUG( FD_LOG_WARNING(( "%s quic %s query_forced on %08x", __func__, conn->server ? "SERVER" : "CLIENT", conn->orig_peer_ip_addr )) );
    qos_entry = fd_qos_query_forced( qos, conn->orig_peer_ip_addr );
  }

  /* we should always have a valid `qos_entry` here */
  FD_TEST( qos_entry );

  fd_qos_set_priority( &priset_key->qos_prio, &qos_entry->value.stats );

  /* set important values */

  ulong conn_idx                  = conn->conn_idx;
  ulong last_completed_stream     = conn->conn_stats.last_completed_stream;
  int   has_at_least_one_stream   = conn->conn_stats.tot_completed_streams > 0UL;
  ulong last_stream_activity_time = has_at_least_one_stream
                                    ? last_completed_stream
                                    : ~0UL;

  priset_key->has_at_least_one_stream   = (uchar)has_at_least_one_stream;
  priset_key->last_stream_activity_time = last_stream_activity_time;
  priset_key->conn_idx                  = conn_idx; /* conn_idx to identify specific */
                                                    /* connection */
  priset_key->last_updated_time         = now;
  /* TODO other members */
}

/* inserts connection into priority set */
/* updates conn->priset_key based on conn->conn_stats */
static void
__attribute__((__used__))
priset_conn_insert( fd_quic_state_t * state,
                    fd_quic_conn_t *  conn ) {
  /* only server connections are in the priority set */
  if( FD_UNLIKELY( !conn->server ) ) return;

  /* insert in connection priority set */
  priset_key_init( &conn->priset_key, conn, state->now, state->qos, NULL );
  fd_quic_priset_node_t * priset_node = priset_pool_ele_acquire( state->priset_pool );

  /* set key on priset_node */
  memcpy( &priset_node->key, &conn->priset_key, sizeof( priset_node->key ) );

  /* choose random value for prio */
  /* TODO why do we keep joining and leaving? */
  fd_rng_t * rng = fd_rng_join( state->_rng );
  priset_node->prio = fd_rng_ulong( rng );
  fd_rng_leave( rng );
  priset_ele_insert( state->priset, priset_node, state->priset_pool );

  priset_node->conn = conn;
}

static void
__attribute__((__used__))
priset_conn_remove( fd_quic_state_t * state,
                    fd_quic_conn_t *  conn ) {
  /* only server connections are in the priority set */
  if( FD_UNLIKELY( !conn->server ) ) return;

  /* remove conn from priset */
  fd_quic_priset_t *      priset      = state->priset;
  fd_quic_priset_node_t * priset_pool = state->priset_pool;

  /* find node */
  fd_quic_priset_node_t * priset_node =
              priset_ele_query( priset,
                                &conn->priset_key,
                                priset_pool );
  FD_TEST( priset_node );
  priset_ele_remove( priset, priset_node, priset_pool );

  /* return node to pool */
  priset_pool_ele_release( priset_pool, priset_node );
}

/* moves a node in the treap in response to key update */
/* conn->priset_key is updated based off the values in conn->conn_stats */
static void
__attribute__((__used__))
priset_key_update( fd_quic_state_t *            state,
                   fd_quic_conn_t *             conn ) {
  /* only server connections are in the priority set */
  if( FD_UNLIKELY( !conn->server ) ) return;

  /* remove conn from priset */
  fd_quic_priset_t *      priset      = state->priset;
  fd_quic_priset_node_t * priset_pool = state->priset_pool;

  /* find node */
  fd_quic_priset_node_t * priset_node =
              priset_ele_query( priset,
                                &conn->priset_key,
                                priset_pool );
  FD_TEST( priset_node );
  priset_ele_remove( priset, priset_node, priset_pool );

  /* don't return node to pool */
  /* instead reuse it for the insert */

  /* insert in connection priority set */

  /* initialize key based off data in conn->conn_stats */
  priset_key_init( &conn->priset_key, conn, state->now, state->qos, NULL );

  /* set key on priset_node */
  memcpy( &priset_node->key, &conn->priset_key, sizeof( priset_node->key ) );

  /* choose random value for prio */
  /* TODO why do we keep joining and leaving? */
  fd_rng_t * rng = fd_rng_join( state->_rng );
  priset_node->prio = fd_rng_ulong( rng );
  fd_rng_leave( rng );
  priset_ele_insert( state->priset, priset_node, state->priset_pool );
}

static fd_quic_conn_t *
fd_quic_query_low_pri( fd_quic_state_t * state ) {
  fd_quic_priset_t *      priset = state->priset;
  fd_quic_priset_node_t * pool   = state->priset_pool;
  priset_fwd_iter_t iter = priset_fwd_iter_init( priset, pool );
  if( FD_UNLIKELY( priset_fwd_iter_done( iter ) ) ) return NULL;

  /* extract the element */
  fd_quic_priset_node_t * node = priset_fwd_iter_ele( iter, pool );
  FD_TEST( node );
  return node->conn;
}


/* fetch an ema after updating with decay */
/* ema value is decayed by now - last_update_time, unless */
/* last_update_time == 0, in which case the old value is considered */
/* zero */
static float
ema_fetch( float * ema, long last_update_time, long now ) {
  if( FD_UNLIKELY( last_update_time == 0 ) ) {
    /* no prior value, so return 0.0f */
    return 0.0f;
  }

  /* the lapsed time is used for the decay */
  long delta_time = now - last_update_time;

  float decay = FD_QOS_EMA_DECAY;

  /* calc scale factor from time and decay */
  float ema_scale = expf( decay * (float)delta_time );

  return ema_scale * *ema;
}

/* update ema with new value and decay */
/* old ema value is decayed by now - last_update_time, unless */
/* last_update_time == 0, in which case the old value is considered */
/* zero
 * The new value is then added */
/* Reading the value entails decaying the ema by the duration since */
/* the last update */
static void
ema_update( float * ema, float addend, long last_update_time, long now ) {
  float decayed_ema = ema_fetch( ema, last_update_time, now );

  *ema = decayed_ema + addend;
}
