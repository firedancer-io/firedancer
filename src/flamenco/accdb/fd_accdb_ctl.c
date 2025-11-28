/* fd_accdb_ctl.c is a command-line debugging tool for interacting with
   a Firedancer account database. */

#include "../../vinyl/fd_vinyl.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../util/cstr/fd_cstr.h"
#include "../../util/pod/fd_pod.h"
#include <ctype.h>
#include <stddef.h> /* offsetof */
#include <stdio.h>

/* req_info contains various request metadata R/W mapped into the vinyl
   tile. */

struct req_info {
  fd_vinyl_key_t  key[1];
  ulong           val_gaddr[1];
  schar           err[1];
  fd_vinyl_comp_t comp[1];
};

typedef struct req_info req_info_t;

/* The client class contains local handles to client-related vinyl
   objects. */

struct client {
  fd_vinyl_rq_t * rq;
  fd_vinyl_cq_t * cq;
  ulong           req_id;
  ulong           link_id;

  fd_vinyl_meta_t * meta;

  req_info_t * req_info;
  ulong        req_info_gaddr;
  fd_wksp_t *  val_wksp;
  fd_wksp_t *  client_wksp;

  /* Vinyl client status */
  ulong quota_rem;
  ulong cq_seq;
};

typedef struct client client_t;

static char const bin2hex[ 16 ] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

static void
hexdump( uchar const * data,
         uint          sz ) {
  ulong sz_align = fd_ulong_align_dn( sz, 16UL );
  uint i;
  for( i=0U; i<sz_align; i+=16U ) {
    char line[ 80 ];
    char * p = fd_cstr_init( line );
    p = fd_cstr_append_uint_as_hex( p, '0', i, 7UL );
    p = fd_cstr_append_text( p, ":  ", 3UL );
    for( ulong j=0UL; j<16UL; j++ ) {
      p = fd_cstr_append_char( p, bin2hex[ data[ i+j ]>>4 ] );
      p = fd_cstr_append_char( p, bin2hex[ data[ i+j ]&15 ] );
      p = fd_cstr_append_char( p, ' ' );
    }
    p = fd_cstr_append_char( p, ' ' );
    for( ulong j=0UL; j<16UL; j++ ) {
      int c = data[ i+j ];
      p = fd_cstr_append_char( p, fd_char_if( fd_isalnum( c ) | fd_ispunct( c ) | (c==' '), (char)c, '.' ) );
    }
    p = fd_cstr_append_char( p, '\n' );
    ulong len = (ulong)( p-line );
    fd_cstr_fini( p );
    fwrite( line, 1UL, len, stdout );
  }
  if( sz ) {
    char line[ 80 ];
    char * p = fd_cstr_init( line );
    p = fd_cstr_append_uint_as_hex( p, '0', i, 7UL );
    p = fd_cstr_append_text( p, ":  ", 3UL );
    for( ; i<sz; i++ ) {
      p = fd_cstr_append_char( p, bin2hex[ data[ i ]>>4 ] );
      p = fd_cstr_append_char( p, bin2hex[ data[ i ]&15 ] );
      p = fd_cstr_append_char( p, ' ' );
    }
    p = fd_cstr_append_char( p, '\n' );
    ulong len = (ulong)( p-line );
    fd_cstr_fini( p );
    fwrite( line, 1UL, len, stdout );
  }
  fflush( stdout );
}

static void
client_query( client_t * client,
              char **    arg,
              ulong      arg_cnt ) {
  req_info_t * req_info = client->req_info;
  if( FD_UNLIKELY( arg_cnt!=1UL ) ) {
    puts( "ERR(query): invalid query command, usage is \"query <account address>\"" );
    return;
  }
  char const * acc_addr_b58 = arg[0];
  fd_vinyl_key_t * acc_key = req_info->key;
  if( FD_UNLIKELY( !fd_base58_decode_32( acc_addr_b58, acc_key->uc ) ) ) {
    puts( "ERR(query): invalid account address" );
    return;
  }

  /* Send an acquire request */

  req_info->comp->seq = 0UL;
  fd_vinyl_rq_send(
      client->rq,
      client->req_id++,
      client->link_id,
      FD_VINYL_REQ_TYPE_ACQUIRE, /* type */
      0UL, /* flags */
      1UL,
      FD_VINYL_VAL_MAX, /* val_max */
      /* key_gaddr       */ client->req_info_gaddr + offsetof( req_info_t, key       ),
      /* val_gaddr_gaddr */ client->req_info_gaddr + offsetof( req_info_t, val_gaddr ),
      /* err_gaddr       */ client->req_info_gaddr + offsetof( req_info_t, err       ),
      /* comp_gaddr      */ client->req_info_gaddr + offsetof( req_info_t, comp      )
  );

  /* Poll direct completion for acquire (not via CQ) */

  fd_vinyl_comp_t * comp = req_info->comp;
  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  int acquire_err = req_info->err[0];
  if( acquire_err==FD_VINYL_SUCCESS ) {
    fd_account_meta_t const * val  = fd_wksp_laddr_fast( client->val_wksp, req_info->val_gaddr[0] );
    void const *              data = (void const *)( val+1 );

    FD_BASE58_ENCODE_32_BYTES( val->owner, owner_b58 );
    printf(
        "\n"
        "Public Key: %s\n"
        "Balance: %lu.%lu SOL\n"
        "Owner: %s\n"
        "Executable: %s\n"
        "Length: %u (0x%x) bytes\n",
        acc_addr_b58,
        val->lamports / 1000000000UL,
        val->lamports % 1000000000UL,
        owner_b58,
        val->executable ? "true" : "false",
        val->dlen,
        val->dlen
    );
    hexdump( data, val->dlen );

    /* Send a release request */

    req_info->comp->seq = 0UL;
    fd_vinyl_rq_send(
        client->rq,
        client->req_id++,
        client->link_id,
        FD_VINYL_REQ_TYPE_RELEASE, /* type */
        0UL, /* flags */
        1UL,
        FD_VINYL_VAL_MAX, /* val_max */
        0UL,
        /* val_gaddr_gaddr */ client->req_info_gaddr + offsetof( req_info_t, val_gaddr ),
        /* err_gaddr       */ client->req_info_gaddr + offsetof( req_info_t, err       ),
        /* comp_gaddr      */ client->req_info_gaddr + offsetof( req_info_t, comp      )
    );

    /* Poll direct completion for release (not via CQ) */

    while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
    FD_TEST( req_info->err[0]==FD_VINYL_SUCCESS );

    puts( "" );
  } else if( acquire_err==FD_VINYL_ERR_KEY ) {
    printf(
        "\n"
        "Public Key: %s\n"
        "Account does not exist\n"
        "\n",
        acc_addr_b58
    );
  } else {
    FD_LOG_ERR(( "Vinyl acquire request failed (err %i-%s)", acquire_err, fd_vinyl_strerror( acquire_err ) ));
  }
}

typedef struct batch_req batch_req_t;
struct batch_req {
  batch_req_t * prev;
  batch_req_t * next;

  ulong key_off;
  ulong err_off;
  ulong val_gaddr_off;

  ulong req_id;
};

static ulong
batch_req_align( void ) {
  return fd_ulong_max( alignof(batch_req_t), alignof(fd_vinyl_key_t) );
}

static ulong
batch_req_footprint( ulong depth ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(batch_req_t),          sizeof(batch_req_t)    );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vinyl_key_t), depth*sizeof(fd_vinyl_key_t) );
  l = FD_LAYOUT_APPEND( l, alignof(schar),          depth*sizeof(schar)          );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),          depth*sizeof(ulong)          );
  return FD_LAYOUT_FINI( l, batch_req_align() );
}

static batch_req_t *
batch_req_new( void * mem,
               ulong  depth ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  batch_req_t *    req       = FD_SCRATCH_ALLOC_APPEND( l, alignof(batch_req_t),    sizeof(batch_req_t)          );
  fd_vinyl_key_t * key       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vinyl_key_t), depth*sizeof(fd_vinyl_key_t) );
  schar *          err       = FD_SCRATCH_ALLOC_APPEND( l, alignof(schar),          depth*sizeof(schar)          );
  ulong *          val_gaddr = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),          depth*sizeof(ulong)          );
  FD_SCRATCH_ALLOC_FINI( l, batch_req_align() );

  *req = (batch_req_t) {
    .prev = NULL,
    .next = NULL,

    .key_off       = (ulong)key       - (ulong)mem,
    .err_off       = (ulong)err       - (ulong)mem,
    .val_gaddr_off = (ulong)val_gaddr - (ulong)mem
  };
  return req;
}

static inline fd_vinyl_key_t *
batch_req_key( batch_req_t * req ) {
  return (fd_vinyl_key_t *)( (ulong)req + req->key_off );
}

static inline schar *
batch_req_err( batch_req_t * req ) {
  return (schar *)( (ulong)req + req->err_off );
}

static inline ulong *
batch_req_val_gaddr( batch_req_t * req ) {
  return (ulong *)( (ulong)req + req->val_gaddr_off );
}

struct bench_query_rand {
  batch_req_t * req_free;     /* free entries */
  batch_req_t * req_wait_lo;  /* list of entries awaiting completion */
  batch_req_t * req_wait_hi;
  ulong         batch_depth;

  ulong            iter_rem;
  fd_vinyl_key_t * sample;
  ulong            sample_idx;
  ulong            sample_max;

  ulong found_cnt;
  ulong miss_cnt;
};
typedef struct bench_query_rand bench_query_rand_t;

/* bqr_free_push adds a wait queue entry to the free stack. */

static void
bqr_free_push( bench_query_rand_t * bqr,
               batch_req_t *        req ) {
  req->prev = NULL;
  req->next = bqr->req_free;
  if( bqr->req_free ) bqr->req_free->prev = req;
  bqr->req_free = req;
}

/* bqr_free_pop removes a wait queue entry from the free stack (alloc). */

static batch_req_t *
bqr_free_pop( bench_query_rand_t * bqr ) {
  batch_req_t * req = bqr->req_free;
  bqr->req_free = req->next;
  if( bqr->req_free ) bqr->req_free->prev = NULL;
  req->prev = req->next = NULL;
  return req;
}

/* bqr_wait_push adds a new wait queue entry. */

static void
bqr_wait_push( bench_query_rand_t * bqr,
               batch_req_t *        req ) {
  req->prev        = bqr->req_wait_hi;
  req->next        = NULL;
  if( bqr->req_wait_hi ) bqr->req_wait_hi->next = req;
  bqr->req_wait_hi = req;
  if( !bqr->req_wait_lo ) bqr->req_wait_lo = req;
}

/* bqr_wait_pop removes the oldest wait queue entry. */

static batch_req_t *
bqr_wait_pop( bench_query_rand_t * bqr ) {
  batch_req_t * req = bqr->req_wait_lo;
  bqr->req_wait_lo = req->next;
  req->prev = req->next = NULL;
  if( bqr->req_wait_lo ) bqr->req_wait_lo->prev = NULL;
  else                   bqr->req_wait_hi       = NULL;
  return req;
}

/* bqr_req_release sends a batch RELEASE request for a batch of values.
   Completions arriving for RELEASE will replenish quota. */

static void
bqr_req_release( client_t *           client,
                 bench_query_rand_t * bqr,
                 batch_req_t *        req,
                 uint                 cnt ) {
  FD_CRIT( !req->prev && !req->next, "attempt to release a request that is already free or still pending" );

  schar * err = batch_req_err( req );
  for( uint i=0U; i<cnt; i++ ) err[ i ] = FD_VINYL_SUCCESS;

  ulong req_id          = fd_ulong_set_bit( client->req_id++, 63 );
  ulong link_id         = client->link_id;
  int   type            = FD_VINYL_REQ_TYPE_RELEASE;
  ulong flags           = 0UL;
  ulong batch_cnt       = (ulong)cnt;
  ulong val_gaddr_gaddr = fd_wksp_gaddr_fast( client->client_wksp, batch_req_val_gaddr( req ) );
  ulong err_gaddr       = fd_wksp_gaddr_fast( client->client_wksp, err );
  fd_vinyl_rq_send( client->rq, req_id, link_id, type, flags, batch_cnt, 0UL, 0UL, val_gaddr_gaddr, err_gaddr, 0UL );

  req->req_id = req_id;
  bqr_wait_push( bqr, req );
}

/* bqr_handle_cq handles an ACQUIRE or RELEASE completion. */

static void
bqr_handle_cq( client_t *           client,
               bench_query_rand_t * bqr,
               fd_vinyl_comp_t *    comp ) {
  FD_CRIT( bqr->req_wait_lo, "received completion even though no request is pending" );
  batch_req_t * req = bqr_wait_pop( bqr );
  FD_CRIT( req->req_id==comp->req_id, "received completion for unexpected req_id" );
  FD_CRIT( comp->batch_cnt<=bqr->batch_depth, "corrupt comp->batch_cnt" );

  /* The high bit of the request ID indicates whether this was an
     ACQUIRE or RELEASE request. */
  int const is_release = fd_ulong_extract_bit( comp->req_id, 63 );

  fd_vinyl_key_t * key       = batch_req_key( req );
  ulong *          val_gaddr = batch_req_val_gaddr( req );
  schar *          err       = batch_req_err( req );

  if( !is_release ) {

    uint j=0U;
    for( uint i=0U; i<comp->batch_cnt; i++ ) {
      int e = err[ i ];
      if( FD_UNLIKELY( e!=FD_VINYL_SUCCESS && e!=FD_VINYL_ERR_KEY ) ) {
        FD_LOG_CRIT(( "Unexpected vinyl error %i-%s", e, fd_vinyl_strerror( e ) ));
      }
      if( e==FD_VINYL_SUCCESS ) {
        bqr->found_cnt++;
        key      [ j ] = key[ i ];
        val_gaddr[ j ] = val_gaddr[ i ];
        j++;
      } else {
        bqr->miss_cnt++;
        client->quota_rem++;
      }
    }

    if( j ) bqr_req_release( client, bqr, req, j );
    else    bqr_free_push( bqr, req );

  } else {

    schar * err = batch_req_err( req );
    uint cnt = comp->batch_cnt;
    for( uint i=0U; i<cnt; i++ ) {
      int e = err[ i ];
      if( FD_UNLIKELY( e ) ) {
        FD_LOG_CRIT(( "Unexpected vinyl error for req %u %i-%s", i, e, fd_vinyl_strerror( e ) ));
      }
    }
    client->quota_rem += comp->batch_cnt;
    bqr_free_push( bqr, req );

  }

}

/* bqr_drain_cq drains all completion queue entries. */

static void
bqr_drain_cq( client_t *           client,
              bench_query_rand_t * bqr ) {
  for(;;) {
    fd_vinyl_comp_t comp[1];
    long cq_err = fd_vinyl_cq_recv( client->cq, client->cq_seq, comp );
    if( FD_UNLIKELY( cq_err<0 ) ) {
      FD_LOG_CRIT(( "Vinyl completion queue overrun detected" ));
    }
    if( cq_err>0 ) break;
    bqr_handle_cq( client, bqr, comp );
    client->cq_seq++;
  }
}

/* bqr_req_acquire sends a batch of ACQUIRE requests. */

static void
bqr_req_acquire( client_t *           client,
                 bench_query_rand_t * bqr ) {
  FD_CRIT( bqr->req_free, "attempt to acquire a request when none are free" );
  batch_req_t * req = bqr_free_pop( bqr );
  ulong cnt = bqr->batch_depth;
  if( FD_UNLIKELY( cnt>bqr->iter_rem ) ) cnt = bqr->iter_rem;

  /* Prepare request descriptor */
  fd_vinyl_key_t * key       = batch_req_key      ( req );
  schar *          err       = batch_req_err      ( req );
  ulong *          val_gaddr = batch_req_val_gaddr( req );
  for( ulong i=0UL; i<cnt; i++ ) {
    ulong idx = bqr->sample_idx;
    key      [ i ] = bqr->sample[ idx ];
    err      [ i ] = 0;
    val_gaddr[ i ] = 0UL;
    bqr->sample_idx++;
    if( bqr->sample_idx>=bqr->sample_max ) bqr->sample_idx = 0UL;
  }

  /* Send request */
  ulong req_id          = fd_ulong_clear_bit( client->req_id++, 63 );
  ulong link_id         = client->link_id;
  int   type            = FD_VINYL_REQ_TYPE_ACQUIRE;
  ulong flags           = 0UL;
  ulong key_gaddr       = fd_wksp_gaddr_fast( client->client_wksp, batch_req_key      ( req ) );
  ulong val_gaddr_gaddr = fd_wksp_gaddr_fast( client->client_wksp, batch_req_val_gaddr( req ) );
  ulong err_gaddr       = fd_wksp_gaddr_fast( client->client_wksp, batch_req_err      ( req ) );
  fd_vinyl_rq_send( client->rq, req_id, link_id, type, flags, cnt, 0UL, key_gaddr, val_gaddr_gaddr, err_gaddr, 0UL );

  /* Update quotas */
  bqr->iter_rem     -= cnt;
  client->quota_rem -= cnt;

  req->req_id = req_id;
  bqr_wait_push( bqr, req );
}

/* bench_query_rand_poll sends as many random read requests to vinyl as
   possible.  Returns 1 if there is more work to do, 0 if the benchmark
   is done. */

static int
bench_query_rand_poll( client_t *           client,
                       bench_query_rand_t * bqr ) {
  if( bqr->req_wait_lo ) {
    bqr_drain_cq( client, bqr );
  }
  while( bqr->req_free && bqr->iter_rem ) {
    bqr_req_acquire( client, bqr );
  }
  return (!!bqr->req_wait_lo) | (!!bqr->iter_rem);
}

/* client_bench_query_rand runs a random read benchmark against vinyl.
   Assumes that RQ and CQ are clean and quota_rem==quota_max. */

static void
client_bench_query_rand( client_t * client,
                         int *      pargc,
                         char ***   pargv ) {

  /* Prepare a random query benchmark

     1. Randomly sample keys into an array (--keys)
     2. Inject random keys at a configurable rate (--miss) to exercise
        index query misses
     3. Loop through the sampled keys array until (--iter) queries have
        been submitted, while doing batches of (--batch) keys at a time

     The benchmark loop is pipelined/asynchronous.  The client will
     submit request batches until it is blocked by quota, RQ, or CQ. */

  ulong       batch_depth = fd_env_strip_cmdline_ulong( pargc, pargv, "--batch", NULL,       1UL );
  ulong       key_cnt     = fd_env_strip_cmdline_ulong( pargc, pargv, "--keys",  NULL,  262144UL );
  ulong const iter_cnt    = fd_env_strip_cmdline_ulong( pargc, pargv, "--iter",  NULL, 1048576UL );
  ulong const seed        = fd_env_strip_cmdline_ulong( pargc, pargv, "--seed",  NULL, (ulong)fd_tickcount() );
  float const miss_r      = fd_env_strip_cmdline_float( pargc, pargv, "--miss",  NULL,      0.1f );

  batch_depth = fd_ulong_max( batch_depth, 1UL );
  key_cnt     = fd_ulong_min( key_cnt, UINT_MAX );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_ulong_hash( seed ), 0UL ) );

  fd_vinyl_meta_t * meta      = client->meta;
  ulong const       ele_max   = fd_vinyl_meta_ele_max  ( meta );
  ulong const       probe_max = fd_vinyl_meta_probe_max( meta );

  /* Allocate a huge page backed scratch memory region to back keys */

  ulong            sample_fp       = fd_ulong_align_up( key_cnt*sizeof(fd_vinyl_key_t), FD_SHMEM_HUGE_PAGE_SZ );
  ulong            sample_page_sz  = FD_SHMEM_NORMAL_PAGE_SZ;
  ulong            sample_page_cnt = sample_fp>>FD_SHMEM_NORMAL_LG_PAGE_SZ;
  fd_vinyl_key_t * sample          = fd_shmem_acquire( sample_page_sz, sample_page_cnt, fd_log_cpu_id()  );
  ulong            sample_cnt      = 0UL;
  if( FD_UNLIKELY( !sample ) ) {
    FD_LOG_WARNING(( "Cannot acquire scratch memory to hold %lu vinyl keys (out of memory).  Aborting benchmark", key_cnt ));
    return;
  }

  /* Determine pipeline depth */

  ulong const rq_ele_depth = fd_vinyl_rq_req_cnt ( client->rq )*batch_depth;
  ulong const cq_ele_depth = fd_vinyl_cq_comp_cnt( client->cq )*batch_depth;
  ulong const quota_max    = fd_ulong_min( client->quota_rem, fd_ulong_min( rq_ele_depth, cq_ele_depth ) );
  ulong const batch_max    = ( quota_max + batch_depth - 1UL ) / batch_depth;

  /* Allocate request queue entries */

  ulong req_footprint       = batch_req_footprint( batch_depth );
  ulong req_batch_footprint = batch_max*req_footprint;
  ulong req_laddr           = (ulong)fd_wksp_alloc_laddr( client->client_wksp, batch_req_align(), req_batch_footprint, 1UL );
  if( FD_UNLIKELY( !req_laddr ) ) {
    FD_LOG_WARNING(( "Vinyl client wksp is too small to hold requests.  Aborting benchmark" ));
    fd_shmem_release( sample, sample_page_sz, sample_page_cnt );
    return;
  }
  for( ulong batch_idx=0UL,
             batch_cur=req_laddr;
       batch_idx<quota_max;
       batch_idx++,
       batch_cur+=req_footprint ) {
    batch_req_t * req = batch_req_new( (void *)batch_cur, batch_depth );
    req->prev = batch_idx>0UL           ? (batch_req_t *)( batch_cur - req_footprint ) : NULL;
    req->next = batch_idx+1UL<batch_max ? (batch_req_t *)( batch_cur + req_footprint ) : NULL;
  }
  batch_req_t * req_free = (batch_req_t *)req_laddr; /* free list holding all batch_req */

  /* Sample keys */

  long dt = -fd_log_wallclock();
  uint const miss_u = (uint)fd_ulong_min( (ulong)( (float)UINT_MAX * miss_r ), UINT_MAX );
  for( ulong i=0UL; i<key_cnt; i++ ) {

    if( fd_rng_uint( rng )<miss_u ) {  /* rand key */
      for( uint j=0U; j<32U; j+=4U ) FD_STORE( uint, sample[ i ].uc+j, fd_rng_uint( rng ) );
      continue;
    }

    /* sample a key, linear probe until one found */
    ulong meta_idx = fd_rng_ulong_roll( rng, ele_max );
    ulong probe_rem;
    for( probe_rem=probe_max; probe_rem; probe_rem-- ) {
      fd_vinyl_meta_ele_t const * ele = meta->ele + meta_idx;
      if( FD_LIKELY( fd_vinyl_meta_ele_in_use( ele ) ) ) {
        sample[ i ] = ele->phdr.key;
        sample_cnt++;
        break;
      }
      meta_idx = (meta_idx+1UL) % ele_max;
    }
    if( !probe_rem ) {  /* no key found (low hashmap utilization) ... */
      for( uint j=0U; j<32U; j+=4U ) FD_STORE( uint, sample[ i ].uc+j, fd_rng_uint( rng ) );
    }

  }
  dt += fd_log_wallclock();

# if FD_HAS_DOUBLE
  FD_LOG_NOTICE(( "Sampled %lu keys in %gs (miss ratio %g)",
                  key_cnt, (double)dt/1e9, (double)( key_cnt-sample_cnt )/(double)key_cnt ));
# else
  FD_LOG_NOTICE(( "Sampled %lu keys in %ldns (%lu missed)",
                  key_cnt, dt, key_cnt-sample_cnt ));
# endif

  /* Run benchmark */

  bench_query_rand_t bqr = {
    .req_free    = req_free,
    .req_wait_lo = NULL,
    .req_wait_hi = NULL,
    .batch_depth = batch_depth,
    .iter_rem    = iter_cnt,
    .sample      = sample,
    .sample_idx  = 0UL,
    .sample_max  = key_cnt
  };
  dt = -fd_log_wallclock();
  while( bench_query_rand_poll( client, &bqr ) );
  dt += fd_log_wallclock();

# if FD_HAS_DOUBLE
  FD_LOG_NOTICE(( "Completed %lu queries (%lu found, %lu missed) in %gs (%g q/s)",
                  iter_cnt, bqr.found_cnt, bqr.miss_cnt,
                  (double)dt/1e9,
                  (double)iter_cnt / ( (double)dt/1e9 ) ));
# else
  FD_LOG_NOTICE(( "Completed %lu queries (%lu found, %lu missed) in %ldns",
                  iter_cnt, bqr.found_cnt, bqr.miss_cnt, dt ));
# endif

  /* Clean up */

  fd_rng_delete( fd_rng_leave( rng ) );

  fd_wksp_free_laddr( (void *)req_laddr );

  fd_shmem_release( sample, sample_page_sz, sample_page_cnt );
}

static int
client_cmd( client_t * client,
            char **    tok,
            ulong      tok_cnt ) {
  if( FD_UNLIKELY( !tok_cnt ) ) return 1;
  char const * cmd = tok[0];
  if( !strcmp( cmd, "query" ) ) {
    client_query( client, tok+1, tok_cnt-1 );
  } else if( !strcmp( cmd, "bench-query-rand" ) ) {
    int argc = (int)tok_cnt;
    client_bench_query_rand( client, &argc, &tok );
  } else if( !strcmp( cmd, "quit" ) || !strcmp( cmd, "exit" ) ) {
    return 0;
  } else {
    printf( "ERR: unknown command `%s`\n", cmd );
  }
  return 1;
}

static void
repl( client_t * client ) {
  char   line[ 4096 ] = {0};
# define TOK_MAX 16
  char * tokens[ 16 ] = {0};
  for(;;) {
    fputs( "accdb> ", stdout );
    fflush( stdout );

    /* Read command */
    if( fgets( line, sizeof(line), stdin )==NULL ) {
      putc( '\n', stdout );
      break;
    }
    line[ strcspn( line, "\n" ) ] = '\0';
    line[ sizeof(line)-1        ] = '\0';

    /* Interpret command */
    ulong tok_cnt = fd_cstr_tokenize( tokens, TOK_MAX, line, ' ' );
    if( !client_cmd( client, tokens, tok_cnt ) ) break;
  }
# undef TOK_MAX
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * cfg_gaddr = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cfg",       NULL, NULL );
  char const * wksp_name = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL );
  ulong const  burst_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--burst-max", NULL, 1UL  );
  ulong const  quota_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--quota-max", NULL, 2UL  );
  if( FD_UNLIKELY( !cfg_gaddr ) ) FD_LOG_ERR(( "Missing required argument --cfg" ));
  if( FD_UNLIKELY( !wksp_name ) ) FD_LOG_ERR(( "Missing required argument --wksp" ));

  argc--; argv++;

  /* Join server shared memory structures */

  uchar * pod = fd_pod_join( fd_wksp_map( cfg_gaddr ) );
  if( FD_UNLIKELY( !pod ) ) FD_LOG_ERR(( "Invalid --cfg pod" ));

  void * _cnc  = fd_wksp_pod_map( pod, "cnc"  );
  void * _meta = fd_wksp_pod_map( pod, "meta" );
  void * _ele  = fd_wksp_pod_map( pod, "ele"  );
  void * _obj  = fd_wksp_pod_map( pod, "obj"  );

  fd_cnc_t * cnc = fd_cnc_join( _cnc ); FD_TEST( cnc );
  fd_vinyl_meta_t meta[1];
  FD_TEST( fd_vinyl_meta_join( meta, _meta, _ele ) );

  ulong vinyl_status = fd_cnc_signal_query( cnc );
  if( FD_UNLIKELY( vinyl_status!=FD_CNC_SIGNAL_RUN ) ) {
    char status_cstr[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
    FD_LOG_ERR(( "Vinyl tile not running (status %lu-%s)", vinyl_status, fd_cnc_signal_cstr( vinyl_status, status_cstr ) ));
  }

  /* Allocate client structures */

  fd_wksp_t * wksp = fd_wksp_attach( wksp_name );
  FD_TEST( wksp );

  ulong const rq_max = 32UL;
  ulong const cq_max = 32UL;
  void * _rq = fd_wksp_alloc_laddr( wksp, fd_vinyl_rq_align(), fd_vinyl_rq_footprint( rq_max ), 1UL );
  void * _cq = fd_wksp_alloc_laddr( wksp, fd_vinyl_cq_align(), fd_vinyl_cq_footprint( cq_max ), 1UL );
  fd_vinyl_rq_t * rq = fd_vinyl_rq_join( fd_vinyl_rq_new( _rq, rq_max ) );
  fd_vinyl_cq_t * cq = fd_vinyl_cq_join( fd_vinyl_cq_new( _cq, cq_max ) );
  if( FD_UNLIKELY( !rq || !cq ) ) {
    FD_LOG_WARNING(( "Failed to allocate request/completion queues" ));
    goto dealloc2;
  }

  ulong req_info_gaddr = fd_wksp_alloc( wksp, alignof(req_info_t), sizeof(req_info_t), 1UL );
  if( FD_UNLIKELY( !req_info_gaddr ) ) {
    FD_LOG_WARNING(( "Failed to pre-allocate request metadata" ));
    goto dealloc1;
  }
  req_info_t * req_info = fd_wksp_laddr_fast( wksp, req_info_gaddr );

  /* Run client */

  ulong const link_id = 0UL;
  int join_err = fd_vinyl_client_join( cnc, rq, cq, wksp, link_id, burst_max, quota_max );
  if( FD_UNLIKELY( join_err ) ) FD_LOG_ERR(( "Failed to join vinyl client to server (err %i-%s)", join_err, fd_vinyl_strerror( join_err ) ));

  FD_LOG_NOTICE(( "Attached client" ));

  client_t client = {
    .rq      = rq,
    .cq      = cq,
    .req_id  = 0UL,
    .link_id = link_id,

    .meta = meta,

    .req_info       = req_info,
    .req_info_gaddr = req_info_gaddr,
    .val_wksp       = fd_wksp_containing( _obj ),
    .client_wksp    = wksp,

    .quota_rem = quota_max,
    .cq_seq    = fd_vinyl_cq_seq( cq )
  };

  if( argc>0 ) {
    client_cmd( &client, argv, (ulong)argc );
  } else {
    repl( &client );
  }

  FD_LOG_NOTICE(( "Detaching client" ));

  int leave_err = fd_vinyl_client_leave( cnc, link_id );
  if( FD_UNLIKELY( leave_err ) ) FD_LOG_ERR(( "Failed to leave vinyl client from server (err %i-%s)", leave_err, fd_vinyl_strerror( leave_err ) ));

dealloc1:
  fd_wksp_free( wksp, req_info_gaddr );

dealloc2:
  fd_wksp_free_laddr( fd_vinyl_rq_delete( fd_vinyl_rq_leave( rq ) ) );
  fd_wksp_free_laddr( fd_vinyl_cq_delete( fd_vinyl_cq_leave( cq ) ) );

  fd_wksp_unmap( fd_cnc_leave( cnc ) );
  fd_vinyl_meta_leave( meta );
  fd_wksp_unmap( _meta );
  fd_wksp_unmap( _ele );
  fd_wksp_unmap( _obj );
  fd_wksp_detach( wksp );

  fd_halt();
  return 0;
}
