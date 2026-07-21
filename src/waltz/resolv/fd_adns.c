#include "fd_adns.h"
#include "fd_netdb.h"
#include "fd_lookup.h"
#include "../../util/log/fd_log.h"
#include "../../util/io/fd_io.h"

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Queries advertise EDNS0 with this UDP payload capacity (the DNS
   flag day 2020 recommendation: large enough that an A answer never
   truncates, small enough to avoid IP fragmentation). */
#define ANSWER_MTU (1232UL)

/* EDNS0 OPT pseudo-RR appended to each query: root name, TYPE=OPT,
   CLASS=payload capacity, TTL=0 (no extended flags), RDLEN=0. */
#define OPT_RR_SZ (11UL)
static uchar const opt_rr[ OPT_RR_SZ ] = { 0, 0, 41, (uchar)(ANSWER_MTU>>8), (uchar)(ANSWER_MTU&0xFF), 0, 0, 0, 0, 0, 0 };

/* Bound receive work per advance so a UDP flood at our ephemeral
   port cannot starve the caller's run loop. */
#define RECV_BURST_MAX (64UL)

FD_TL ushort fd_adns_ns_port = 53;

#define NS_MAX (3UL) /* MAXNS */

#define REQ_STATE_IDLE    (0)
#define REQ_STATE_PENDING (1)
#define REQ_STATE_DONE    (2)

struct fd_adns_req {
  int              state;
  uchar            query[ FD_DNS_QUERY_MTU ];
  int              qlen;
  int              no_edns;         /* server answered FORMERR/NOTIMP to EDNS0 */
  long             deadline_nanos;  /* next (re)send */
  uint             sends_left;
  fd_adns_result_t result;
};

typedef struct fd_adns_req fd_adns_req_t;

struct fd_adns_private {
  int   fd;

  uint  ns[ NS_MAX ];
  ulong ns_cnt;
  long  retry_nanos;
  uint  attempts;

  ulong           max;
  ulong           active_cnt;  /* PENDING+DONE */
  ulong           pending_cnt; /* PENDING only */
  fd_adns_req_t * reqs;

  ulong magic;
};

FD_FN_CONST ulong
fd_adns_align( void ) {
  return fd_ulong_max( alignof(fd_adns_t), alignof(fd_adns_req_t) );
}

FD_FN_CONST ulong
fd_adns_footprint( ulong max_reqs ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_adns_t),     sizeof(fd_adns_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_adns_req_t), max_reqs*sizeof(fd_adns_req_t) );
  return FD_LAYOUT_FINI( l, fd_adns_align() );
}

void *
fd_adns_new( void * shmem,
             ulong  max_reqs ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_adns_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_reqs ) ) {
    FD_LOG_WARNING(( "max_reqs must be at least 1" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_adns_t * adns = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_adns_t),     sizeof(fd_adns_t) );
  adns->reqs       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_adns_req_t), max_reqs*sizeof(fd_adns_req_t) );

  adns->max         = max_reqs;
  adns->active_cnt  = 0UL;
  adns->pending_cnt = 0UL;
  for( ulong i=0UL; i<max_reqs; i++ ) adns->reqs[ i ].state = REQ_STATE_IDLE;

  /* resolv.conf: nameservers plus retry cadence (timeout is the total
     budget spread over attempts, like the blocking resolver). */
  uint ns[ NS_MAX ];
  uint timeout  = 5U;
  uint attempts = 2U;
  int  ns_cnt = fd_dns_nameservers( ns, NS_MAX, &timeout, &attempts );
  if( FD_UNLIKELY( ns_cnt<=0 ) ) {
    FD_LOG_WARNING(( "no usable IPv4 nameservers in /etc/resolv.conf" ));
    ns_cnt = 0;
  }
  adns->ns_cnt = (ulong)ns_cnt;
  for( ulong i=0UL; i<adns->ns_cnt; i++ ) adns->ns[ i ] = ns[ i ];
  adns->attempts    = fd_uint_max( attempts, 1U );
  adns->retry_nanos = ((long)timeout*1000L*1000L*1000L)/(long)adns->attempts;

  adns->fd = socket( AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==adns->fd ) ) FD_LOG_ERR(( "socket() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( adns->magic ) = FD_ADNS_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)adns;
}

fd_adns_t *
fd_adns_join( void * shadns ) {
  if( FD_UNLIKELY( !shadns ) ) {
    FD_LOG_WARNING(( "NULL shadns" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shadns, fd_adns_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shadns" ));
    return NULL;
  }

  fd_adns_t * adns = (fd_adns_t *)shadns;
  if( FD_UNLIKELY( adns->magic!=FD_ADNS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return adns;
}

void *
fd_adns_leave( fd_adns_t * adns ) {
  return (void *)adns;
}

void *
fd_adns_delete( void * shadns ) {
  fd_adns_t * adns = (fd_adns_t *)shadns;
  if( FD_UNLIKELY( !adns ) ) return NULL;
  if( FD_UNLIKELY( adns->magic!=FD_ADNS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( -1==close( adns->fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  FD_COMPILER_MFENCE();
  FD_VOLATILE( adns->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shadns;
}

int
fd_adns_resolve( fd_adns_t *  adns,
                 char const * name,
                 ulong        req_id ) {
  if( FD_UNLIKELY( adns->active_cnt>=adns->max ) ) return -1;

  fd_adns_req_t * req = NULL;
  for( ulong i=0UL; i<adns->max; i++ ) {
    if( FD_LIKELY( adns->reqs[ i ].state==REQ_STATE_IDLE ) ) { req = &adns->reqs[ i ]; break; }
  }
  FD_TEST( req );

  req->result.req_id   = req_id;
  req->result.err      = 0;
  req->result.addr_cnt = 0UL;
  req->no_edns         = 0;

  /* Local names (literals, /etc/hosts) complete without network I/O */
  int cnt = fd_dns_ip4_local( name, req->result.addrs, FD_ADNS_ADDR_MAX );
  if( FD_UNLIKELY( cnt ) ) {
    if( FD_LIKELY( cnt>0 ) ) req->result.addr_cnt = (ulong)cnt;
    else                     req->result.err      = cnt;
    req->state = REQ_STATE_DONE;
    adns->active_cnt++;
    return 0;
  }

  req->qlen = fd_dns_ip4_query( name, req->query );
  if( FD_UNLIKELY( req->qlen<0 ) ) {
    req->result.err = FD_EAI_NONAME;
    req->state      = REQ_STATE_DONE;
    adns->active_cnt++;
    return 0;
  }

  /* Answers are matched by query id; make ids distinct. */
  for( ulong i=0UL; i<adns->max; i++ ) {
    if( FD_UNLIKELY( adns->reqs[ i ].state!=REQ_STATE_PENDING ) ) continue;
    if( FD_UNLIKELY( adns->reqs[ i ].query[ 0 ]==req->query[ 0 ] && adns->reqs[ i ].query[ 1 ]==req->query[ 1 ] ) ) {
      req->query[ 1 ]++;
      i = (ulong)-1L; /* restart scan */
    }
  }

  req->deadline_nanos = 0L; /* due immediately */
  req->sends_left     = adns->attempts;
  req->state          = REQ_STATE_PENDING;
  adns->active_cnt++;
  adns->pending_cnt++;
  return 0;
}

static void
drain_answers( fd_adns_t * adns );

static void
pending_io( fd_adns_t * adns,
            long        now ) {
  if( FD_LIKELY( !adns->pending_cnt ) ) return;

  drain_answers( adns );

  /* Send due (re)tries to all nameservers in parallel */
  for( ulong i=0UL; i<adns->max; i++ ) {
    fd_adns_req_t * req = &adns->reqs[ i ];
    if( FD_LIKELY( req->state!=REQ_STATE_PENDING ) ) continue;
    if( FD_LIKELY( req->deadline_nanos>now ) )       continue;

    if( FD_UNLIKELY( !req->sends_left || !adns->ns_cnt ) ) {
      req->result.err = FD_EAI_AGAIN;
      req->state      = REQ_STATE_DONE;
      adns->pending_cnt--;
      continue;
    }

    /* req->query holds the bare question packet (the part answers
       echo); the wire packet adds the EDNS0 OPT RR unless the server
       rejected it */
    uchar pkt[ FD_DNS_QUERY_MTU+OPT_RR_SZ ];
    fd_memcpy( pkt, req->query, (ulong)req->qlen );
    ulong pkt_sz = (ulong)req->qlen;
    if( FD_LIKELY( !req->no_edns ) ) {
      fd_memcpy( pkt+pkt_sz, opt_rr, OPT_RR_SZ );
      pkt[ 11 ] = 1; /* arcount */
      pkt_sz += OPT_RR_SZ;
    }

    int sent_any = 0, all_eagain = 1;
    for( ulong j=0UL; j<adns->ns_cnt; j++ ) {
      struct sockaddr_in ns_addr = {
        .sin_family = AF_INET,
        .sin_port   = fd_ushort_bswap( fd_adns_ns_port ),
        .sin_addr   = { .s_addr = adns->ns[ j ] }
      };
      long sent;
      do sent = sendto( adns->fd, pkt, pkt_sz, MSG_NOSIGNAL, fd_type_pun( &ns_addr ), sizeof(ns_addr) );
      while( FD_UNLIKELY( -1L==sent && errno==EINTR ) ); /* retry before charging the attempt */
      if( FD_UNLIKELY( -1L==sent ) ) {
        if( FD_UNLIKELY( errno!=EAGAIN && errno!=ECONNREFUSED && errno!=ENETUNREACH && errno!=EHOSTUNREACH ) )
          FD_LOG_ERR(( "sendto() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        if( FD_LIKELY( errno!=EAGAIN ) ) all_eagain = 0;
      } else {
        sent_any = 1;
      }
    }
    /* Local socket backpressure put nothing on the wire: stay due and
       retry next advance without consuming the attempt */
    if( FD_UNLIKELY( !sent_any && all_eagain && adns->ns_cnt ) ) { req->deadline_nanos = now; continue; }
    req->sends_left--;
    req->deadline_nanos = now+adns->retry_nanos;
  }
}

static void
drain_answers( fd_adns_t * adns ) {
  for( ulong burst=0UL; burst<RECV_BURST_MAX; burst++ ) {
    uchar answer[ ANSWER_MTU ];
    struct sockaddr_in sa;
    struct iovec iov = { .iov_base = answer, .iov_len = sizeof(answer) };
    struct msghdr mh = {
      .msg_name    = &sa,
      .msg_namelen = sizeof(sa),
      .msg_iov     = &iov,
      .msg_iovlen  = 1
    };
    long rlen = recvmsg( adns->fd, &mh, 0 );
    if( FD_LIKELY( rlen<0L ) ) {
      if( FD_LIKELY( errno==EAGAIN || errno==EWOULDBLOCK ) ) break;
      if( FD_LIKELY( errno==ECONNREFUSED || errno==EINTR ) ) continue;
      FD_LOG_ERR(( "recvmsg() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    if( FD_UNLIKELY( rlen<12L ) ) continue;

    /* Ignore replies from addresses we didn't send to */
    ulong j;
    for( j=0UL; j<adns->ns_cnt; j++ ) {
      if( FD_LIKELY( sa.sin_family==AF_INET && sa.sin_addr.s_addr==adns->ns[ j ] && sa.sin_port==fd_ushort_bswap( fd_adns_ns_port ) ) ) break;
    }
    if( FD_UNLIKELY( j==adns->ns_cnt ) ) continue;

    /* Must be a standard-query response */
    if( FD_UNLIKELY( (answer[ 2 ]&0x80)!=0x80 || (answer[ 2 ]&0x78)!=0 ) ) continue;

    fd_adns_req_t * req = NULL;
    for( ulong i=0UL; i<adns->max; i++ ) {
      if( FD_LIKELY( adns->reqs[ i ].state==REQ_STATE_PENDING && adns->reqs[ i ].query[ 0 ]==answer[ 0 ] && adns->reqs[ i ].query[ 1 ]==answer[ 1 ] ) ) {
        req = &adns->reqs[ i ];
        break;
      }
    }
    if( FD_UNLIKELY( !req ) ) continue;
    if( FD_UNLIKELY( rlen<req->qlen ) ) continue;
    if( FD_UNLIKELY( answer[ 4 ]!=req->query[ 4 ] || answer[ 5 ]!=req->query[ 5 ] ) ) continue;
    if( FD_UNLIKELY( memcmp( answer+12, req->query+12, (ulong)req->qlen-12UL ) ) ) continue;

    /* FORMERR/NOTIMP from an EDNS0-unaware server: resend plain.
       Guarantee a send remains, else attempts:1 expires the request
       at the sends_left check instead of retrying. */
    if( FD_UNLIKELY( ((answer[ 3 ]&15)==1 || (answer[ 3 ]&15)==4) && !req->no_edns ) ) {
      req->no_edns        = 1;
      req->sends_left     = fd_uint_max( req->sends_left, 1U );
      req->deadline_nanos = 0L; /* due immediately */
      continue;
    }

    int truncated = !!(answer[ 2 ]&2) | !!(mh.msg_flags&MSG_TRUNC);

    int cnt = fd_dns_ip4_answer( answer, (ulong)rlen, req->result.addrs, FD_ADNS_ADDR_MAX );
    if( FD_UNLIKELY( cnt==FD_EAI_AGAIN && !truncated ) ) continue; /* SERVFAIL: leave pending for retry */
    /* Truncated and nothing parseable: with EDNS0 advertising 1232B
       this means a pathological answer; the leading records we need
       (up to FD_ADNS_ADDR_MAX) essentially always fit, so this is a
       terminal failure rather than a TCP fallback. */
    if( FD_UNLIKELY( cnt<=0 && truncated ) ) cnt = FD_EAI_FAIL;

    if( FD_LIKELY( cnt>0 ) ) req->result.addr_cnt = (ulong)cnt;
    else                     req->result.err      = cnt;
    req->state = REQ_STATE_DONE;
    adns->pending_cnt--;
  }
}

int
fd_adns_advance( fd_adns_t *        adns,
                 long               now,
                 fd_adns_result_t * result ) {
  if( FD_LIKELY( !adns->active_cnt ) ) return 0;

  pending_io( adns, now );

  for( ulong i=0UL; i<adns->max; i++ ) {
    fd_adns_req_t * req = &adns->reqs[ i ];
    if( FD_LIKELY( req->state!=REQ_STATE_DONE ) ) continue;
    *result    = req->result;
    req->state = REQ_STATE_IDLE;
    adns->active_cnt--;
    return 1;
  }
  return 0;
}
