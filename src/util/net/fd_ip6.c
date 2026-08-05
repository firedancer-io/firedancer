#include "fd_ip6.h"
#include "fd_ip4.h"
#include "../fd_util.h"

#include <net/if.h> /* if_nametoindex */

/* hex_val returns the value of a hex digit, or -1 if c is not a hex
   digit. */

static int
hex_val( int c ) {
  if( c>='0' && c<='9' ) return c-'0';
  if( c>='a' && c<='f' ) return c-'a'+10;
  if( c>='A' && c<='F' ) return c-'A'+10;
  return -1;
}

/* ip4_parse parses a dotted quad in [s,end).  Returns 1 on success and
   stores the address in network byte order to out, otherwise 0. */

static int
ip4_parse( char const * s,
           char const * end,
           uint *       out ) {
  uchar octet[ 4 ];
  for( ulong i=0UL; i<4UL; i++ ) {
    if( i ) {
      if( s>=end || *s!='.' ) return 0;
      s++;
    }
    uint val = 0U;
    int  dig = 0;
    int  lead_zero = ( s<end && *s=='0' );
    while( s<end && *s>='0' && *s<='9' ) {
      val = val*10U + (uint)( *s-'0' );
      s++;
      if( ++dig>3 ) return 0;
    }
    /* Reject leading zeroes, which are ambiguous (octal or decimal?) */
    if( !dig || val>255U || ( lead_zero && dig>1 ) ) return 0;
    octet[ i ] = (uchar)val;
  }
  if( s!=end ) return 0;
  memcpy( out, octet, 4UL );
  return 1;
}

/* ip6_parse parses an IPv6 address literal (RFC 4291 section 2.2) in
   [s,end), including the zero compression ("::") and embedded IPv4
   ("::ffff:1.2.3.4") forms.  Returns 1 on success and stores the
   address in network byte order to out, otherwise 0. */

static int
ip6_parse( char const * s,
           char const * end,
           uchar        out[ 16 ] ) {
  uchar addr[ 16 ] = {0};
  int   cnt        = 0;  /* number of 16-bit groups parsed */
  int   gap        = -1; /* group index at which "::" appeared, or -1 */

  if( s>=end ) return 0;

  if( *s==':' ) { /* leading "::" (the only way an address may start with ':') */
    s++;
    if( s>=end || *s!=':' ) return 0;
    s++;
    gap = 0;
  }

  int expect_sep = 0;
  while( s<end ) {

    if( expect_sep ) {
      if( *s!=':' ) return 0;
      s++;
      if( s<end && *s==':' ) { /* "::" */
        if( gap>=0 ) return 0; /* at most one gap */
        s++;
        gap        = cnt;
        expect_sep = 0;
        continue;
      }
      if( s>=end ) return 0; /* trailing ':' */
    }

    /* Find the end of this group and check whether it is an embedded
       IPv4 address */

    char const * tok_end = s;
    int          is_ip4  = 0;
    while( tok_end<end && *tok_end!=':' ) {
      is_ip4 |= ( *tok_end=='.' );
      tok_end++;
    }

    if( is_ip4 ) {
      uint ip4;
      if( cnt>6 || tok_end!=end ) return 0; /* must be the last two groups */
      if( !ip4_parse( s, tok_end, &ip4 ) ) return 0;
      memcpy( addr+2*cnt, &ip4, 4UL );
      cnt += 2;
      s    = tok_end;
      break;
    }

    uint val = 0U;
    int  dig = 0;
    while( s<end && hex_val( *s )>=0 ) {
      val = ( val<<4 ) | (uint)hex_val( *s );
      s++;
      if( ++dig>4 ) return 0;
    }
    if( !dig || cnt>7 ) return 0;
    addr[ 2*cnt   ] = (uchar)( val>>8 );
    addr[ 2*cnt+1 ] = (uchar)( val    );
    cnt++;
    expect_sep = 1;

  }

  if( gap<0 ) {
    if( cnt!=8 ) return 0;
  } else {
    if( cnt>=8 ) return 0; /* "::" must cover at least one group */
    /* Move the groups that follow the gap to the end of the address */
    int tail = cnt-gap;
    if( tail ) memmove( addr+16-2*tail, addr+2*gap, (ulong)( 2*tail ) );
    memset( addr+2*gap, 0, (ulong)( 16-2*gap-2*tail ) );
  }

  memcpy( out, addr, 16UL );
  return 1;
}

/* zone_parse resolves a zone ID (interface name or numeric interface
   index) in [s,end) to an interface index.  Returns 0 on failure. */

static uint
zone_parse( char const * s,
            char const * end ) {
  if( s>=end ) return 0U;

  int numeric = 1;
  for( char const * p=s; p<end; p++ ) numeric &= ( *p>='0' && *p<='9' );

  if( numeric ) {
    ulong idx = 0UL;
    for( char const * p=s; p<end; p++ ) {
      idx = idx*10UL + (ulong)( *p-'0' );
      if( idx>UINT_MAX ) return 0U;
    }
    return (uint)idx;
  }

  if( (ulong)( end-s )>=IF_NAMESIZE ) return 0U;
  char name[ IF_NAMESIZE ];
  memcpy( name, s, (ulong)( end-s ) );
  name[ end-s ] = '\0';
  return if_nametoindex( name ); /* 0 if no such interface */
}

int
fd_cstr_to_ip6_addr( char const *    s,
                     fd_ip6_addr_t * out ) {

  /* Split off the zone ID, if any */

  char const * end  = s;
  char const * zone = NULL;
  while( *end ) {
    if( *end=='%' ) { zone = end+1; break; }
    end++;
  }

  fd_ip6_addr_t addr = {0};
  if( FD_UNLIKELY( !ip6_parse( s, end, addr.addr ) ) ) return 0;

  if( zone ) {
    /* A zone ID only identifies an interface for addresses that are not
       globally scoped.  Reject it elsewhere, as the kernel would
       silently ignore it. */
    if( FD_UNLIKELY( !fd_ip6_addr_is_scoped( addr.addr ) ) ) return 0;
    char const * zone_end = zone;
    while( *zone_end ) zone_end++;
    addr.scope_id = zone_parse( zone, zone_end );
    if( FD_UNLIKELY( !addr.scope_id ) ) return 0;
  }

  *out = addr;
  return 1;
}

int
fd_cstr_to_ip46_addr( char const *    s,
                      fd_ip6_addr_t * out ) {
  uint ip4_addr;
  if( fd_cstr_to_ip4_addr( s, &ip4_addr ) ) {
    fd_ip6_addr_t addr = {0};
    fd_ip6_addr_ip4_mapped( addr.addr, ip4_addr );
    *out = addr;
    return 1;
  }
  return fd_cstr_to_ip6_addr( s, out );
}

/* ip4_cstr appends a dotted quad to p */

static char *
ip4_cstr( char *        p,
          uchar const * octet ) {
  for( ulong i=0UL; i<4UL; i++ ) {
    if( i ) p = fd_cstr_append_char( p, '.' );
    p = fd_cstr_append_printf( p, "%u", (uint)octet[ i ] );
  }
  return p;
}

char *
fd_ip6_addr_cstr( char                  buf[ static FD_IP6_ADDR_CSTR_MAX ],
                  fd_ip6_addr_t const * addr ) {
  uchar const * a = addr->addr;
  int           ip4 = fd_ip6_addr_is_ip4_mapped( a );

  /* An IPv4 address prints as a dotted quad */

  if( ip4 && !addr->scope_id ) {
    char * p = fd_cstr_init( buf );
    p = ip4_cstr( p, a+12 );
    fd_cstr_fini( p );
    return buf;
  }

  ushort group[ 8 ];
  for( ulong i=0UL; i<8UL; i++ ) group[ i ] = (ushort)( ( (uint)a[ 2*i ]<<8 ) | a[ 2*i+1 ] );

  /* Find the longest run of zero groups to compress, leftmost run
     winning ties.  Runs of a single group are not compressed
     (RFC 5952 section 4.2). */

  int gap = -1, gap_len = 1;
  for( int i=0; i<8; ) {
    if( group[ i ] ) { i++; continue; }
    int j = i;
    while( j<8 && !group[ j ] ) j++;
    if( j-i>gap_len ) { gap = i; gap_len = j-i; }
    i = j;
  }

  char * p     = fd_cstr_init( buf );
  int    colon = 0;
  p = fd_cstr_append_char( p, '[' );
  for( int i=0; i<8; ) {
    if( i==gap ) {
      p     = fd_cstr_append_text( p, "::", 2UL );
      i    += gap_len;
      colon = 0;
      continue;
    }
    if( colon ) p = fd_cstr_append_char( p, ':' );
    if( ip4 && i==6 ) { /* IPv4-mapped addresses use the mixed notation (RFC 5952 section 5) */
      p = ip4_cstr( p, a+12 );
      break;
    }
    p     = fd_cstr_append_printf( p, "%x", (uint)group[ i ] );
    colon = 1;
    i++;
  }

  if( addr->scope_id ) p = fd_cstr_append_printf( p, "%%%u", addr->scope_id );
  p = fd_cstr_append_char( p, ']' );
  fd_cstr_fini( p );

  return buf;
}
