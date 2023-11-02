#include "fd_ip.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <unistd.h>

#define PGM_NAME "test_arp"


/* to test ARP run this in a network namespace
   and verify the arp cache after */


/* get interface index from interface name */
uint
get_ifindex( char const * intf, int fd ) {
  struct ifreq if_idx = {0};
  memset( &if_idx, 0, sizeof(struct ifreq) );
  strncpy( if_idx.ifr_name, intf, IFNAMSIZ-1 );
  if( ioctl( fd, SIOCGIFINDEX, &if_idx ) < 0 ) {
    FD_LOG_ERR(( " Error from ioctl( fd, SIOCGIFINDEX, ... ). Error: %d %s", errno, strerror( errno ) ));
    exit(1);
  }

  return (uint)if_idx.ifr_ifindex;
}


/* get interface mac address from interface name */
void
get_mac_addr( uchar * out_mac_addr, char const * intf, int fd )
{
  struct ifreq if_mac = {0};
  memset( &if_mac, 0, sizeof(struct ifreq) );
  strncpy( if_mac.ifr_name, intf, IFNAMSIZ-1 );
  if( ioctl( fd, SIOCGIFHWADDR, &if_mac ) < 0 ) {
    FD_LOG_ERR(( " Error from ioctl( fd, SIOCGIFHWADDR, ... ). Error: %d %s", errno, strerror( errno ) ));
    exit(1);
  }

  memcpy( out_mac_addr, &if_mac.ifr_hwaddr.sa_data, 6 );
}


/* get interface ip address from interace name */
uint
get_ip_addr( char const * intf, int fd ) {
  struct ifreq ifr = {0};
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy( ifr.ifr_name, intf, IFNAMSIZ-1 );

  if( ioctl( fd, SIOCGIFADDR, &ifr ) < 0 ) {
    FD_LOG_ERR(( " Error from ioctl( fd, SIOCGIFADDR, ... ). Error: %d %s", errno, strerror( errno ) ));
    exit(1);
  }

  void * v_ifr = (void*)&ifr.ifr_addr;

  return ntohl( ((struct sockaddr_in *)v_ifr)->sin_addr.s_addr );
}


void
print_help( void ) {
  printf(
      "NAME\n"
      "\t"  "test_arp - test ARP API in Firedancer\n"
      "\n"
      "SYNOPSIS\n"
      "\t"  "test_arp INTERFACE_NAME DST_IP_ADDR\n"
      "\n"
      "INTERFACE_NAME\n"
      "\t"  "Specifies the name of the interface used to send the ARP\n"
      "\n"
      "DST_IP_ADDR\n"
      "\t"  "Specifies the name of the destination V4 IP address\n"
      "\n"
      "DESCRIPTION\n"
      "\t"  "Sends an ARP with the target IP address specified.\n"
      "\n"
      "EXPECTED RESULT\n"
      "\t"  "Should update the kernel ARP\n"
      );
}


uint
str_to_ip_addr( char const * in ) {
  uint a = 0;
  uint b = 0;
  uint c = 0;
  uint d = 0;
  if( sscanf( in, "%u.%u.%u.%u", &a, &b, &c, &d ) != 4 ) {
    fprintf( stderr, "IP address not understood\n\n" );
    print_help();

    exit(1);
  }

  return ( a << 030 ) | ( b << 020 ) | ( c << 010 ) | d;
}


static char const *
get_state_str( uint state ) {
  char const * state_str = "N/A";
  switch( state ) {
#   define CASE(X) case X: state_str = #X; break
    CASE(NUD_NONE);
    CASE(NUD_REACHABLE);
    CASE(NUD_INCOMPLETE);
    CASE(NUD_PROBE);
    CASE(NUD_DELAY);
    CASE(NUD_STALE);
    CASE(NUD_PERMANENT);
    CASE(NUD_NOARP);
    default: break;
  }

  return state_str;
}


int
main( int argc, char **argv ) {
  fd_boot( &argc, &argv );

  if( argc < 3 ) {
    print_help();
    exit(0);
  }

  int fd = socket( AF_PACKET, SOCK_RAW, IPPROTO_RAW );
  if( fd == -1 ) {
    FD_LOG_NOTICE(( "error: %d %s", errno, strerror( errno ) ));
  }

  char const * intf             = argv[1];
  uint         ifindex          = get_ifindex( intf, fd );
  uint         dst_ip_addr      = str_to_ip_addr( argv[2] );
  uint         src_ip_addr      = get_ip_addr( intf, fd );
  uchar        src_mac_addr[6]  = {0};

  get_mac_addr( src_mac_addr, intf, fd );

  fd_nl_t nl;
  fd_nl_init( &nl, 4242 );

  /* load arp entries */
# define ARP_TABLE_CAP 32
  fd_nl_arp_entry_t arp_table[ARP_TABLE_CAP];

  long arp_table_sz = 0;

  do {
    arp_table_sz = fd_nl_load_arp_table( &nl, arp_table, ARP_TABLE_CAP );
    FD_TEST( arp_table_sz != FD_IP_ERROR );
  } while( arp_table_sz < 0 );

  /* should be no arp entry for the ip

     need to create one in NONE state, then move it to INCOMPLETE
     then we send an ARP probe, and the kernel should take over */

  /* create ARP entry */
  int rc = fd_nl_update_arp_table( &nl, arp_table, ARP_TABLE_CAP, dst_ip_addr, ifindex );
  FD_LOG_WARNING(( "1 fd_nl_update_arp_table rc = %d", rc ));
  FD_TEST( rc == FD_IP_RETRY );

  /* move entry to state INCOMPLETE */
  rc = fd_nl_update_arp_table( &nl, arp_table, ARP_TABLE_CAP, dst_ip_addr, ifindex );
  FD_LOG_WARNING(( "2 fd_nl_update_arp_table rc = %d", rc ));
  FD_TEST( rc == FD_IP_PROBE_RQD );

  /* now send a probe */
  uchar buf[2048];
  ulong buf_sz  = sizeof( buf );
  ulong arp_len = 0;

  /* format an ARP probe message */
  fd_ip_arp_gen_arp_probe( buf, buf_sz, &arp_len, dst_ip_addr, src_ip_addr, src_mac_addr );

  struct sockaddr_ll dst_nic = {0};

  dst_nic.sll_ifindex = (int)ifindex;
  memcpy( &dst_nic.sll_addr, src_mac_addr, 6 );

  /* send the ARP probe via the given local interface */
  if( sendto( fd, buf, arp_len, 0, (void*)&dst_nic, sizeof( dst_nic ) ) == -1 ) {
    FD_LOG_NOTICE(( "sendto failed with: %d %s", errno, strerror( errno ) ));
  }

  /* wait */
  fd_log_sleep( (long)( 20. * 1e6 ) ); /* sleep for  20ms */

  /* reload ARP table */
  do {
    arp_table_sz = fd_nl_load_arp_table( &nl, arp_table, ARP_TABLE_CAP );
    FD_TEST( ARP_TABLE_CAP != FD_IP_ERROR );
  } while( arp_table_sz < 0 );

  /* query the table */
  fd_nl_arp_entry_t * entry = fd_nl_arp_query( arp_table, (ulong)arp_table_sz, dst_ip_addr );
  FD_TEST( entry );

  FD_LOG_NOTICE(( "entry state: %d (%s)", (int)entry->state, get_state_str( entry->state ) ));

  uint old_state = entry->state;
  uint attempts  = 15;
  uint retries   = 3;
  while( retries && attempts ) {
    fd_log_sleep( (long)( 10. * 1e6 ) ); /* sleep for  10ms */

    /* reload ARP table */
    do {
      arp_table_sz = fd_nl_load_arp_table( &nl, arp_table, ARP_TABLE_CAP );
      FD_TEST( ARP_TABLE_CAP != FD_IP_ERROR );
    } while( arp_table_sz < 0 );

    fd_nl_arp_entry_t * entry = fd_nl_arp_query( arp_table, (ulong)arp_table_sz, dst_ip_addr );
    FD_TEST( entry );

    if( entry->state & ( NUD_STALE | NUD_DELAY ) ) {
      /* send an ARP probe via the given local interface */
      if( sendto( fd, buf, arp_len, 0, (void*)&dst_nic, sizeof( dst_nic ) ) == -1 ) {
        FD_LOG_NOTICE(( "sendto failed with: %d %s", errno, strerror( errno ) ));
      }

      /* the reply ensures the kernel moves the state to NUD_REACHABLE */

      /* count attempts */
      attempts--;
    }

    /* count the number of transitions from stale|delay to reachable */

    if( entry->state == NUD_REACHABLE && old_state & ( NUD_STALE | NUD_DELAY ) ) {
      retries--;
    }

    if( entry->state != old_state ) {
      FD_LOG_NOTICE(( "entry state: %d (%s)", (int)entry->state, get_state_str( entry->state ) ));
    }

    old_state = entry->state;
  }

  FD_LOG_NOTICE(( "pass" ));

  close( fd );

  fd_halt();

  return 0;
}
