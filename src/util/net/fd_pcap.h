#ifndef HEADER_fd_src_util_net_fd_pcap_h
#define HEADER_fd_src_util_net_fd_pcap_h

#include "../log/fd_log.h"
#include "fd_eth.h"

#define FD_PCAP_ITER_TYPE_ETHERNET (0UL)
#define FD_PCAP_ITER_TYPE_COOKED   (1UL)

/* Opaque handle of a pcap iterator */

struct fd_pcap_iter;
typedef struct fd_pcap_iter fd_pcap_iter_t;

FD_PROTOTYPES_BEGIN

/* fd_pcap_iter_new creates an iterator suitable for reading a pcap
   file.  file should be non-NULL handle of a stream seeked to the first
   byte of the pcap file (e.g. on a hosted platform a FILE * of the
   fopen'd file).  Returns file on success (the pcap_iter will have
   ownership of the file stream) and NULL on failure (an indeterminant
   number of bytes in the stream might have been consumed on failure). */

fd_pcap_iter_t *
fd_pcap_iter_new( void * file );

/* fd_pcap_iter_file returns the file stream of the pcap file being
   iterated over.  fd_pcap_iter_type returns the type of pcap file being
   iterated over (return value will be a FD_PCAP_ITER_TYPE_*).  Assumes
   iter is a current iterator and the iterator is unchanged.  No bytes
   in the underlying stream are consumed. */

FD_FN_CONST static inline void * fd_pcap_iter_file( fd_pcap_iter_t * iter ) { return (void *)(((ulong)iter) & ~1UL); }
FD_FN_CONST static inline ulong  fd_pcap_iter_type( fd_pcap_iter_t * iter ) { return          ((ulong)iter) &  1UL;  }

/* fd_pcap_iter_delete destroys a fd_pcap_iter_t.  Returns the handle of
   the underlying stream; the caller has ownership of the stream. */

FD_FN_CONST static inline void * fd_pcap_iter_delete( fd_pcap_iter_t * iter ) { return fd_pcap_iter_file( iter ); }

/* fd_pcap_iter_next extracts the next packet from the pcap stream.
   Returns pkt_sz the number of bytes in the packet on success and 0 on
   on failure.  Failure reasons include normal end-of-file, fread
   failures, pcap file corruption, pcap file contains truncated packets
   and pkt_max is too small for pkt_sz.  Details of all failures except
   normal end-of-file are logged with a warning.

   On a successful return, the memory region pointed to by pkt will
   contain the pkt_sz bytes of the extracted packet starting from the
   first byte of Ethernet header to the last byte of whatever was
   captured for that packet (e.g. the last byte of the Ethernet payload,
   the last byte of the Ethernet FCS, etc).  *_pkt_ts will contain the
   packet timestamp (assumes that the pcap captured at nanosecond
   resolution).  The iterator's underlying stream pointer will be
   advanced exactly on pcap pkt (and the underlying stream will have
   consumed bytes up to the next pkt).  If iterating over over a cooked
   capture, pkt will have use a phony Ethernet header with no VLAN
   tagging that mangles cooked sll dir/ha_type/ha_len fields into the
   dst mac and the ha into the src mac).

   On a failed return, pkt and pkt_ts are untouched.  If not a normal
   EOF, the iterator's underlying stream may have consumed an
   indeterminant number of bytes. */

ulong
fd_pcap_iter_next( fd_pcap_iter_t * iter,
                   void *           pkt,
                   ulong            pkt_max,
                   long *           _pkt_ts );

/* fd_pcap_fwrite_hdr write a little endian 2.4 Ethernet pcap header to
   the stream pointed to by file.  Same semantics as fwrite (returns
   number of headers written, which should be 1 on success and 0 on
   failure). */

ulong
fd_pcap_fwrite_hdr( void * file );

/* fd_pcap_fwrite_pkt writes the pcap ethernet frame formed by
   concatenating hdr/payload/fcs to appropriate for a pcap file at time
   ts (will be encoded with ns resolution).  hdr should start on the
   first byte of the Ethernet header and payload should end on the last
   byte of the Ethernet payloaded.  For normal (uncorrupted) frames:

     _fcs = fd_eth_fcs_append( fd_eth_fcs( _hdr, hdr_sz ), _payload, _payload_sz )

   Same semantics as fwrite: returns number of packets written -> 1 on
   success and 0 on failure (logs details on failure). */

ulong
fd_pcap_fwrite_pkt( long         ts,
                    void const * _hdr,
                    ulong        hdr_sz,
                    void const * _payload,
                    ulong        payload_sz,
                    uint         _fcs,
                    void *       file );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_net_fd_pcap_h */

