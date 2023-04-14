#ifndef HEADER_fd_src_util_net_fd_pcapng_h
#define HEADER_fd_src_util_net_fd_pcapng_h

/* pcapng is a file format for packet captures. Incompatible with
   classic "tcpdump" pcap as in fd_pcap.h but supports additional
   features such as embedded encryption secrets.

   Spec: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/

   fd_pcapng only supports little-endian files.  All strings in this API
   are formatted as UTF-8 (superset of ASCII) and max not exceed 200
   char length.  All values in "opt" structs are optional, absence
   implied by zero unless otherwise stated.

   This library is not optimized for high performance and is thus not
   suitable for packet capture at line rate. */

#include "../fd_util_base.h"

/* fd_pcapng_shb_opts_t contain Section Header Block options. */

struct fd_pcapng_shb_opts {
  char const * hardware; /* Generic name of machine performing capture
                            e.g. "x86_64 Server" */
  char const * os;       /* Operating system or distro name */
  char const * userappl; /* Name of this program (e.g. "Firedancer") */
};
typedef struct fd_pcapng_shb_opts fd_pcapng_shb_opts_t;

/* fd_pcapng_idb_opts_t contain Interface Description Block options. */

struct fd_pcapng_idb_opts {
  char  name[16];     /* Name of network interface in OS */
  uchar ip4_addr[4];  /* IPv4 address in big endian order -- todo support multiple */
  uchar mac_addr[6];  /* MAC address */
  uchar tsresol;      /* See FD_PCAPNG_TSRESOL_* */
  char  hardware[64]; /* Name of network interface hardware */
};
typedef struct fd_pcapng_idb_opts fd_pcapng_idb_opts_t;

#define FD_PCAPNG_TSRESOL_NS ((uchar)0x09)

FD_PROTOTYPES_BEGIN

/* fd_pcapng_shb_defaults stores default options for an SHB based on the
   system environment into opt.  Given opt must be initialized prior to
   call. */

void
fd_pcapng_shb_defaults( fd_pcapng_shb_opts_t * opt );

/* fd_pcapng_fwrite_shb writes a little endian pcapng SHB v1.0 (Section
   Header Block) to the stream pointed to by file.  Same semantics as
   fwrite (returns the number of headers written, which should be 1 on
   success and 0 on failure). opt contains options embedded into SHB
   and may be NULL.

   The PCAPNG spec requires an SHB v1.0 at the beginning of the file.
   Multiple SHBs per file are permitted.  An SHB clears any side effects
   induced by blocks (such as the timestamp resolution of an IDB).  It
   is the caller's responsibility to maintain 4 byte alignment for
   stream pointer of file. (all functions in this API will write
   multiples of 4).

   If SHB is not first of file, this function currently makes no attempt
   to fix up the length field of the preceding SHB (may change in the
   future). */

ulong
fd_pcapng_fwrite_shb( fd_pcapng_shb_opts_t const * opt,
                      void *                       file );

#if FD_HAS_HOSTED

/* fd_pcapng_idb_defaults stores default options for an IDB based on the
   system environment into opt.  if_idx is the operating system's
   interface index. (THIS IS UNRELATED TO THE PCAPNG INTERFACE INDEX).
   Returns 0 on success and -1 on failure.  Reasons for failure are
   written to log.  On failure, partially writes opt. */

int
fd_pcapng_idb_defaults( fd_pcapng_idb_opts_t * opt,
                        uint                   if_idx );

#endif /* FD_HAS_HOSTED */

/* fd_pcapng_fwrite_idb writes an IDB (Interface Description Block) to
   the stream pointed to by file.  Usually a successor of an SHB.  Refer
   to fd_pcapng_fwrite_shb for use of opt, file args. link_type is one
   of FD_PCAPNG_LINKTYPE_*. */

/* FD_PCAPNG_LINKTYPE_*: Link types (currently only Ethernet supported) */

#define FD_PCAPNG_LINKTYPE_ETHERNET (1U)

ulong
fd_pcapng_fwrite_idb( uint                         link_type,
                      fd_pcapng_idb_opts_t const * opt,
                      void *                       file );

/* fd_pcapng_fwrite_pkt writes an EPB (Enhanced Packet Block) containing
   an ethernet frame at time ts (in nanos). Same semantics as fwrite
   (returns the number of packets written, which should be 1 on success
   and 0 on failure). Current section's IDB
   tsresol==FD_PCAPNG_TSRESOL_NS (initialized accordingly by
   fd_pcapng_idb_defaults).  queue is the RX queue index on which this
   packet was received on (-1 if unknown). */

ulong
fd_pcapng_fwrite_pkt( long         ts,
                      void const * payload,
                      ulong        payload_sz,
                      void *       file );

/* fd_pcapng_fwrite_tls_key_log writes TLS key log info to a PCAPNG via
   a DSB (Decryption Secrets Block).  Similar semantics to fwrite
   (returns 1 on success and 0 on failure, but will dispatch multiple
   fwrite calls internally).  log points to first byte of NSS key log
   in ASCII format.  log_sz is byte size of log. */

ulong
fd_pcapng_fwrite_tls_key_log( uchar const * log,
                              uint          log_sz,
                              void *        file );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_net_fd_pcapng_h */
