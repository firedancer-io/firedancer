#ifndef HEADER_fd_src_disco_pack_fd_pack_acct_blocklist_h
#define HEADER_fd_src_disco_pack_fd_pack_acct_blocklist_h

/* Sizing of the pack account blocklist, shared with the topology and
   config parsers so they need not include all of fd_pack.h. */

#define FD_PACK_ACCT_BLOCKLIST_LG_MAX   4
#define FD_PACK_ACCT_BLOCKLIST_MAX      (1UL<<FD_PACK_ACCT_BLOCKLIST_LG_MAX)

#endif /* HEADER_fd_src_disco_pack_fd_pack_acct_blocklist_h */
