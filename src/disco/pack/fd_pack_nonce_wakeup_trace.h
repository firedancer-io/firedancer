#ifndef HEADER_fd_src_disco_pack_fd_pack_nonce_wakeup_trace_h
#define HEADER_fd_src_disco_pack_fd_pack_nonce_wakeup_trace_h

/* Private, source-only diagnostic.  Build fd_pack.c with
     -DFD_PACK_NONCE_WAKEUP_TRACE=1
   Default builds have no fields, hooks, logging, or selector work.

   PACK_NONCE_WAKEUP_V1 is NOT a slot, runtime execution, fee, or root
   oracle.  Join the pack thread/process generation and tick/log interval
   with normal pack_became_leader/pack_end_block logs.  A schedule event
   means selection by pack, not execution.  No absence claim is valid
   across CLEAR, DISABLED, a missing serial, or a failed membership walk.

   Hard bounds per fd_pack_new lifetime: 4096 NOTICE calls (including
   INIT and the reserved DISABLED record), <=3 reciprocal-parent walks
   of128 nodes/record, no pool/tree scans.  Logs are synchronous; timing
   perturbation is unmeasured, NOT bounded in wall time.  Logfile NOTICE
   capture/complete process interval is required (logger I/O loss cannot
   be detected here).  Serial is monotonic; tick is fd_tickcount, not ns.
   State survives clear_all/end_block.  Exhaustion emits lost_ge=1 and
   disabled=1 once, then does no further selection/trace work.

   Unmatched ordinary ingress checks account1 and last static account
   only.  Nonce-shaped ingress additionally searches <=64 resolved
   accounts: the unchanged native fixture puts K at account6.  Ordinary
   K elsewhere is OUT OF SCOPE.  All hooks remain pack-only.

   Enabled storage: one uint per pool element (alignment can add up to
   64 bytes/element) and the fixed state below; no event ring/allocation.
   Selected signatures/public account K are public bytes, never keys. */
#ifndef FD_PACK_NONCE_WAKEUP_TRACE
#define FD_PACK_NONCE_WAKEUP_TRACE 0
#endif

#if FD_PACK_NONCE_WAKEUP_TRACE
#define FD_PACK_NT_READ       1U
#define FD_PACK_NT_WRITE      2U
#define FD_PACK_NT_LINEAGE    4U
#define FD_PACK_NT_NONCE      8U
#define FD_PACK_NT_ESTIMATED 16U
#define FD_PACK_NT_BUNDLE    32U
#define FD_PACK_NT_CAP    4096UL
#define FD_PACK_NT_WALK    128UL

typedef struct {
  ulong serial;
  ulong disabled;
  ulong lost_ge;
  ulong writer_valid;
  ulong writer_queued;
  uchar writer_sig[64];
  ulong writers_seen;
  ulong selected_queued;
  ulong selected_banks;
  ulong original_scheduled;
  ulong lineage_scheduled;
  ulong schedule_calls;
  ulong schedule_zero;
  ulong schedule_nonzero;
  ulong schedule_first;
  ulong end_block_seq;
  ulong clear_active;
} fd_pack_nt_state_t;

#define FD_PACK_NT_ORD_FIELD   uint nt_role;
#define FD_PACK_NT_PACK_FIELD  fd_pack_nt_state_t nt[1];
#define FD_PACK_NT_INIT(p)     memset( (p)->nt, 0, sizeof((p)->nt) )
#define FD_PACK_NT_RESET(o)    ((o)->nt_role=0U)
#define FD_PACK_NT_START(p)    fd_pack_nt_start(p)
#define FD_PACK_NT_BEGIN(p,o)  ((o)->nt_role=fd_pack_nt_select((p),(o)))
#define FD_PACK_NT_EST(o)      do { if( (o)->nt_role ) (o)->nt_role|=FD_PACK_NT_ESTIMATED; } while(0)
#define FD_PACK_NT_RESULT(p,o,r) fd_pack_nt_result((p),(o),(r))
#define FD_PACK_NT_BUNDLE_BEGIN(p,b,n) fd_pack_nt_bundle_begin((p),(b),(n))
#define FD_PACK_NT_BUNDLE_RESULT(p,b,n,r) fd_pack_nt_bundle_result((p),(b),(n),(r))
#define FD_PACK_NT_MATCH(p,o,s) fd_pack_nt_tx_t nt_old = fd_pack_nt_match((p),(o),(s))
#define FD_PACK_NT_REPLACE(p,o,event) fd_pack_nt_replace((p),(o),&nt_old,(event))
#define FD_PACK_NT_DELETE_BEGIN(p,o,a,b) fd_pack_nt_tx_t nt_deleted = fd_pack_nt_delete_begin((p),(o),(a),(b))
#define FD_PACK_NT_DELETE_END(p) fd_pack_nt_delete_end((p),&nt_deleted)
#define FD_PACK_NT_SCHEDULED(p,o,b) fd_pack_nt_scheduled((p),(o),(b))
#define FD_PACK_NT_SCHEDULE_RESULT(p,n,c,b,f) fd_pack_nt_schedule_result((p),(n),(c),(b),(f))
#define FD_PACK_NT_COMPLETE(p,b,after) fd_pack_nt_complete((p),(b),(after))
#define FD_PACK_NT_END_BLOCK(p,after) fd_pack_nt_end_block((p),(after))
#define FD_PACK_NT_CLEAR(p,after) fd_pack_nt_clear((p),(after))
#else
#define FD_PACK_NT_ORD_FIELD
#define FD_PACK_NT_PACK_FIELD
#define FD_PACK_NT_INIT(p) ((void)0)
#define FD_PACK_NT_RESET(o) ((void)0)
#define FD_PACK_NT_START(p) ((void)0)
#define FD_PACK_NT_BEGIN(p,o) ((void)0)
#define FD_PACK_NT_EST(o) ((void)0)
#define FD_PACK_NT_RESULT(p,o,r) ((void)0)
#define FD_PACK_NT_BUNDLE_BEGIN(p,b,n) ((void)0)
#define FD_PACK_NT_BUNDLE_RESULT(p,b,n,r) ((void)0)
#define FD_PACK_NT_MATCH(p,o,s) ((void)0)
#define FD_PACK_NT_REPLACE(p,o,event) ((void)0)
#define FD_PACK_NT_DELETE_BEGIN(p,o,a,b) ((void)0)
#define FD_PACK_NT_DELETE_END(p) ((void)0)
#define FD_PACK_NT_SCHEDULED(p,o,b) ((void)0)
#define FD_PACK_NT_SCHEDULE_RESULT(p,n,c,b,f) ((void)0)
#define FD_PACK_NT_COMPLETE(p,b,after) ((void)0)
#define FD_PACK_NT_END_BLOCK(p,after) ((void)0)
#define FD_PACK_NT_CLEAR(p,after) ((void)0)
#endif
#endif
