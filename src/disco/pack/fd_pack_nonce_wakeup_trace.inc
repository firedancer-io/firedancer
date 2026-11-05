/* Included after private pack/map/treap definitions.  Diagnostic metadata
   never participates in comparison, scheduling, validation, or deletion. */
#if FD_PACK_NONCE_WAKEUP_TRACE
#include "../fd_disco_base.h"
static fd_acct_addr_t const fd_pack_nt_k = {{
  'K','K','K','K','K','K','K','K','K','K','K','K','K','K','K','K',
  'K','K','K','K','K','K','K','K','K','K','K','K','K','K','K','K'
}};

typedef struct {
  uchar sig[64];
  uint role;
  uint rewards;
  uint compute;
} fd_pack_nt_tx_t;

static inline uint
fd_pack_nt_select( fd_pack_t const * pack, fd_pack_ord_txn_t const * ord ) {
  if( FD_UNLIKELY( pack->nt->disabled ) ) return 0U;
  fd_txn_t const * txn = TXN(ord->txn);
  fd_acct_addr_t const * a = fd_txn_get_acct_addrs( txn, ord->txn->payload );
  ulong imm = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_IMM );
  ulong all = fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_ALL );
  ulong idx = ULONG_MAX;
  if( imm>1UL && !memcmp( a[1].b, fd_pack_nt_k.b, 32UL ) ) idx=1UL;
  else if( imm && !memcmp( a[imm-1UL].b, fd_pack_nt_k.b, 32UL ) ) idx=imm-1UL;
  int nonce = fd_disco_tpu_is_durable_nonce( txn, ord->txn->payload );
  if( idx==ULONG_MAX && nonce && all<=64UL ) {
    for( ulong j=0UL; j<all; j++ ) {
      fd_acct_addr_t const * key = j<imm ? a+j : ord->txn_e->alt_accts+(j-imm);
      if( !memcmp( key->b, fd_pack_nt_k.b, 32UL ) ) { idx=j; break; }
    }
  }
  if( idx==ULONG_MAX ) return 0U;
  return (fd_txn_is_writable( txn, (ushort)idx ) ? FD_PACK_NT_WRITE : FD_PACK_NT_READ)
       | (nonce ? FD_PACK_NT_NONCE : 0U);
}

static inline fd_pack_nt_tx_t
fd_pack_nt_capture( fd_pack_ord_txn_t const * ord ) {
  fd_pack_nt_tx_t t = { .role=ord->nt_role, .rewards=0U, .compute=0U };
  if( t.role ) {
    memcpy( t.sig, TXNE_TO_SIG(ord->txn_e), 64UL );
    if( t.role & FD_PACK_NT_ESTIMATED ) { t.rewards=ord->rewards; t.compute=ord->compute_est; }
  }
  return t;
}

/* Query by all64 signature bytes each time.  Never save a pool/map/treap
   pointer over a mutation; penalty-map removal can relocate its owners. */
static inline fd_pack_ord_txn_t const *
fd_pack_nt_lookup( fd_pack_t const * pack, uchar const sig[64] ) {
  fd_txn_e_t q;
  TXN(q.txnp)->signature_off=0U;
  memcpy( q.txnp->payload, sig, 64UL );
  ulong idx = sig2txn_idx_query_const( pack->signature_map, &q, ULONG_MAX, pack->pool );
  return idx==ULONG_MAX ? NULL : pack->pool+idx;
}

/* Actual membership, independent of the transaction's root tag.  Every
   upward edge must be reciprocated by exactly one child edge, and the
   terminal node must be this tree's actual root with a null parent.
   -1 means unknown/invalid/depth cap, not absent. */
static int
fd_pack_nt_member( fd_pack_t const * pack, fd_pack_ord_txn_t const * ord, treap_t const * tree ) {
  if( !ord || !tree ) return 0;
  if( (ulong)tree->root==treap_idx_null() ) return treap_ele_cnt(tree) ? -1 : 0;
  ulong n = trp_pool_max( pack->pool );
  ulong i = (ulong)(ord-pack->pool);
  for( ulong step=0UL; step<FD_PACK_NT_WALK; step++ ) {
    if( i>=n ) return -1;
    ulong parent = pack->pool[i].parent;
    if( parent==treap_idx_null() ) return i==(ulong)tree->root;
    if( parent>=n ) return -1;
    int left = (ulong)pack->pool[parent].left==i;
    int right = (ulong)pack->pool[parent].right==i;
    if( left==right ) return -1;
    i=parent;
  }
  return -1;
}

static void
fd_pack_nt_hex( char out[129], uchar const * sig ) {
  char const * h="0123456789abcdef";
  for( ulong i=0UL; i<64UL; i++ ) {
    uchar b=sig ? sig[i] : 0U;
    out[2UL*i]=h[b>>4]; out[2UL*i+1UL]=h[b&15U];
  }
  out[128]='\0';
}

static void
fd_pack_nt_emit( fd_pack_t * pack, char const * event, fd_pack_nt_tx_t const * tx,
                 fd_pack_nt_tx_t const * peer, long result, ulong aux, ulong arg, ulong flags ) {
  fd_pack_nt_state_t * s=pack->nt;
  if( s->disabled ) return;
  if( s->serial>=FD_PACK_NT_CAP-1UL ) {
    s->disabled=1UL; s->lost_ge=1UL;
    FD_LOG_NOTICE(( "PACK_NONCE_WAKEUP_V1 serial=%lu tick=%lu event=DISABLED lost_ge=1 disabled=1 cap=4096",
                    ++s->serial, (ulong)fd_tickcount() ));
    return;
  }
  fd_pack_ord_txn_t const * writer = s->writer_valid ? fd_pack_nt_lookup( pack, s->writer_sig ) : NULL;
  fd_pack_ord_txn_t const * subject = tx && tx->role ? fd_pack_nt_lookup( pack, tx->sig ) : NULL;
  fd_pack_ord_txn_t const * prior = peer && peer->role ? fd_pack_nt_lookup( pack, peer->sig ) : NULL;
  fd_pack_bitset_acct_mapping_t const * refs = bitset_map_query( pack->acct_to_bitset, fd_pack_nt_k, NULL );
  fd_pack_penalty_treap_t const * penalty = penalty_map_query( pack->penalty_treaps, fd_pack_nt_k, NULL );
  fd_pack_addr_use_t const * use = acct_uses_query( pack->acct_in_use, fd_pack_nt_k, NULL );
  int wp=fd_pack_nt_member( pack, writer, pack->pending );
  int wk=fd_pack_nt_member( pack, writer, penalty ? penalty->penalty_treap : NULL );
  int wb=fd_pack_nt_member( pack, writer, pack->pending_bundles );
  char sig[129], old[129], wsig[129];
  fd_pack_nt_hex( sig, tx && tx->role ? tx->sig : NULL );
  fd_pack_nt_hex( old, peer && peer->role ? peer->sig : NULL );
  fd_pack_nt_hex( wsig, s->writer_valid ? s->writer_sig : NULL );
  FD_LOG_NOTICE(( "PACK_NONCE_WAKEUP_V1 serial=%lu tick=%lu event=%s lost_ge=0 disabled=0 "
                  "sig=%s peer=%s role=%u result=%ld aux=%lu arg=%lu flags=%lu rewards=%u compute=%u "
                  "subject_present=%u subject_root=%d peer_present=%u peer_root=%d peer_rewards=%u peer_compute=%u "
                  "queue=%lu selected_queue=%lu k_refs=%lu k_penalty=%lu "
                  "k_use=%lx inflight=%lx selected_banks=%lx writer=%s writer_present=%u writer_root=%d "
                  "writer_pending=%d writer_penalty=%d writer_bundle=%d writers=%lu original_scheduled=%lu "
                  "lineage_scheduled=%lu opportunities=%lu zero=%lu nonzero=%lu end_seq=%lu expire_before=%lu "
                  "block_cus=%lu max_block_cus=%lu bytes=%lu max_bytes=%lu microblocks=%lu max_microblocks=%lu",
                  ++s->serial, (ulong)fd_tickcount(), event, sig, old, tx ? tx->role : 0U,
                  result, aux, arg, flags, tx ? tx->rewards : 0U, tx ? tx->compute : 0U,
                  (uint)!!subject, subject ? subject->root : -1, (uint)!!prior, prior ? prior->root : -1,
                  peer ? peer->rewards : 0U, peer ? peer->compute : 0U, pack->pending_txn_cnt, s->selected_queued,
                  refs ? refs->ref_cnt : 0UL, penalty ? treap_ele_cnt(penalty->penalty_treap) : 0UL,
                  use ? use->in_use_by : 0UL, pack->outstanding_microblock_mask, s->selected_banks,
                  wsig, (uint)!!writer, writer ? writer->root : -1, wp, wk, wb, s->writers_seen,
                  s->original_scheduled, s->lineage_scheduled, s->schedule_calls, s->schedule_zero,
                  s->schedule_nonzero, s->end_block_seq, pack->expire_before,
                  pack->cumulative_block_cost, pack->lim->max_cost_per_block,
                  pack->data_bytes_consumed, pack->lim->max_data_bytes_per_block,
                  pack->microblock_cnt, pack->lim->max_microblocks_per_block ));
}

static void
fd_pack_nt_start( fd_pack_t * pack ) {
  if( !pack->nt->serial ) fd_pack_nt_emit( pack, "INIT", NULL, NULL, 0L, FD_PACK_NT_CAP, FD_PACK_NT_WALK, 0UL );
}

static void
fd_pack_nt_result( fd_pack_t * pack, fd_pack_ord_txn_t const * ord, int result ) {
  if( !ord->nt_role || pack->nt->disabled ) return;
  fd_pack_nt_tx_t t=fd_pack_nt_capture(ord);
  if( result>=0 ) {
    pack->nt->selected_queued++;
    if( t.role & FD_PACK_NT_WRITE ) {
      pack->nt->writers_seen++;
      if( !pack->nt->writer_valid ) {
        memcpy( pack->nt->writer_sig, t.sig, 64UL );
        pack->nt->writer_valid=1UL; pack->nt->writer_queued=1UL;
      }
    }
  }
  fd_pack_nt_emit( pack, result>=0 ? "ADMIT" : "REJECT", &t, NULL, (long)result, 0UL, 0UL, 0UL );
}

static void
fd_pack_nt_bundle_begin( fd_pack_t * pack, fd_txn_e_t * const * bundle, ulong n ) {
  for( ulong i=0UL; i<n; i++ ) {
    fd_pack_ord_txn_t * o=(fd_pack_ord_txn_t *)bundle[i];
    o->nt_role=fd_pack_nt_select(pack,o);
    if( o->nt_role ) o->nt_role|=FD_PACK_NT_BUNDLE;
  }
}

static void
fd_pack_nt_bundle_result( fd_pack_t * pack, fd_txn_e_t * const * bundle, ulong n, int result ) {
  for( ulong i=0UL; i<n; i++ ) fd_pack_nt_result(pack,(fd_pack_ord_txn_t *)bundle[i],result);
}

static fd_pack_nt_tx_t
fd_pack_nt_match( fd_pack_t * pack, fd_pack_ord_txn_t * ord, fd_pack_ord_txn_t const * old ) {
  if( pack->nt->disabled ) return (fd_pack_nt_tx_t){0};
  fd_pack_nt_tx_t t=fd_pack_nt_capture(old);
  if( t.role || ord->nt_role ) ord->nt_role|=FD_PACK_NT_LINEAGE|FD_PACK_NT_NONCE|FD_PACK_NT_ESTIMATED;
  if( ord->nt_role && !pack->nt->disabled ) {
    /* Include the old signature even when selection came only from new. */
    memcpy(t.sig,TXNE_TO_SIG(old->txn_e),64UL);
    t.role=old->nt_role ? old->nt_role : FD_PACK_NT_LINEAGE;
    t.rewards=old->rewards; t.compute=old->compute_est;
    fd_pack_nt_tx_t now=fd_pack_nt_capture(ord);
    fd_pack_nt_emit(pack,"NONCE_MATCH",&now,&t,0L,0UL,0UL,0UL);
  }
  return t;
}

static void
fd_pack_nt_replace( fd_pack_t * pack, fd_pack_ord_txn_t const * ord, fd_pack_nt_tx_t const * old, char const * event ) {
  if( !ord->nt_role || pack->nt->disabled ) return;
  fd_pack_nt_tx_t t=fd_pack_nt_capture(ord);
  fd_pack_nt_emit(pack,event,&t,old,0L,0UL,0UL,0UL);
}

static fd_pack_nt_tx_t
fd_pack_nt_delete_begin( fd_pack_t * pack, fd_pack_ord_txn_t const * ord, int bundle, int wake ) {
  if( pack->nt->disabled ) return (fd_pack_nt_tx_t){0};
  fd_pack_nt_tx_t t=fd_pack_nt_capture(ord);
  if( t.role ) fd_pack_nt_emit(pack,"DELETE_BEFORE",&t,NULL,0L,(ulong)bundle,(ulong)wake,0UL);
  return t;
}

static void
fd_pack_nt_delete_end( fd_pack_t * pack, fd_pack_nt_tx_t const * t ) {
  if( !t->role || pack->nt->disabled ) return;
  if( pack->nt->selected_queued ) pack->nt->selected_queued--;
  if( pack->nt->writer_valid && !memcmp(t->sig,pack->nt->writer_sig,64UL) ) pack->nt->writer_queued=0UL;
  fd_pack_nt_emit(pack,"DELETE_AFTER",t,NULL,1L,0UL,0UL,0UL);
}

static void
fd_pack_nt_scheduled( fd_pack_t * pack, fd_pack_ord_txn_t const * ord, ulong bank ) {
  if( !ord->nt_role || pack->nt->disabled ) return;
  fd_pack_nt_tx_t t=fd_pack_nt_capture(ord);
  pack->nt->selected_banks|=1UL<<bank;
  if( pack->nt->selected_queued ) pack->nt->selected_queued--;
  if( (t.role & FD_PACK_NT_NONCE) && (t.role & FD_PACK_NT_READ) && !(t.role & FD_PACK_NT_LINEAGE) )
    pack->nt->original_scheduled++;
  if( t.role & FD_PACK_NT_LINEAGE ) pack->nt->lineage_scheduled++;
  if( pack->nt->writer_valid && !memcmp(t.sig,pack->nt->writer_sig,64UL) ) pack->nt->writer_queued=0UL;
  /* Before removal: the full-signature map/tree still contains subject.
     K references already reflect this schedule's released references. */
  fd_pack_nt_emit(pack,"SCHEDULE_SELECTED",&t,NULL,1L,bank,0UL,0UL);
}

static void
fd_pack_nt_schedule_result( fd_pack_t * pack, ulong n, ulong cus, ulong bank, int flags ) {
  fd_pack_nt_state_t * s=pack->nt;
  if( s->disabled || !(s->writer_queued || s->selected_banks) ) return;
  s->schedule_calls++;
  if( n ) s->schedule_nonzero++; else s->schedule_zero++;
  if( !s->schedule_first ) {
    s->schedule_first=1UL; /* <=one checkpoint per block, never per-call logging */
    fd_pack_nt_emit(pack,"SCHEDULE_RESULT",NULL,NULL,(long)n,cus,bank,(ulong)flags);
  }
}

static void
fd_pack_nt_complete( fd_pack_t * pack, ulong bank, int after ) {
  if( pack->nt->disabled || !(pack->nt->selected_banks & (1UL<<bank)) ) return;
  if( after ) pack->nt->selected_banks &= ~(1UL<<bank);
  fd_pack_nt_emit(pack,after ? "COMPLETE_AFTER" : "COMPLETE_BEFORE",NULL,NULL,0L,bank,0UL,0UL);
}

static void
fd_pack_nt_end_block( fd_pack_t * pack, int after ) {
  if( pack->nt->disabled || !(pack->nt->selected_queued || pack->nt->selected_banks) ) return;
  if( after ) { pack->nt->selected_banks=0UL; pack->nt->schedule_first=0UL; }
  else pack->nt->end_block_seq++;
  fd_pack_nt_emit(pack,after ? "END_BLOCK_AFTER" : "END_BLOCK_BEFORE",NULL,NULL,0L,0UL,0UL,0UL);
}

static void
fd_pack_nt_clear( fd_pack_t * pack, int after ) {
  if( pack->nt->disabled ) return;
  if( !after ) pack->nt->clear_active=!!(pack->nt->selected_queued || pack->nt->selected_banks);
  if( !pack->nt->clear_active ) return;
  if( after ) { pack->nt->selected_queued=0UL; pack->nt->writer_queued=0UL; pack->nt->selected_banks=0UL; }
  fd_pack_nt_emit(pack,after ? "CLEAR_AFTER" : "CLEAR_BEFORE",NULL,NULL,0L,0UL,0UL,0UL);
  if( after ) pack->nt->clear_active=0UL;
}
#endif
