/* The failover controller: the state machine the failov tile drives
   from its stem callbacks.  ctx->action holds the state, one of
   FD_FAILOVER_ACTION_*, and set_action is its only writer.

   Two machines share one identity.  The holder gives it up through the
   demotion flow and the taker adopts it through the handoff request and
   promotion flows.

     Holder, giving up the identity        Taker, adopting it

     IDLE                                  IDLE
      | accept_handoff                      | run_handoff_cmd
     DEMOTE_SWITCH                         HANDOFF_WAIT_PEER
      | the admin tile installs the junk    | poll_peer dials and sends
      | key, step_demote_switch             | HANDOFF_REQUEST, on_demoted_msg
     DEMOTE_DRAIN                           | takes the final state
      | the votor's last votes arrive,     PROMOTE_WAIT_REPLAY
      | step_demote_drain                   | replay reaches the anchor,
     DEMOTE_WAIT_ACK                        | step_promote_wait_replay
      | DEMOTED sent, the peer answers,    PROMOTE_WAIT_ADOPT
      | on_demoted_answer_msg               | the votor adopts the history,
     IDLE                                   | step_promote_wait_adopt
                                           PROMOTE_SWITCH
                                            | the admin tile installs the
                                            | identity, step_promote_switch
                                           HANDOFF_WAIT_RESULT
                                            | the peer records our answer,
                                            | on_handoff_result_msg
                                           IDLE

   This is not a translation unit. Keep it free of stem callbacks and
   the topology or seccomp, which stay in the tile. */

/* The state */

static char const * const action_names[ FD_FAILOVER_ACTION_CNT ] = {
  [ FD_FAILOVER_ACTION_IDLE                ] = "idle",
  [ FD_FAILOVER_ACTION_DEMOTE_SWITCH       ] = "demote_switch",
  [ FD_FAILOVER_ACTION_DEMOTE_DRAIN        ] = "demote_drain",
  [ FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK     ] = "demote_wait_ack",
  [ FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER   ] = "handoff_wait_peer",
  [ FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY ] = "promote_wait_replay",
  [ FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT  ] = "promote_wait_adopt",
  [ FD_FAILOVER_ACTION_PROMOTE_SWITCH      ] = "promote_switch",
  [ FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ] = "handoff_wait_result",
};

static char const *
get_action_name( ulong action ) {
  return action<FD_FAILOVER_ACTION_CNT ? action_names[ action ] : "unknown";
}

/* Our handoff request is open, before or after its promotion. */
static inline int
is_requesting( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT;
}

static inline int
is_promoting( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY || ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT ||
         ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH;
}

/* Only an identity switch leaves DEMOTE_SWITCH and DEMOTE_DRAIN, a peer
   message cannot. */
static inline int
is_switching_out( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH || ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN;
}

static inline int
is_switch_pending( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->id_switch.pending_key!=FD_FAILOVER_SWITCH_KEY_CNT;
}

/* Moves to action and arms its deadline, FD_FAILOVER_DEADLINE_SLOTS of
   replay and as many seconds of our clock, so a stalled replay still
   times out.  A state entered again, as a forced promotion does when it
   falls back, is logged but keeps its deadline. */
static void
set_action( fd_failover_tile_ctx_t * ctx,
            ulong                    action ) {
  FD_LOG_INFO(( "action %s -> %s", get_action_name( ctx->action ), get_action_name( action ) ));
  if( FD_LIKELY( action!=ctx->action ) ) {
    ctx->deadline_slot = ctx->replay_slot==FD_FAILOVER_SLOT_NULL ? FD_FAILOVER_SLOT_NULL : fd_ulong_sat_add( ctx->replay_slot, FD_FAILOVER_DEADLINE_SLOTS );
    ctx->deadline_at   = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_DEADLINE_NANOS );
  }
  ctx->action = action;
}

/* The current state passed its slot deadline or its clock deadline. */
static int
is_overdue( fd_failover_tile_ctx_t const * ctx ) {
  int slots = ctx->deadline_slot!=FD_FAILOVER_SLOT_NULL && ctx->replay_slot!=FD_FAILOVER_SLOT_NULL && ctx->replay_slot>ctx->deadline_slot;
  return slots || fd_failover_clock()>=ctx->deadline_at;
}

/* Returns the controller to IDLE with nothing in flight.  The caller
   takes a new boot id, so the other machine treats anything bound to the
   old one as from a restarted peer. */
static void
reset_controller( fd_failover_tile_ctx_t * ctx ) {
  fd_memset( &ctx->request,   0, sizeof(ctx->request)   );
  fd_memset( &ctx->handoff,   0, sizeof(ctx->handoff)   );
  fd_memset( &ctx->promotion, 0, sizeof(ctx->promotion) );
  fd_memset( &ctx->reply,     0, sizeof(ctx->reply)     );
  fd_memset( &ctx->tx,        0, sizeof(ctx->tx)        );
  ctx->cmd_addr                 = 0U;
  ctx->cmd_port                 = (ushort)0;
  ctx->adopt_result_fresh       = 0;
  ctx->session.close_after_send = 0;
  ctx->peer_history.valid       = 0;
  ctx->current_history.valid    = 0;
  ctx->last_vote_slot           = FD_FAILOVER_SLOT_NULL;
  ctx->stuck                    = 0;
  set_action( ctx, FD_FAILOVER_ACTION_IDLE );
}

/* Shared helpers: the session, the control queue and the log */

static inline ushort
get_dial_port( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->cmd_port ? ctx->cmd_port : FD_FAILOVER_DEFAULT_PORT;
}

/* The peer on the current session is the bound one. */
static inline int
is_bound_peer( fd_failover_tile_ctx_t const * ctx,
               fd_failover_peer_t const *     bound ) {
  return is_same_peer( bound, fd_failover_channel_peer_hello( ctx->channel )->boot_id );
}

/* Sets the installed identity this machine currently signs with. */
static void
set_installed( fd_failover_tile_ctx_t * ctx,
               uchar const *            pubkey ) {
  fd_memcpy( ctx->installed, pubkey, 32UL );
  ctx->hello.holds = (uchar)holds_identity( ctx );
  fd_failover_channel_set_holds( ctx->channel, ctx->hello.holds );
}

static void
finish_cmd( fd_failover_tile_ctx_t * ctx,
            ulong                    result ) {
  if( FD_LIKELY( !ctx->cmd_nonce || ctx->cmd_done ) ) return;
  if( FD_LIKELY( result==FD_ADMINCTL_RESULT_SUCCESS ) ) FD_LOG_NOTICE (( "`failover promote` done, this machine runs the identity" ));
  else                                                  FD_LOG_WARNING(( "`failover promote` failed, %s", fd_adminctl_failover_result_cstr( result ) ));
  ctx->cmd_result = result;
  ctx->cmd_done   = 1;
}

/* Logs a step of a command at NOTICE. */
#define LOG_CMD_STEP( ctx, ... ) do {                                                                           \
    FD_LOG_NOTICE(( __VA_ARGS__ ));                                                                              \
    fd_cstr_printf( (ctx)->cmd_step[ (ctx)->cmd_step_head%FD_FAILOVER_STEP_CNT ], FD_FAILOVER_BUS_STEP_MAX, NULL, __VA_ARGS__ ); \
    (ctx)->cmd_step_head++;                                                                                      \
    if( (ctx)->cmd_step_head-(ctx)->cmd_step_tail>FD_FAILOVER_STEP_CNT ) (ctx)->cmd_step_tail++;                  \
  } while(0)

/* Updates our session state when the channel's session changes. */
static void
sync_session( fd_failover_tile_ctx_t * ctx ) {
  ulong state      = fd_failover_channel_state( ctx->channel );
  ulong generation = fd_failover_channel_generation( ctx->channel );
  if( FD_LIKELY( state==ctx->session.state && generation==ctx->session.generation ) ) return;
  ctx->session.state            = state;
  ctx->session.generation       = generation;
  ctx->request.sent             = 0;
  ctx->session.close_after_send = 0;
  if( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_HANDOFF_RESULT ) ctx->tx.valid = 0;
  if( FD_LIKELY( state!=FD_FAILOVER_SESSION_PAIRED ) ) return;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  ctx->session.peer_boot_id = peer->boot_id;
  if( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_SENT ) ctx->handoff.delivery = FD_FAILOVER_DELIVERY_PENDING;
  if( FD_UNLIKELY( peer->holds ) ) {
    /* A peer running the identity voted past any final state we saved. */
    if( is_promoting( ctx ) ) ctx->promotion.holder_seen = 1;
    if( ctx->peer_history.valid ) FD_LOG_NOTICE(( "peer boot %016lx runs the identity, discarding the saved final state, keeping the coverage floors", peer->boot_id ));
    ctx->peer_history.valid = 0;
  }
}

/* Drops the session and stops dialing. */
static void
hang_up( fd_failover_tile_ctx_t * ctx,
         long                     now ) {
  fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  fd_failover_channel_hangup( ctx->channel, now );
  sync_session( ctx );
}

/* Only one control message can be outstanding at a time.  Its recipient
   is fixed even if the connection changes before it is sent. */
static int
queue_control( fd_failover_tile_ctx_t *   ctx,
               ushort                     type,
               fd_failover_peer_t const * to,
               void const *               payload,
               ulong                      payload_sz ) {
  if( FD_UNLIKELY( ctx->tx.valid || !payload_sz || payload_sz>sizeof(ctx->tx.payload) ) ) return -1;
  ctx->tx.type  = type;
  ctx->tx.sz    = (ushort)payload_sz;
  ctx->tx.valid = 1;
  ctx->tx.to    = *to;
  fd_memcpy( ctx->tx.payload, payload, payload_sz );
  return 0;
}

static int
queue_demoted( fd_failover_tile_ctx_t * ctx ) {
  return queue_control( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, &ctx->handoff.target, ctx->handoff.payload, ctx->handoff.payload_sz );
}

/* Tells the requester how its handoff ended and closes the session once
   that has drained.  A NULL to means the peer on the current session. */
static void
queue_handoff_result( fd_failover_tile_ctx_t *   ctx,
                      fd_failover_peer_t const * to,
                      ulong                      id,
                      ulong                      result ) {
  fd_failover_peer_t peer;
  if( !to ) {
    peer.boot_id = fd_failover_channel_peer_hello( ctx->channel )->boot_id;
    to = &peer;
  }
  fd_failover_handoff_result_t response = { .handoff_id=id, .result=result };
  if( FD_LIKELY( !queue_control( ctx, FD_FAILOVER_MSG_HANDOFF_RESULT, to, &response, sizeof(response) ) ) ) {
    ctx->session.close_after_send = 1;
  }
}

/* Queues our last response to a DEMOTED.  If the control slot is busy it
   stays pending and step_controller retries once the slot drains. */
static void
queue_reply( fd_failover_tile_ctx_t * ctx ) {
  uchar payload[ sizeof(fd_failover_promote_rejected_t) ];
  ulong payload_sz = ctx->reply.type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK
                     ? fd_failover_promote_ack_encode( payload, ctx->reply.handoff_id )
                     : fd_failover_promote_rejected_encode( payload, ctx->reply.handoff_id, ctx->reply.reason );
  ctx->reply.state = queue_control( ctx, ctx->reply.type, &ctx->reply.peer, payload, payload_sz ) ? FD_FAILOVER_REPLY_PENDING : FD_FAILOVER_REPLY_KEPT;
}

/* Remembers our response to the DEMOTED with handoff_id from peer and
   queues it.  The same DEMOTED again gets the same response. */
static void
finish_reply( fd_failover_tile_ctx_t *   ctx,
              fd_failover_peer_t const * peer,
              ulong                      handoff_id,
              ushort                     type,
              uchar                      reason ) {
  ctx->reply.peer       = *peer;
  ctx->reply.handoff_id = handoff_id;
  ctx->reply.type       = type;
  ctx->reply.reason     = reason;
  queue_reply( ctx );
}

static char const *
get_handoff_name( ulong result ) {
  static char const * const names[ FD_FAILOVER_HANDOFF_CNT ] = {
    "none", "pending", "taken", "declined", "restarted", "cancelled", "not holder"
  };
  return result<FD_FAILOVER_HANDOFF_CNT ? names[ result ] : "unknown";
}

static char const *
get_msg_name( ushort type ) {
  switch( type ) {
  case (ushort)FD_FAILOVER_MSG_DEMOTED:          return "DEMOTED";
  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK:      return "PROMOTE_ACK";
  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED: return "PROMOTE_REJECTED";
  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESULT:   return "HANDOFF_RESULT";
  default:                                       return "unknown";
  }
}

/* Sends the queued control message once the session can take it. */
static void
flush_pending( fd_failover_tile_ctx_t * ctx,
               long                     now ) {
  if( FD_LIKELY( !ctx->tx.valid ) ) return;
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED || fd_failover_channel_tx_pending( ctx->channel ) ) ) return;
  if( FD_UNLIKELY( !is_bound_peer( ctx, &ctx->tx.to ) ) ) return;
  if( FD_UNLIKELY( fd_failover_channel_send( ctx->channel, now, ctx->tx.type, ctx->tx.payload, ctx->tx.sz ) ) ) return;
  if( ctx->tx.type==(ushort)FD_FAILOVER_MSG_DEMOTED && ctx->handoff.delivery==FD_FAILOVER_DELIVERY_PENDING ) ctx->handoff.delivery = FD_FAILOVER_DELIVERY_SENT;
  if( ctx->tx.type==(ushort)FD_FAILOVER_MSG_HANDOFF_RESULT ) {
    fd_failover_handoff_result_t result;
    fd_memcpy( &result, ctx->tx.payload, sizeof(result) );
    FD_LOG_NOTICE(( "handoff %lu: sent HANDOFF_RESULT to peer boot %016lx, %s", result.handoff_id, ctx->tx.to.boot_id, fd_adminctl_failover_result_cstr( result.result ) ));
  } else {
    ulong id = ctx->tx.type==(ushort)FD_FAILOVER_MSG_DEMOTED ? ctx->handoff.id : ctx->reply.handoff_id;
    FD_LOG_NOTICE(( "handoff %lu: sent %s to peer boot %016lx", id, get_msg_name( ctx->tx.type ), ctx->tx.to.boot_id ));
  }
  ctx->tx.valid = 0;
}

static char const *
get_reject_name( uint reason ) {
  static char const * const names[ FD_FAILOVER_REJECT_CNT ] = {
    "none", "busy", "holds identity", "replay behind", "adoption mismatch", "adoption failed", "switch failed"
  };
  return reason<FD_FAILOVER_REJECT_CNT ? names[ reason ] : "unknown";
}

static char const *
get_adopt_err_name( ulong result ) {
  switch( result ) {
  case FD_VOTOR_ADOPT_ERR_DECODE:          return "decode error";
  case FD_VOTOR_ADOPT_ERR_INVALID:         return "invalid";
  case FD_VOTOR_ADOPT_ERR_UNREPLAYED_ROOT: return "finality anchor not replayed";
  case FD_VOTOR_ADOPT_ERR_UNREPLAYED:      return "consensus not initialized";
  case FD_VOTOR_ADOPT_ERR_STALE:           return "older than the votes this machine sent as this identity";
  case FD_VOTOR_ADOPT_ERR_CAPACITY:        return "insufficient slot state capacity";
  default:                                 return "unknown";
  }
}

static char const *
get_source_name( ulong source ) {
  return source==FD_FAILOVER_SOURCE_PEER ? "the vote history the peer gave us" : "an empty history";
}

/* Inputs: vote history, gossip and the identity switch */

static void
prepare_history( fd_failover_tile_ctx_t *    ctx,
                 fd_votor_hist_msg_t const * hist ) {
  uchar state[ FD_FAILOVER_ALPENGLOW_STATE_MAX ];
  ulong state_sz = 0UL;
  if( FD_UNLIKELY( ag_hist_ser( &hist->hist, state, FD_FAILOVER_ALPENGLOW_STATE_MAX, &state_sz ) || ag_hist_tip( &hist->hist )!=hist->vote_slot ) ) {
    if( FD_UNLIKELY( !ctx->hist_warned ) ) FD_LOG_WARNING(( "votor produced a vote history that does not match its slot metadata" ));
    ctx->hist_warned = 1;
    return;
  }
  ctx->hist_warned = 0;
  fd_memcpy( ctx->current_history.state, state, state_sz );
  ctx->current_history.valid = 1;
  ctx->current_history.tip   = hist->vote_slot;
  ctx->current_history.sz    = state_sz;
}

/* Takes in a votor_hist frame: replay and root slots, and the history
   of the identity we hand off once the votor streams it in full. */
static void
on_votor_hist_msg( fd_failover_tile_ctx_t *    ctx,
                   fd_votor_hist_msg_t const * hist ) {
  if( FD_LIKELY( hist->replay_slot!=FD_FAILOVER_SLOT_NULL && ( ctx->replay_slot==FD_FAILOVER_SLOT_NULL || hist->replay_slot>ctx->replay_slot ) ) ) ctx->replay_slot = hist->replay_slot;
  if( FD_LIKELY( hist->root_slot!=FD_FAILOVER_SLOT_NULL ) ) ctx->root_slot = hist->root_slot;
  /* Histories of another key can arrive during preparation or after the switch. */
  if( FD_UNLIKELY( !fd_memeq( hist->identity.uc, ctx->hello.staked_pubkey, 32UL ) || hist->vote_slot==FD_FAILOVER_SLOT_NULL ) ) return;
  /* The drain still takes the history of our last votes after the
     switch to the junk key. */
  int producing = holds_identity( ctx ) || ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH || ctx->action==FD_FAILOVER_ACTION_DEMOTE_DRAIN;
  /* A vote we signed, or the first history with a vote in it while we
     run the identity, cast before we tracked our votes. */
  int voted     = hist->has_vote || ( producing && ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL );
  /* A frame with no new vote can still change the history, after a
     LEADER or a vote marked unsent. */
  int changed   = producing && ctx->current_history.valid && hist->vote_slot>=ctx->last_vote_slot;
  if( FD_LIKELY( !voted && !changed ) ) return;
  ctx->last_vote_slot = hist->vote_slot;
  if( voted && ( ctx->own_floor==FD_FAILOVER_SLOT_NULL || hist->vote_slot>ctx->own_floor ) ) ctx->own_floor = hist->vote_slot;
  /* The tip of a history always counts toward the floor. */
  if( hist->has_vote ) ctx->own_voted = 1;
  prepare_history( ctx, hist );
}

/* The address of the machine running the identity comes from gossip. */
static void
on_contact_info_msg( fd_failover_tile_ctx_t * ctx,
                     long                     now ) {
  uint addr = ctx->gossip_socket.addr;
  if( FD_UNLIKELY( !addr || !fd_memeq( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL ) ) ) return;
  if( FD_UNLIKELY( addr==ctx->own_gossip.addr && ctx->gossip_socket.port==ctx->own_gossip.port ) ) return;
  ctx->staked_seen_at = now;
  if( FD_UNLIKELY( ctx->peer_history.valid ) ) {
    /* Another host votes as the identity past any final state we saved. */
    FD_LOG_NOTICE(( "gossip shows the identity at `" FD_IP4_ADDR_FMT "`, discarding the saved final state, keeping the coverage floors", FD_IP4_ADDR_FMT_ARGS( addr ) ));
    ctx->peer_history.valid = 0;
  }
  if( FD_LIKELY( addr==ctx->staked_addr ) ) return;
  FD_LOG_NOTICE(( "gossip shows the identity at `" FD_IP4_ADDR_FMT "`, a handoff from this machine dials it", FD_IP4_ADDR_FMT_ARGS( addr ) ));
  ctx->staked_addr = addr;
}

/* Sends the promotion's history or empty bound to the votor for the
   target identity.  Returns the request id, which the response echoes,
   or ULONG_MAX if there was nothing to send. */
static ulong
publish_adopt_state( fd_failover_tile_ctx_t * ctx,
                     fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->adopt_out_idx==ULONG_MAX || !ctx->promotion.adopt.sz ) ) return ULONG_MAX;
  if( FD_UNLIKELY( !++ctx->adopt_request_id ) ) ctx->adopt_request_id++;
  uchar * req = fd_chunk_to_laddr( ctx->adopt_out_mem, ctx->adopt_out_chunk );
  ulong   sz  = FD_VOTOR_ADOPT_REQ_HDR_SZ+ctx->promotion.adopt.sz;
  fd_memcpy( req,                           ctx->hello.staked_pubkey,   FD_VOTOR_ADOPT_REQ_HDR_SZ );
  fd_memcpy( req+FD_VOTOR_ADOPT_REQ_HDR_SZ, ctx->promotion.adopt.state, ctx->promotion.adopt.sz  );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->adopt_out_idx, ctx->adopt_request_id, ctx->adopt_out_chunk, sz, 0UL, tspub, tspub );
  ctx->adopt_out_chunk    = fd_dcache_compact_next( ctx->adopt_out_chunk, sz, ctx->adopt_out_chunk0, ctx->adopt_out_wmark );
  ctx->adopt_result_fresh = 0;
  return ctx->adopt_request_id;
}

/* Asks the admin tile to switch to the given key.  Only the public key
   goes out, the sign tile preloaded both keypairs.  One request can be
   in flight, and the reply echoes its id so a late reply can be told
   apart.  Returns the id, or ULONG_MAX if nothing was sent. */
static ulong
request_switch( fd_failover_tile_ctx_t * ctx,
                fd_stem_context_t *      stem,
                ulong                    key ) {
  if( FD_UNLIKELY( ctx->admin_out_idx==ULONG_MAX || is_switch_pending( ctx ) ) ) return ULONG_MAX;
  if( FD_UNLIKELY( !++ctx->id_switch.request_id ) ) ctx->id_switch.request_id++;
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce = ctx->id_switch.request_id;
  fd_failover_switch_req_t req = { .epoch=ctx->id_switch.epoch };
  fd_memcpy( req.identity, key==FD_FAILOVER_SWITCH_KEY_STAKED ? ctx->hello.staked_pubkey : ctx->spare_pubkey, 32UL );
  fd_memcpy( out->payload, &req, sizeof(req) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_SWITCH_REQ, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk       = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
  ctx->id_switch.pending_key = key;
  ctx->id_switch.fresh       = 0;
  return ctx->id_switch.request_id;
}

/* Ends the switch in flight when nonce answers it and returns 1 if the
   caller should take the result.  We drop a reply to another request,
   and the reply to a switch that set-identity overtook. */
static int
on_switch_resp_msg( fd_failover_tile_ctx_t * ctx,
                    ulong                    nonce ) {
  if( FD_UNLIKELY( !is_switch_pending( ctx ) || nonce!=ctx->id_switch.request_id ) ) {
    FD_LOG_WARNING(( "dropping a stale identity switch answer" ));
    return 0;
  }
  ctx->id_switch.pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  if( FD_UNLIKELY( ctx->id_switch.discard ) ) {
    ctx->id_switch.discard = 0;
    return 0;
  }
  ctx->id_switch.fresh = 1;
  return 1;
}

/* Takes the answer to our identity switch, once. */
static ulong
take_switch_result( fd_failover_tile_ctx_t * ctx ) {
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;
  return ctx->id_switch.result.result;
}

/* The identity switch in flight passed its deadline.  Its outcome is
   unknown, so we keep waiting and refuse another switch. */
static void
mark_switch_overdue( fd_failover_tile_ctx_t * ctx ) {
  ctx->stuck = 1;
  if( FD_LIKELY( ctx->id_switch.overdue ) ) return;
  ctx->id_switch.overdue = 1;
  FD_LOG_WARNING(( "identity switch %lu to %s is overdue, its outcome is unknown, we keep waiting and refuse another switch",
                   ctx->id_switch.request_id, ctx->id_switch.pending_key==FD_FAILOVER_SWITCH_KEY_STAKED ? "the identity" : "the junk key" ));
}

/* set-identity installed a key, or failover promote <keypair> picked a
   target, so we start over as if this machine had rebooted, with a new
   boot id and nothing in flight.  A peer with another target fails
   HELLO. */
static void
on_operator_action_msg( fd_failover_tile_ctx_t *       ctx,
                        fd_failover_operator_t const * operator ) {
  if( FD_UNLIKELY( operator->epoch<=ctx->id_switch.epoch ) ) return;
  ctx->id_switch.epoch   = operator->epoch;
  ctx->id_switch.discard = is_switch_pending( ctx );
  ctx->id_switch.fresh   = 0;
  ctx->id_switch.overdue = 0;
  if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE || ctx->request.id || ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE || ctx->reply.state==FD_FAILOVER_REPLY_PENDING ) ) {
    FD_LOG_WARNING(( "the identity changed in %s, dropping request %lu, handoff %lu and reply %lu, the other machine may already run the identity",
                     get_action_name( ctx->action ), ctx->request.id, ctx->handoff.id, ctx->reply.handoff_id ));
  }
  finish_cmd( ctx, FD_FAILOVER_CONTROL_RESULT_IDENTITY_CHANGED );
  hang_up( ctx, fd_failover_clock() );
  reset_controller( ctx );
  /* What gossip told us is about the old failover identity. */
  if( FD_UNLIKELY( !fd_memeq( operator->failover_identity, ctx->hello.staked_pubkey, 32UL ) ) ) {
    ctx->staked_addr    = 0U;
    ctx->staked_seen_at = 0L;
    ctx->peer_floor     = FD_FAILOVER_SLOT_NULL;
    ctx->own_floor      = FD_FAILOVER_SLOT_NULL;
    ctx->own_voted      = 0;
  }
  ulong boot_id = ctx->hello.boot_id;
  do FD_TEST( fd_rng_secure( &ctx->hello.boot_id, sizeof(ulong) ) ); while( FD_UNLIKELY( !ctx->hello.boot_id || ctx->hello.boot_id==boot_id ) );
  fd_memcpy( ctx->hello.staked_pubkey, operator->failover_identity, 32UL );
  set_installed( ctx, operator->identity );
  fd_tls_sign_t signer = { .ctx=ctx, .sign_fn=sign_ed25519 };
  if( FD_UNLIKELY( fd_failover_channel_set_identity( ctx->channel, signer, (fd_failover_proof_signer_t){ .ctx=ctx, .sign_fn=sign_proof }, &ctx->hello ) ) ) {
    FD_LOG_ERR(( "failover TLS setup failed after the identity changed" ));
  }
  sync_session( ctx );
  FD_BASE58_ENCODE_32_BYTES( operator->identity,          identity );
  FD_BASE58_ENCODE_32_BYTES( operator->failover_identity, failover_identity );
  FD_LOG_NOTICE(( "failover now hands off `%s` and this machine runs `%s`, with a new boot %016lx", failover_identity, identity, ctx->hello.boot_id ));
}

/* Demotion: the holder gives up the identity */

/* Our DEMOTED got its answer or cannot get one any more.  This machine
   keeps its junk key either way. */
static void
resolve_handoff( fd_failover_tile_ctx_t * ctx,
                 ulong                    result ) {
  if( FD_UNLIKELY( ctx->tx.valid && ctx->tx.type==(ushort)FD_FAILOVER_MSG_DEMOTED ) ) ctx->tx.valid = 0;
  if( FD_LIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) set_action( ctx, FD_FAILOVER_ACTION_IDLE );
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_NONE;
  ctx->handoff.result   = result;
}

/* Ends the demotion without final state.  Nobody can promote on it, and
   the machine that asked is told at once rather than at its deadline. */
static void
abort_demotion( fd_failover_tile_ctx_t * ctx,
                char const *             why ) {
  FD_LOG_WARNING(( "handoff %lu: %s, %s", ctx->handoff.id, why, holds_identity( ctx ) ? "this machine keeps the identity" : "nobody runs the identity" ));
  if( FD_UNLIKELY( ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE ) ) queue_handoff_result( ctx, &ctx->handoff.target, ctx->handoff.id, FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  ctx->handoff.delivery = FD_FAILOVER_DELIVERY_NONE;
  ctx->stuck            = 1;
  set_action( ctx, FD_FAILOVER_ACTION_IDLE );
}

/* The final history has to be the history of our last vote. */
static int
is_final_history_ok( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->current_history.valid && ctx->current_history.sz && ctx->last_vote_slot!=FD_FAILOVER_SLOT_NULL && ctx->current_history.tip==ctx->last_vote_slot;
}

/* Whether we can hand off now to a machine whose replay is at
   replay_slot.  One more than FD_FAILOVER_DEADLINE_SLOTS behind our
   history's finality anchor could not reach it before its promotion's
   deadline.  Returns FD_ADMINCTL_RESULT_SUCCESS or the refusal. */
static ulong
check_handoff( fd_failover_tile_ctx_t const * ctx,
               ulong                          replay_slot ) {
  if( FD_UNLIKELY( !is_final_history_ok( ctx ) ) ) return FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY;
  ag_hist_t hist[1];
  ulong     anchor = ag_hist_de( ctx->current_history.state, ctx->current_history.sz, hist ) ? ctx->last_vote_slot : hist->anchor;
  if( FD_UNLIKELY( replay_slot==FD_FAILOVER_SLOT_NULL || fd_ulong_sat_add( replay_slot, FD_FAILOVER_DEADLINE_SLOTS )<anchor ) ) return FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND;
  return FD_ADMINCTL_RESULT_SUCCESS;
}

/* Gives up the identity for the peer that asked, on the session it asked
   on.  step_demote_switch asks for the junk key. */
static void
accept_handoff( fd_failover_tile_ctx_t * ctx,
                ulong                    handoff_id ) {
  fd_memset( &ctx->handoff, 0, sizeof(ctx->handoff) );
  ctx->handoff.id             = handoff_id;
  ctx->handoff.delivery       = FD_FAILOVER_DELIVERY_PENDING;
  ctx->handoff.target.boot_id = ctx->session.peer_boot_id;
  ctx->stuck                  = 0;
  FD_LOG_NOTICE(( "handoff %lu: accepted the request from peer boot %016lx, giving up the identity", handoff_id, ctx->handoff.target.boot_id ));
  set_action( ctx, FD_FAILOVER_ACTION_DEMOTE_SWITCH );
}

/* The junk key is installed.  Waits for the votor's last votes, up to
   the output sequence it stopped signing at, then hands the final
   history to the peer. */
static void
step_demote_drain( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( !fd_seq_ge( fd_seq_inc( ctx->hist_seen_seq, 1UL ), ctx->id_switch.result.history_watermark ) ) ) {
    if( FD_UNLIKELY( is_overdue( ctx ) ) ) abort_demotion( ctx, "the vote history stream did not report its last votes in time, sending nothing" );
    return;
  }
  if( FD_UNLIKELY( !is_final_history_ok( ctx ) ) ) { abort_demotion( ctx, "no final vote history for the last vote, sending nothing" ); return; }
  ctx->handoff.payload_sz = fd_failover_demoted_encode( ctx->handoff.payload, ctx->handoff.id, ctx->handoff.target.boot_id, ctx->last_vote_slot, ctx->current_history.state, ctx->current_history.sz );
  if( FD_UNLIKELY( !ctx->handoff.payload_sz ) ) { abort_demotion( ctx, "the final vote history does not encode, sending nothing" ); return; }
  ctx->handoff.result = FD_FAILOVER_HANDOFF_PENDING;
  FD_LOG_NOTICE(( "handoff %lu: this machine runs its junk key now, sending the final vote history ending at slot %lu", ctx->handoff.id, ctx->last_vote_slot ));
  (void)queue_demoted( ctx );
  set_action( ctx, FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
}

/* Asks the admin tile for the junk key and waits for its answer. */
static void
step_demote_switch( fd_failover_tile_ctx_t * ctx,
                    fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( !is_switch_pending( ctx ) && !ctx->id_switch.fresh ) ) {
    if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_JUNK )==ULONG_MAX ) ) { abort_demotion( ctx, "an identity switch could not be requested" ); return; }
    FD_LOG_NOTICE(( "handoff %lu: asked the admin tile to install the junk key", ctx->handoff.id ));
    return;
  }
  if( FD_LIKELY( !ctx->id_switch.fresh ) ) {
    if( FD_UNLIKELY( is_overdue( ctx ) ) ) mark_switch_overdue( ctx );
    return;
  }
  ulong result = take_switch_result( ctx );
  if( FD_UNLIKELY( result!=FD_FAILOVER_SWITCH_OK ) ) {
    abort_demotion( ctx, result==FD_FAILOVER_SWITCH_ERR_DISABLED ? "failover is disabled" : result==FD_FAILOVER_SWITCH_ERR_AUTHORIZED_VOTER ? "the identity is an authorized voter" : "the identity switch failed" );
    return;
  }
  set_installed( ctx, ctx->spare_pubkey );
  set_action( ctx, FD_FAILOVER_ACTION_DEMOTE_DRAIN );
  step_demote_drain( ctx );
}

/* DEMOTED is out and the peer answers with PROMOTE_ACK or
   PROMOTE_REJECTED.  If it goes quiet we only raise stuck, the identity
   is already gone from this machine.  A new peer boot cannot answer this
   DEMOTED, and its earlier boot may have taken the identity and voted
   before losing its ACK. */
static void
step_demote_wait_ack( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED && ctx->session.peer_boot_id!=ctx->handoff.target.boot_id ) ) {
    FD_LOG_WARNING(( "handoff %lu: the peer restarted before it answered and may have voted, nobody runs the identity", ctx->handoff.id ));
    ctx->peer_history.valid = 0;
    resolve_handoff( ctx, FD_FAILOVER_HANDOFF_RESTARTED );
    return;
  }
  if( FD_UNLIKELY( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_PENDING && !ctx->tx.valid ) ) (void)queue_demoted( ctx );
  if( FD_UNLIKELY( is_overdue( ctx ) && !ctx->stuck ) ) {
    FD_LOG_WARNING(( "handoff %lu: the peer has not answered, this machine runs the junk key", ctx->handoff.id ));
    ctx->stuck = 1;
  }
}

/* Handoff request: the taker asks the holder for the identity */

/* Our request is paused at its deadline, `failover promote` resumes it. */
static inline int
is_request_paused( fd_failover_tile_ctx_t const * ctx ) {
  return ctx->request.id && !ctx->request.until && is_requesting( ctx );
}

/* Stops dialing without ending the request, which keeps its binding to
   the peer boot that may still answer it. */
static void
pause_request( fd_failover_tile_ctx_t * ctx,
               long                     now,
               ulong                    result,
               char const *             why ) {
  FD_LOG_WARNING(( "handoff %lu paused in %s, %s, `failover promote` here resumes it", ctx->request.id, get_action_name( ctx->action ), why ));
  ctx->request.until = 0L;
  ctx->stuck         = 1;
  if( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER ) finish_cmd( ctx, result );
  hang_up( ctx, now );
}

/* Ends our request with result, an FD_FAILOVER_HANDOFF_*, and hangs up. */
static void
end_request( fd_failover_tile_ctx_t * ctx,
             long                     now,
             ulong                    result ) {
  FD_TEST( !is_switch_pending( ctx ) && is_requesting( ctx ) );
  FD_LOG_NOTICE(( "handoff %lu: request ended (%s), %s", ctx->request.id, get_handoff_name( result ), holds_identity( ctx ) ? "this machine runs the identity" : "this machine does not run the identity" ));
  ctx->request.id               = 0UL;
  ctx->request.until            = 0L;
  ctx->tx.valid                 = 0;
  ctx->session.close_after_send = 0;
  ctx->stuck                    = result!=FD_FAILOVER_HANDOFF_TAKEN;
  if( ctx->reply.state==FD_FAILOVER_REPLY_PENDING ) ctx->reply.state = FD_FAILOVER_REPLY_KEPT;
  set_action( ctx, FD_FAILOVER_ACTION_IDLE );
  hang_up( ctx, now );
}

/* Our promotion answered the peer's DEMOTED.  Waits for the peer to
   record that answer, dialing again if the request paused meanwhile. */
static void
await_request_result( fd_failover_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx->request.until ) ) fd_failover_channel_init_dialer( ctx->channel, ctx->request.addr, get_dial_port( ctx ) );
  ctx->request.until = fd_long_sat_add( fd_failover_clock(), FD_FAILOVER_DEADLINE_NANOS );
  set_action( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT );
}

/* Promotion: the taker adopts the identity */

/* The coverage floor is the higher of the peer's reported last vote and
   our highest signed vote, which the adopted history has to reach. */
static ulong
get_coverage_floor( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( ctx->peer_floor==FD_FAILOVER_SLOT_NULL ) ) return ctx->own_floor;
  if( FD_UNLIKELY( ctx->own_floor ==FD_FAILOVER_SLOT_NULL ) ) return ctx->peer_floor;
  return fd_ulong_max( ctx->peer_floor, ctx->own_floor );
}

/* The history source a promotion would adopt now. */
static ulong
get_promote_source( fd_failover_tile_ctx_t const * ctx ) {
  /* The peer may already vote past our unanswered DEMOTED. */
  if( FD_UNLIKELY( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) ) return FD_FAILOVER_SOURCE_EMPTY;
  ulong floor   = get_coverage_floor( ctx );
  int   peer_ok = ctx->peer_history.valid && ( floor==FD_FAILOVER_SLOT_NULL || ctx->peer_history.tip>=floor ) &&
                  ( ctx->root_slot==FD_FAILOVER_SLOT_NULL || ctx->peer_history.tip>ctx->root_slot );
  return peer_ok ? FD_FAILOVER_SOURCE_PEER : FD_FAILOVER_SOURCE_EMPTY;
}

/* Checks whether a forced promotion may go ahead now.  Returns
   FD_ADMINCTL_RESULT_SUCCESS or the refusal. */
static ulong
check_promotion( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_UNLIKELY( holds_identity( ctx ) ) ) return FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER;
  int cancellable = ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK || ( ctx->request.id && is_requesting( ctx ) );
  if( FD_UNLIKELY( ( ctx->action!=FD_FAILOVER_ACTION_IDLE && !cancellable ) || is_switch_pending( ctx ) ) ) return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  return FD_ADMINCTL_RESULT_SUCCESS;
}

/* Records the finality anchor of the saved history the promotion adopts,
   which replay has to reach first.  An empty history has none, its bound
   is set when replay is ready. */
static void
set_adopt_anchor( fd_failover_tile_ctx_t * ctx ) {
  ctx->adopt_anchor     = FD_FAILOVER_SLOT_NULL;
  ctx->empty_vote_after = FD_FAILOVER_SLOT_NULL;
  if( FD_UNLIKELY( ctx->promotion.source==FD_FAILOVER_SOURCE_EMPTY ) ) return;
  ag_hist_t hist[1];
  if( FD_LIKELY( !ag_hist_de( ctx->promotion.adopt.state, ctx->promotion.adopt.sz, hist ) ) ) ctx->adopt_anchor = hist->anchor;
}

/* Whether replay reached the saved history's finality anchor.  An empty
   history is ready at once, with its vote bound at the higher of the
   replay slot and the coverage floor. */
static int
is_replay_ready( fd_failover_tile_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->promotion.source!=FD_FAILOVER_SOURCE_EMPTY ) ) {
    return ctx->adopt_anchor==FD_FAILOVER_SLOT_NULL || ctx->replay_slot>=ctx->adopt_anchor;
  }
  ulong floor = ctx->promotion.floor;
  ctx->empty_vote_after = floor==FD_FAILOVER_SLOT_NULL ? ctx->replay_slot : fd_ulong_max( ctx->replay_slot, floor );
  FD_STORE( ulong, ctx->promotion.adopt.state, ctx->empty_vote_after );
  ctx->promotion.adopt.sz = FD_VOTOR_ADOPT_EMPTY_SZ;
  return 1;
}

static ulong
get_reject_result( uchar reason ) {
  switch( reason ) {
  case (uchar)FD_FAILOVER_REJECT_REPLAY_BEHIND:  return FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND;
  case (uchar)FD_FAILOVER_REJECT_HOLDS_IDENTITY: return FD_FAILOVER_CONTROL_RESULT_PEER_HOLDS;
  case (uchar)FD_FAILOVER_REJECT_SWITCH_FAILED:  return FD_FAILOVER_CONTROL_RESULT_SWITCH_FAILED;
  default:                                       return FD_FAILOVER_CONTROL_RESULT_ADOPTION_FAILED;
  }
}

/* Ends the promotion without the identity.  A peer's handoff gets our
   refusal and waits for the peer to record it. */
static void
reject_promotion( fd_failover_tile_ctx_t * ctx,
                  uchar                    reason,
                  int                      bad_history ) {
  if( FD_UNLIKELY( bad_history && ctx->promotion.source==FD_FAILOVER_SOURCE_PEER ) ) ctx->peer_history.valid = 0;
  ctx->stuck = 1;
  FD_LOG_WARNING(( "%s failed (%s), this machine does not take the identity", ctx->promotion.label, get_reject_name( reason ) ));
  finish_cmd( ctx, get_reject_result( reason ) );
  if( FD_LIKELY( !ctx->promotion.from_peer ) ) { set_action( ctx, FD_FAILOVER_ACTION_IDLE ); return; }
  ctx->peer_history.valid  = 0;
  ctx->promotion.from_peer = 0;
  await_request_result( ctx );
  finish_reply( ctx, &ctx->promotion.peer, ctx->promotion.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
}

/* Takes the identity with the history from source.  peer is the member
   boot whose DEMOTED with handoff_id asked for it and gets our answer,
   NULL for an operator promotion.  flags is whether the promotion uses
   FD_ADMINCTL_FAILOVER_FLAG_ADOPT or _FORCE, which also accept an empty
   history, and 0 for a handoff. */
static void
start_promotion( fd_failover_tile_ctx_t *   ctx,
                 ulong                      source,
                 fd_failover_peer_t const * peer,
                 ulong                      handoff_id,
                 ulong                      flags ) {
  fd_memset( &ctx->promotion, 0, sizeof(ctx->promotion) );
  if( source==FD_FAILOVER_SOURCE_PEER ) ctx->promotion.adopt = ctx->peer_history;
  else                                  ctx->promotion.adopt.tip = FD_FAILOVER_SLOT_NULL;
  if( peer ) {
    ctx->promotion.peer       = *peer;
    ctx->promotion.handoff_id = handoff_id;
    ctx->promotion.from_peer  = 1;
    fd_cstr_printf( ctx->promotion.label, sizeof(ctx->promotion.label), NULL, "handoff %lu", handoff_id );
  } else {
    fd_cstr_printf( ctx->promotion.label, sizeof(ctx->promotion.label), NULL, "operator promotion" );
  }
  ctx->promotion.source = source;
  ctx->promotion.force  = !!( flags & (FD_ADMINCTL_FAILOVER_FLAG_ADOPT|FD_ADMINCTL_FAILOVER_FLAG_FORCE) );
  ctx->promotion.floor  = get_coverage_floor( ctx );
  /* Until this tenure votes, its final history is exactly the adopted one. */
  ctx->current_history = ctx->promotion.adopt;
  ctx->last_vote_slot  = ctx->promotion.adopt.tip;
  ctx->stuck           = 0;
  set_adopt_anchor( ctx );
  LOG_CMD_STEP( ctx, "%s: adopting %s%s", ctx->promotion.label, get_source_name( source ),
                ( flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE ) ? ", --force skips the checks on the other machine" :
                ( flags & FD_ADMINCTL_FAILOVER_FLAG_ADOPT ) ? ", --adopt found no sign of life on the other machine" : "" );
  set_action( ctx, FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
}

/* A forced operator promotion whose saved history is not eligible falls
   back to an empty history.  Returns whether it did. */
static int
try_promote_fallback( fd_failover_tile_ctx_t * ctx,
                      char const *             reason ) {
  if( FD_UNLIKELY( ctx->promotion.from_peer || !ctx->promotion.force || ctx->promotion.source==FD_FAILOVER_SOURCE_EMPTY ) ) return 0;
  LOG_CMD_STEP( ctx, "%s: %s is not eligible (%s), trying %s", ctx->promotion.label, get_source_name( ctx->promotion.source ), reason, get_source_name( FD_FAILOVER_SOURCE_EMPTY ) );
  ctx->peer_history.valid    = 0;
  ctx->promotion.source      = FD_FAILOVER_SOURCE_EMPTY;
  ctx->promotion.adopt.valid = 0;
  ctx->promotion.adopt.tip   = FD_FAILOVER_SLOT_NULL;
  ctx->promotion.adopt.sz    = 0UL;
  ctx->promotion.retry       = 0;
  ctx->current_history       = ctx->promotion.adopt;
  ctx->last_vote_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->adopt_result_fresh    = 0;
  set_adopt_anchor( ctx );
  set_action( ctx, FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  return 1;
}

/* The adoption failed for reason.  Tries the fallback first. */
static void
fail_adoption( fd_failover_tile_ctx_t * ctx,
               uchar                    reason,
               char const *             why,
               int                      bad_history ) {
  if( try_promote_fallback( ctx, why ) ) return;
  reject_promotion( ctx, reason, bad_history );
}

/* Asks the votor to adopt the history.  Returns whether it did. */
static int
publish_adoption( fd_failover_tile_ctx_t * ctx,
                  fd_stem_context_t *      stem ) {
  ulong id = publish_adopt_state( ctx, stem );
  if( FD_UNLIKELY( id==ULONG_MAX ) ) { reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 ); return 0; }
  LOG_CMD_STEP( ctx, "%s: asking the votor to adopt %s", ctx->promotion.label, get_source_name( ctx->promotion.source ) );
  ctx->promotion.adopt_id = id;
  ctx->promotion.retry    = 0;
  return 1;
}

/* Waits for replay to reach the history's finality anchor, then asks the
   votor to adopt it. */
static void
step_promote_wait_replay( fd_failover_tile_ctx_t * ctx,
                          fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( is_overdue( ctx ) ) ) { reject_promotion( ctx, FD_FAILOVER_REJECT_REPLAY_BEHIND, 0 ); return; }
  if( FD_UNLIKELY( ctx->replay_slot==FD_FAILOVER_SLOT_NULL ) ) return;
  if( FD_UNLIKELY( !is_replay_ready( ctx ) ) ) { (void)try_promote_fallback( ctx, "replay has not reached its finality anchor" ); return; }
  if( FD_UNLIKELY( !publish_adoption( ctx, stem ) ) ) return;
  set_action( ctx, FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
}

/* Waits for the votor's answer.  A votor that is not ready yet is asked
   again as replay moves, a history short of the coverage floor waits for
   the deadline, and a good adoption asks the admin tile for the
   identity. */
static void
step_promote_wait_adopt( fd_failover_tile_ctx_t * ctx,
                         fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( is_overdue( ctx ) ) ) { reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 ); return; }
  if( FD_UNLIKELY( ctx->promotion.retry ) ) {
    if( FD_LIKELY( ctx->replay_slot<=ctx->promotion.retry_slot ) ) return;
    (void)publish_adoption( ctx, stem );
    return;
  }
  if( FD_LIKELY( !ctx->adopt_result_fresh ) ) return;
  ctx->adopt_result_fresh = 0;
  if( FD_UNLIKELY( ctx->adopt_result_id!=ctx->promotion.adopt_id ) ) return;
  ulong        result = ctx->adopt_result.result;
  char const * err    = get_adopt_err_name( result );
  if( FD_UNLIKELY( result==FD_VOTOR_ADOPT_ERR_UNREPLAYED || result==FD_VOTOR_ADOPT_ERR_CAPACITY ) ) {
    if( FD_UNLIKELY( !ctx->promotion.from_peer ) ) { fail_adoption( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, err, 0 ); return; }
    LOG_CMD_STEP( ctx, "%s: the votor is not ready to adopt the vote history (%s), asking again as replay moves", ctx->promotion.label, err );
    ctx->promotion.retry      = 1;
    ctx->promotion.retry_slot = ctx->replay_slot;
    return;
  }
  if( FD_UNLIKELY( result!=FD_VOTOR_ADOPT_SUCCESS ) ) {
    fail_adoption( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, err, result==FD_VOTOR_ADOPT_ERR_DECODE || result==FD_VOTOR_ADOPT_ERR_INVALID || result==FD_VOTOR_ADOPT_ERR_STALE );
    return;
  }
  ulong tip = ctx->promotion.adopt.tip;
  if( FD_UNLIKELY( tip!=FD_FAILOVER_SLOT_NULL && ctx->adopt_result.vote_slot!=tip ) ) { fail_adoption( ctx, FD_FAILOVER_REJECT_ADOPTION_MISMATCH, "adoption did not retain its final vote", 1 ); return; }
  ulong floor   = ctx->promotion.floor;
  ulong reached = ctx->promotion.source==FD_FAILOVER_SOURCE_EMPTY ? ctx->adopt_result.vote_bound : ctx->adopt_result.vote_slot;
  int   covered = floor==FD_FAILOVER_SLOT_NULL || ( reached!=FD_FAILOVER_SLOT_NULL && reached>=floor );
  if( ctx->adopt_result.vote_slot==FD_FAILOVER_SLOT_NULL ) LOG_CMD_STEP( ctx, "%s: the votor adopted %s, no last vote, no vote at or below slot %lu", ctx->promotion.label, get_source_name( ctx->promotion.source ), ctx->adopt_result.vote_bound );
  else LOG_CMD_STEP( ctx, "%s: the votor adopted %s, last vote at slot %lu, no vote at or below slot %lu", ctx->promotion.label, get_source_name( ctx->promotion.source ), ctx->adopt_result.vote_slot, ctx->adopt_result.vote_bound );
  if( FD_UNLIKELY( !covered && !ctx->promotion.force ) ) {
    /* Only a handoff gets here, and the peer's history does not change,
       so we wait for the deadline rather than ask again. */
    if( try_promote_fallback( ctx, "its votes do not cover the known signing history" ) ) return;
    ctx->promotion.retry      = 1;
    ctx->promotion.retry_slot = FD_FAILOVER_SLOT_NULL;
    return;
  }
  if( FD_UNLIKELY( ctx->promotion.holder_seen && !ctx->promotion.force ) ) { reject_promotion( ctx, FD_FAILOVER_REJECT_HOLDS_IDENTITY, 0 ); return; }
  if( FD_UNLIKELY( tip==FD_FAILOVER_SLOT_NULL ) ) ctx->last_vote_slot = ctx->adopt_result.vote_slot;
  if( FD_UNLIKELY( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED )==ULONG_MAX ) ) { reject_promotion( ctx, FD_FAILOVER_REJECT_ADOPTION_FAILED, 0 ); return; }
  LOG_CMD_STEP( ctx, "%s: asked the admin tile to install the identity", ctx->promotion.label );
  set_action( ctx, FD_FAILOVER_ACTION_PROMOTE_SWITCH );
}

/* Waits for the admin tile to install the identity.  Standing down
   before its answer would tell the peer nobody promoted while the
   identity may well be installed, so a late answer still counts. */
static void
step_promote_switch( fd_failover_tile_ctx_t * ctx ) {
  if( FD_LIKELY( !ctx->id_switch.fresh ) ) {
    if( FD_UNLIKELY( is_overdue( ctx ) ) ) mark_switch_overdue( ctx );
    return;
  }
  if( FD_UNLIKELY( take_switch_result( ctx )!=FD_FAILOVER_SWITCH_OK ) ) { reject_promotion( ctx, FD_FAILOVER_REJECT_SWITCH_FAILED, 0 ); return; }
  /* An operator promotion installed the identity outside a handoff, so
     a background session must not keep our old HELLO. */
  if( !ctx->promotion.from_peer ) hang_up( ctx, fd_failover_clock() );
  set_installed( ctx, ctx->hello.staked_pubkey );
  ctx->peer_history.valid = 0; /* a new tenure starts, the saved history is older than its votes */
  ctx->own_voted          = 1; /* this machine votes as the identity from here, before its first vote goes out */
  ctx->stuck              = 0;
  FD_LOG_NOTICE(( "%s: this machine runs the identity now, last vote at slot %lu", ctx->promotion.label, ctx->last_vote_slot ));
  finish_cmd( ctx, FD_ADMINCTL_RESULT_SUCCESS );
  if( FD_LIKELY( !ctx->promotion.from_peer ) ) { set_action( ctx, FD_FAILOVER_ACTION_IDLE ); return; }
  /* The ACK tells the other machine its handoff is done, and we keep the
     identity while it records that. */
  ctx->promotion.from_peer = 0;
  await_request_result( ctx );
  finish_reply( ctx, &ctx->promotion.peer, ctx->promotion.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, (uchar)FD_FAILOVER_REJECT_NONE );
}

/* Advances the state that replay slots and the clock drive. */
static void
step_controller( fd_failover_tile_ctx_t * ctx,
                 fd_stem_context_t *      stem ) {
  if( FD_UNLIKELY( ctx->reply.state==FD_FAILOVER_REPLY_PENDING && !ctx->tx.valid ) ) queue_reply( ctx );
  switch( ctx->action ) {
  case FD_FAILOVER_ACTION_IDLE:
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER:
  case FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT: return; /* poll_peer drives the request on session events */
  case FD_FAILOVER_ACTION_DEMOTE_SWITCH:       step_demote_switch( ctx, stem );       return;
  case FD_FAILOVER_ACTION_DEMOTE_DRAIN:        step_demote_drain( ctx );              return;
  case FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK:     step_demote_wait_ack( ctx );           return;
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY: step_promote_wait_replay( ctx, stem ); return;
  case FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT:  step_promote_wait_adopt( ctx, stem );  return;
  case FD_FAILOVER_ACTION_PROMOTE_SWITCH:      step_promote_switch( ctx );            return;
  default: FD_LOG_ERR(( "unexpected failover action %lu", ctx->action ));
  }
}

/* Peer messages and polling.  Each handler returns 1 when the message
   was handled, including one it ignored on purpose, and 0 when it was
   malformed, which drops the session: these messages hand off the
   identity so we do not guess at them. */

/* HANDOFF_REQUEST, the peer asks us to give up the identity. */
static int
on_handoff_request_msg( fd_failover_tile_ctx_t * ctx,
                        ulong                    payload_sz ) {
  fd_failover_handoff_request_t request;
  if( FD_UNLIKELY( !fd_failover_handoff_request_decode( &request, ctx->rx, payload_sz ) ) ) return 0;
  ulong result = FD_ADMINCTL_RESULT_SUCCESS;
  if( FD_UNLIKELY( request.target_boot_id!=ctx->hello.boot_id ) ) {
    result = FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY;
  } else if( FD_UNLIKELY( request.handoff_id==ctx->handoff.id && is_bound_peer( ctx, &ctx->handoff.target ) ) ) {
    /* The same request again keeps the demotion and gets its answer again. */
    if( is_switching_out( ctx ) ) return 1;
    if( ctx->handoff.delivery!=FD_FAILOVER_DELIVERY_NONE ) {
      if( !ctx->tx.valid ) (void)queue_demoted( ctx );
      return 1;
    }
    result = ctx->handoff.result==FD_FAILOVER_HANDOFF_TAKEN ? FD_ADMINCTL_RESULT_SUCCESS : FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY;
  } else if( ctx->action!=FD_FAILOVER_ACTION_IDLE || is_switch_pending( ctx ) || ctx->tx.valid || ctx->session.close_after_send ) {
    result = FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  } else if( !holds_identity( ctx ) || fd_failover_channel_peer_hello( ctx->channel )->holds ) {
    result = FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER;
  } else {
    result = check_handoff( ctx, request.replay_slot );
    if( FD_LIKELY( result==FD_ADMINCTL_RESULT_SUCCESS ) ) { accept_handoff( ctx, request.handoff_id ); return 1; }
  }
  FD_LOG_WARNING(( "handoff %lu refused, %s", request.handoff_id, fd_adminctl_failover_result_cstr( result ) ));
  queue_handoff_result( ctx, NULL, request.handoff_id, result );
  return 1;
}

static int
is_peer_result( ulong result ) {
  return result==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY || result==FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND ||
         result==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS      || result==FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER  ||
         result==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY;
}

/* HANDOFF_RESULT, the peer recorded how our request ended. */
static int
on_handoff_result_msg( fd_failover_tile_ctx_t * ctx,
                       ulong                    payload_sz,
                       long                     now ) {
  fd_failover_handoff_result_t result;
  if( FD_UNLIKELY( !fd_failover_handoff_result_decode( &result, ctx->rx, payload_sz ) ) ) return 0;
  if( FD_UNLIKELY( !ctx->request.id || result.handoff_id!=ctx->request.id || !is_bound_peer( ctx, &ctx->request.peer ) || !is_requesting( ctx ) ) ) return 1;
  int failed = result.result!=FD_ADMINCTL_RESULT_SUCCESS || !holds_identity( ctx );
  if( FD_UNLIKELY( failed && result.result==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_HISTORY &&
                   ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER && ctx->request.send_cnt<FD_FAILOVER_REQUEST_RETRIES ) ) {
    LOG_CMD_STEP( ctx, "handoff %lu: the other machine has no final vote state yet, asking again (send %lu)", result.handoff_id, ctx->request.send_cnt );
    return 1;
  }
  if( FD_UNLIKELY( failed ) ) {
    FD_LOG_WARNING(( "handoff %lu ended, %s, %s", result.handoff_id, fd_adminctl_failover_result_cstr( result.result ), holds_identity( ctx ) ? "this machine runs the identity and the other may run it too" : "this machine does not run the identity" ));
    finish_cmd( ctx, is_peer_result( result.result ) ? result.result : FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  }
  end_request( ctx, now, failed ? FD_FAILOVER_HANDOFF_DECLINED : FD_FAILOVER_HANDOFF_TAKEN );
  return 1;
}

/* DEMOTED, the peer gave up the identity and hands us its final history. */
static int
on_demoted_msg( fd_failover_tile_ctx_t * ctx,
                ulong                    payload_sz ) {
  fd_failover_demoted_t demoted;
  if( FD_UNLIKELY( !fd_failover_demoted_decode( &demoted, ctx->rx, payload_sz ) || demoted.mode!=(uchar)FD_FAILOVER_MODE_ALPENGLOW ) ) return 0;
  /* An unsolicited DEMOTED cannot change our request or its answer. */
  if( FD_UNLIKELY( !ctx->request.id || ctx->request.id!=demoted.handoff_id || !is_bound_peer( ctx, &ctx->request.peer ) ) ) return 1;
  if( FD_UNLIKELY( demoted.target_boot_id!=ctx->hello.boot_id ) ) return 0;
  /* The same DEMOTED again.  Once we are done with it we repeat our answer. */
  if( FD_UNLIKELY( ctx->promotion.from_peer && ctx->promotion.handoff_id==demoted.handoff_id ) ) return 1;
  if( FD_UNLIKELY( ctx->reply.state!=FD_FAILOVER_REPLY_NONE && ctx->reply.handoff_id==demoted.handoff_id && is_bound_peer( ctx, &ctx->reply.peer ) ) ) { queue_reply( ctx ); return 1; }
  uchar reason = holds_identity( ctx )                                                      ? FD_FAILOVER_REJECT_HOLDS_IDENTITY :
                 ctx->action!=FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER || is_switch_pending( ctx ) ? FD_FAILOVER_REJECT_BUSY           : FD_FAILOVER_REJECT_NONE;
  if( FD_UNLIKELY( reason!=FD_FAILOVER_REJECT_NONE ) ) {
    FD_LOG_WARNING(( "handoff %lu: refusing the peer's final state (%s)", demoted.handoff_id, get_reject_name( reason ) ));
    finish_reply( ctx, &ctx->request.peer, demoted.handoff_id, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, reason );
    return 1;
  }
  fd_failover_history_t history = { .valid=1, .tip=demoted.last_vote_slot, .sz=(ulong)demoted.state_len };
  fd_memcpy( history.state, ctx->rx+sizeof(fd_failover_demoted_t), history.sz );
  if( ctx->peer_floor==FD_FAILOVER_SLOT_NULL || history.tip>ctx->peer_floor ) ctx->peer_floor = history.tip;
  ctx->peer_history = history;
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, &ctx->request.peer, demoted.handoff_id, 0 );
  return 1;
}

/* PROMOTE_ACK or PROMOTE_REJECTED, the peer's answer to our DEMOTED.  It
   counts only from the member boot the DEMOTED went to, and one after
   the deadline still counts. */
static int
on_demoted_answer_msg( fd_failover_tile_ctx_t * ctx,
                       ushort                   type,
                       ulong                    payload_sz ) {
  int                            taken = type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK;
  fd_failover_promote_ack_t      ack;
  fd_failover_promote_rejected_t rej;
  if( FD_UNLIKELY( taken ? !fd_failover_promote_ack_decode( &ack, ctx->rx, payload_sz ) : !fd_failover_promote_rejected_decode( &rej, ctx->rx, payload_sz ) ) ) return 0;
  ulong handoff_id = taken ? ack.handoff_id : rej.handoff_id;
  if( FD_UNLIKELY( ctx->handoff.delivery==FD_FAILOVER_DELIVERY_NONE || handoff_id!=ctx->handoff.id || !is_bound_peer( ctx, &ctx->handoff.target ) || is_switching_out( ctx ) ) ) return 1;
  if( taken ) FD_LOG_NOTICE (( "handoff %lu: the peer took the identity, this machine keeps the junk key", handoff_id ));
  else        FD_LOG_WARNING(( "handoff %lu: the peer declined the identity (%s), nobody runs it", handoff_id, get_reject_name( rej.reason ) ));
  ctx->peer_history.valid = 0; /* the peer votes past it, or either machine may now recover without the other */
  ctx->stuck              = !taken;
  resolve_handoff( ctx, taken ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED );
  queue_handoff_result( ctx, NULL, handoff_id, taken ? FD_ADMINCTL_RESULT_SUCCESS : FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  return 1;
}

/* Handles a control message.  Anything malformed drops the session. */
static void
handle_control( fd_failover_tile_ctx_t * ctx,
                ushort                   type,
                ulong                    payload_sz,
                long                     now ) {
  int handled;
  switch( type ) {
  case (ushort)FD_FAILOVER_MSG_HANDOFF_REQUEST:  handled = on_handoff_request_msg( ctx, payload_sz );       break;
  case (ushort)FD_FAILOVER_MSG_HANDOFF_RESULT:   handled = on_handoff_result_msg ( ctx, payload_sz, now );  break;
  case (ushort)FD_FAILOVER_MSG_DEMOTED:          handled = on_demoted_msg        ( ctx, payload_sz );       break;
  case (ushort)FD_FAILOVER_MSG_PROMOTE_ACK:
  case (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED: handled = on_demoted_answer_msg ( ctx, type, payload_sz ); break;
  default:                                       handled = 0;                                               break;
  }
  if( FD_LIKELY( handled ) ) return;
  fd_failover_channel_protocol_error( ctx->channel, now );
  sync_session( ctx );
}

/* The machine running the identity refreshed its contact info in gossip
   within FD_FAILOVER_GOSSIP_FRESH_NANOS. */
static inline int
is_holder_fresh( fd_failover_tile_ctx_t const * ctx,
                 long                           now ) {
  return ctx->staked_seen_at && now>=ctx->staked_seen_at && now-ctx->staked_seen_at<FD_FAILOVER_GOSSIP_FRESH_NANOS;
}

/* Whether the machine running the identity showed a sign of life
   recently. */
static int
is_holder_live( fd_failover_tile_ctx_t const * ctx,
                long                           now ) {
  if( is_holder_fresh( ctx, now ) ) return 1;
  return fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED && fd_failover_channel_peer_hello( ctx->channel )->holds;
}

/* An idle machine that does not run the identity authenticates to the
   one that does ahead of an operator command.  Merely pairing never
   creates a request or changes the installed identity. */
static void
preconnect( fd_failover_tile_ctx_t * ctx,
            long                     now ) {
  if( ctx->request.id || ctx->stuck || ctx->tx.valid || ctx->session.close_after_send || ctx->action!=FD_FAILOVER_ACTION_IDLE || is_switch_pending( ctx ) ) return;
  /* A stale gossip address may name a validator that does not run the identity any more. */
  if( !holds_identity( ctx ) && fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED && !fd_failover_channel_peer_hello( ctx->channel )->holds ) fd_failover_channel_hangup( ctx->channel, now );
  int ready = !holds_identity( ctx ) && ctx->staked_addr && is_holder_fresh( ctx, now );
  if( !ready )                                                                   fd_failover_channel_init_dialer( ctx->channel, 0U, 0 );
  else if( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ) fd_failover_channel_init_dialer( ctx->channel, ctx->staked_addr, FD_FAILOVER_DEFAULT_PORT );
}

/* Services the channel and drives our handoff request on it: the
   deadline pauses it, the first peer running the identity binds it, a
   restarted peer pauses or ends it, and a bound session gets the
   HANDOFF_REQUEST once. */
static void
poll_peer( fd_failover_tile_ctx_t * ctx,
           long                     now,
           int *                    charge_busy ) {
  preconnect( ctx, now );
  sync_session( ctx );
  if( FD_UNLIKELY( ctx->request.id && ctx->request.until && now>=ctx->request.until && is_requesting( ctx ) ) ) {
    pause_request( ctx, now, FD_FAILOVER_CONTROL_RESULT_TIMEOUT,
                   !ctx->request.peer.boot_id ? "no peer authenticated before the deadline" :
                   !ctx->request.send_cnt     ? "no handoff request sent before the deadline" : "no answer before the deadline" );
    return;
  }
  if( FD_UNLIKELY( ctx->session.close_after_send && !ctx->tx.valid && !fd_failover_channel_tx_pending( ctx->channel ) ) ) {
    ctx->session.close_after_send = 0;
    fd_failover_channel_hangup( ctx->channel, now );
    sync_session( ctx );
    return;
  }
  ushort type;
  ulong  payload_sz;
  if( FD_UNLIKELY( fd_failover_channel_poll( ctx->channel, now, charge_busy, &type, ctx->rx, &payload_sz ) ) ) {
    sync_session( ctx );
    handle_control( ctx, type, payload_sz, now );
  }
  sync_session( ctx );
  if( FD_LIKELY( !ctx->request.id || fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED ) ) return;
  fd_failover_hello_t const * peer = fd_failover_channel_peer_hello( ctx->channel );
  if( FD_UNLIKELY( ctx->request.peer.boot_id && !is_bound_peer( ctx, &ctx->request.peer ) ) ) {
    /* The peer restarted.  Its new boot cannot confirm our answer, so
       that wait ends, and it cannot answer the old request either, which
       keeps its binding until the operator ends it. */
    if( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && !is_switch_pending( ctx ) ) {
      FD_LOG_WARNING(( "handoff %lu: the peer restarted before it confirmed our answer, ending the request", ctx->request.id ));
      end_request( ctx, now, holds_identity( ctx ) ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED );
    } else if( ctx->request.until ) {
      ctx->request.peer_restarted = 1;
      pause_request( ctx, now, FD_FAILOVER_CONTROL_RESULT_PEER_RESTARTED, "the peer restarted" );
    }
    return;
  }
  if( FD_LIKELY( !ctx->request.until || ctx->request.sent ) ) return;
  if( FD_UNLIKELY( !ctx->request.peer.boot_id ) ) {
    if( FD_UNLIKELY( !peer->holds ) ) {
      FD_LOG_WARNING(( "handoff %lu: dialed `" FD_IP4_ADDR_FMT ":%hu`, which does not run the identity", ctx->request.id, FD_IP4_ADDR_FMT_ARGS( ctx->request.addr ), get_dial_port( ctx ) ));
      finish_cmd( ctx, FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER );
      end_request( ctx, now, FD_FAILOVER_HANDOFF_NOT_HOLDER );
      return;
    }
    ctx->request.peer.boot_id = peer->boot_id;
  }
  fd_failover_handoff_request_t request = { .handoff_id=ctx->request.id, .target_boot_id=ctx->request.peer.boot_id, .replay_slot=ctx->replay_slot };
  if( FD_UNLIKELY( fd_failover_channel_send( ctx->channel, now, FD_FAILOVER_MSG_HANDOFF_REQUEST, (uchar const *)&request, sizeof(request) ) ) ) return;
  ctx->request.sent     = 1;
  ctx->request.send_cnt = fd_ulong_sat_add( ctx->request.send_cnt, 1UL );
  LOG_CMD_STEP( ctx, "handoff %lu: asked peer boot %016lx for the identity (send %lu)", ctx->request.id, ctx->request.peer.boot_id, ctx->request.send_cnt );
  *charge_busy = 1;
}

/* Operator commands and status */

static ulong
get_settled_result( fd_failover_tile_ctx_t const * ctx ) {
  if( FD_LIKELY( holds_identity( ctx ) ) ) return FD_ADMINCTL_RESULT_SUCCESS;
  return ctx->reply.type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED ? get_reject_result( ctx->reply.reason ) : FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY;
}

/* `failover promote`: asks the machine running the identity for it, or
   resumes a paused request.  A request whose peer restarted is ended
   and replaced.  Returns SUCCESS when the command is settled and
   FD_FAILOVER_CMD_PENDING when it waits for the outcome. */
static ulong
run_handoff_cmd( fd_failover_tile_ctx_t *           ctx,
                 fd_adminctl_failover_req_t const * req,
                 long                               now ) {
  int paused = is_request_paused( ctx ) && !is_switch_pending( ctx );
  if( FD_UNLIKELY( paused && ctx->request.peer_restarted ) ) {
    if( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ) {
      /* Local adoption is settled, this only ends our wait for the old
         peer's confirmation, which its new boot cannot give. */
      FD_LOG_WARNING(( "handoff %lu: the authenticated peer changed before it confirmed our answer, ending the confirmation wait", ctx->request.id ));
      ulong result = get_settled_result( ctx );
      end_request( ctx, now, holds_identity( ctx ) ? FD_FAILOVER_HANDOFF_TAKEN : FD_FAILOVER_HANDOFF_DECLINED );
      return result;
    }
    FD_LOG_NOTICE(( "handoff %lu was bound to peer boot %016lx, the authenticated peer changed, ending it and starting a new handoff", ctx->request.id, ctx->request.peer.boot_id ));
    end_request( ctx, now, FD_FAILOVER_HANDOFF_RESTARTED );
    paused = 0;
  }
  if( FD_UNLIKELY( paused ) ) {
    uint addr = req->addr ? req->addr : ctx->staked_addr;
    if( FD_UNLIKELY( !addr ) ) return FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS;
    ctx->cmd_addr      = req->addr;
    ctx->cmd_port      = req->port;
    ctx->request.addr  = addr;
    ctx->request.until = fd_long_sat_add( now, FD_FAILOVER_DEADLINE_NANOS );
    ctx->request.sent  = 0;
    ctx->stuck         = 0;
    fd_failover_channel_init_dialer( ctx->channel, ctx->request.addr, get_dial_port( ctx ) );
    LOG_CMD_STEP( ctx, "handoff %lu: resuming at `" FD_IP4_ADDR_FMT ":%hu` using %s", ctx->request.id, FD_IP4_ADDR_FMT_ARGS( ctx->request.addr ), get_dial_port( ctx ),
                  ctx->cmd_addr ? "`failover promote --address`" : "gossip" );
    return ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT ? get_settled_result( ctx ) : FD_FAILOVER_CMD_PENDING;
  }
  if( FD_UNLIKELY( ctx->action!=FD_FAILOVER_ACTION_IDLE || is_switch_pending( ctx ) ) ) return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  if( FD_UNLIKELY( holds_identity( ctx ) ) ) return FD_FAILOVER_CONTROL_RESULT_WRONG_HOLDER;
  uint addr = req->addr ? req->addr : ctx->staked_addr;
  if( FD_UNLIKELY( !addr ) ) return FD_FAILOVER_CONTROL_RESULT_NO_HOLDER_ADDRESS;
  ctx->cmd_addr = req->addr;
  ctx->cmd_port = req->port;
  fd_memset( &ctx->request, 0, sizeof(ctx->request) );
  ctx->request.id = ctx->handoff_base+(++ctx->handoff_cnt);
  if( FD_UNLIKELY( !ctx->request.id ) ) ctx->request.id = ++ctx->handoff_cnt;
  ctx->request.addr             = addr;
  ctx->request.until            = fd_long_sat_add( now, FD_FAILOVER_DEADLINE_NANOS );
  ctx->stuck                    = 0;
  ctx->session.close_after_send = 0;
  fd_failover_channel_init_dialer( ctx->channel, addr, get_dial_port( ctx ) );
  LOG_CMD_STEP( ctx, "handoff %lu: requesting handoff from the machine running the identity at `" FD_IP4_ADDR_FMT ":%hu` using %s",
                ctx->request.id, FD_IP4_ADDR_FMT_ARGS( addr ), get_dial_port( ctx ), ctx->cmd_addr ? "`failover promote --address`" : "gossip" );
  set_action( ctx, FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER );
  return FD_FAILOVER_CMD_PENDING;
}

/* `failover promote --adopt` or `--force` (after the handoff failed)
   take the identity without coordination.  --adopt refuses while the
   machine running the identity shows a sign of life, --force takes it
   on the operator's word that it cannot sign.  It cancels our request or
   the wait for the peer's answer to our DEMOTED first. */
static ulong
run_promote_cmd( fd_failover_tile_ctx_t *           ctx,
                 fd_adminctl_failover_req_t const * req,
                 long                               now ) {
  int force = !!( req->flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE );
  int adopt = !!( req->flags & FD_ADMINCTL_FAILOVER_FLAG_ADOPT );
  /* The admin tile sends a promote with neither flag as a handoff. */
  if( FD_UNLIKELY( force==adopt ) ) return FD_ADMINCTL_RESULT_UNKNOWN_COMMAND;
  ulong result = check_promotion( ctx );
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) return result;
  if( FD_UNLIKELY( adopt && is_holder_live( ctx, now ) ) ) return FD_FAILOVER_CONTROL_RESULT_HOLDER_LIVE;
  ulong source = get_promote_source( ctx );
  if( ctx->request.id && is_requesting( ctx ) ) end_request( ctx, now, FD_FAILOVER_HANDOFF_CANCELLED );
  if( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK ) {
    ctx->peer_history.valid = 0; /* the peer may have voted */
    resolve_handoff( ctx, FD_FAILOVER_HANDOFF_CANCELLED );
  }
  start_promotion( ctx, source, NULL, 0UL, req->flags & (FD_ADMINCTL_FAILOVER_FLAG_ADOPT|FD_ADMINCTL_FAILOVER_FLAG_FORCE) );
  return FD_FAILOVER_CMD_PENDING;
}

static ulong
run_preflight_cmd( fd_failover_tile_ctx_t const *     ctx,
                   fd_adminctl_failover_req_t const * req ) {
  if( fd_memeq( req->target, ctx->hello.staked_pubkey, 32UL ) ) return FD_ADMINCTL_RESULT_SUCCESS;
  if( FD_UNLIKELY( is_switch_pending( ctx ) || ( ctx->action!=FD_FAILOVER_ACTION_IDLE && !is_request_paused( ctx ) ) ) ) {
    return FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS;
  }
  if( FD_UNLIKELY( holds_identity( ctx ) && ctx->own_voted ) ) return FD_FAILOVER_CONTROL_RESULT_HOLDS_OTHER;
  return FD_ADMINCTL_RESULT_SUCCESS;
}

/* Runs an operator command.  Returns either its result or
   FD_FAILOVER_CMD_PENDING. */
static ulong
apply_control( fd_failover_tile_ctx_t *           ctx,
               fd_adminctl_failover_req_t const * req,
               long                               now ) {
  if( FD_UNLIKELY( ctx->cmd_nonce ) ) return FD_FAILOVER_CONTROL_RESULT_BUSY;
  switch( req->cmd ) {
  case FD_ADMINCTL_FAILOVER_CMD_HANDOFF:   return run_handoff_cmd( ctx, req, now );
  case FD_ADMINCTL_FAILOVER_CMD_PROMOTE:   return run_promote_cmd( ctx, req, now );
  case FD_ADMINCTL_FAILOVER_CMD_PREFLIGHT: return run_preflight_cmd( ctx, req );
  default:                                 return FD_ADMINCTL_RESULT_UNSUPPORTED;
  }
}

/* Answers one bus frame with the result for nonce. */
static void
publish_bus_result( fd_failover_tile_ctx_t * ctx,
                    fd_stem_context_t *      stem,
                    ulong                    nonce,
                    ulong                    result ) {
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce  = nonce;
  out->result = result;
  FD_STORE( ulong, out->payload, ctx->last_vote_slot );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_RESPONSE, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
}

/* Publishes the outcome finish_cmd recorded. */
static void
publish_cmd_answer( fd_failover_tile_ctx_t * ctx,
                    fd_stem_context_t *      stem ) {
  publish_bus_result( ctx, stem, ctx->cmd_nonce, ctx->cmd_result );
  ctx->cmd_nonce     = 0UL;
  ctx->cmd_done      = 0;
  ctx->cmd_step_tail = ctx->cmd_step_head;
}

/* Publishes the oldest unsent step of the pending command. */
static void
publish_cmd_step( fd_failover_tile_ctx_t * ctx,
                  fd_stem_context_t *      stem ) {
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->admin_out_mem, ctx->admin_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce = ctx->cmd_nonce;
  fd_cstr_ncpy( (char *)out->payload, ctx->cmd_step[ ctx->cmd_step_tail%FD_FAILOVER_STEP_CNT ], FD_FAILOVER_BUS_STEP_MAX );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->admin_out_idx, FD_FAILOVER_BUS_STEP, ctx->admin_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->admin_out_chunk = fd_dcache_compact_next( ctx->admin_out_chunk, sizeof(*out), ctx->admin_out_chunk0, ctx->admin_out_wmark );
  ctx->cmd_step_tail++;
}

/* Runs one operator command.  A refused or settled command is answered
   now, an accepted one when the controller decides its outcome.  The
   admin tile validated the ABI already. */
static void
serve_bus_request( fd_failover_tile_ctx_t * ctx,
                   fd_stem_context_t *      stem,
                   long                     now ) {
  fd_adminctl_failover_req_t req;
  fd_memcpy( &req, ctx->bus_req.payload, sizeof(req) );
  char const * cmd_name  = fd_adminctl_failover_cmd_typed( req.cmd );
  ulong        step_head = ctx->cmd_step_head;
  ulong        result    = apply_control( ctx, &req, now );
  if( FD_UNLIKELY( result==FD_FAILOVER_CMD_PENDING ) ) {
    ctx->cmd_nonce     = ctx->bus_req.nonce;
    ctx->cmd_step_tail = step_head; /* the steps it took are sent, older ones are not */
    return;
  }
  char const * flag = ( req.flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE ) ? " --force" : ( req.flags & FD_ADMINCTL_FAILOVER_FLAG_ADOPT ) ? " --adopt" : "";
  if( FD_UNLIKELY( result!=FD_ADMINCTL_RESULT_SUCCESS ) ) FD_LOG_WARNING(( "`%s%s` refused, %s", cmd_name, flag, fd_adminctl_failover_result_cstr( result ) ));
  publish_bus_result( ctx, stem, ctx->bus_req.nonce, result );
}
