ENCODE_FN {

  PREP

  switch( enc->state ) {
  case STATE_SLOT_DELTA: {
    PUSH_VAL( ulong, 1UL       ); /* slot_deltas_len = 1 */
    PUSH_VAL( ulong, enc->slot ); /* slot                */
    PUSH_VAL( uchar, 1         ); /* is_root = true      */
    PUSH_VAL( ulong, 0UL       ); /* status_len = 0      */
    enc->state = STATE_DONE;
    break;
  }
  case STATE_DONE:
    return 0UL;
  }

  return RET_EXPR;
}

#undef PREP
#undef ENCODE_FN
#undef PUSH_VAL
#undef RET_EXPR
