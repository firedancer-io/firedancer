/* https://docs.solana.com/developing/programming-model/transactions#anatomy-of-a-transaction */

#include "fd_txn.h"
#include "fd_compact_u16.h"

ulong
fd_txn_parse_core( uchar const             * payload,
                   ulong                     payload_sz,
                   void                    * out_buf,
                   fd_txn_parse_counters_t * counters_opt,
                   ulong *                   payload_sz_opt,
                   int                       allow_zero_signatures ) {
  ulong i = 0UL;
  /* This code does non-trivial parsing of untrusted user input, which
     is a potentially dangerous thing.  The main invariants we need to
     ensure are
         A)   i<=payload_sz  at all times
         B)   i< payload_sz  prior to reading
     As long as these invariants hold, it's safe to read payload[ i ].
     To ensure this, we force the following discipline for all parsing
     steps:
       Step 1. Assert there are enough bytes to read the field
       Step 2. Read the field
       Step 3. Advance i
       Step 4. Validate the field (if there's anything to do)
     This code is structured highly horizontally to make it very clear
     that it is correct.

     The first 3 steps are in three columns.  The variable `i` only
     appears in very specific locations on the line (try searching for
     \<i\> in VIM to see this).

     The CHECK_LEFT( x ) call in the first column and the i+=x in the
     third column always have the same argument, which ensures invariant
     A holds.  "Prior to reading" from invariant B corresponds to the
     middle column, which is the only place `i` is read. Because x is
     positive, the CHECK_LEFT( x ) in the first column ensures invariant
     B holds.

     Unfortunately for variable length integers, we have to combine the
     first two columns into a call to READ_CHECKED_COMPACT_U16 that also
     promises not to use any out-of-bounds data.

     The assignments are done in chunks in as close to the same order as
     possible as the variables are declared in the struct, making it
     very clear every variable has been initialized. */

  /* A temporary for storing the return value of fd_cu16_dec_sz */
  ulong bytes_consumed = 0UL;

  /* Increment counters and return immediately if cond is false. */
  #define CHECK( cond )  do {                                                                                   \
    if( FD_UNLIKELY( !(cond) ) ) {                                                                              \
      if( FD_LIKELY( counters_opt ) ) {                                                                         \
        counters_opt->failure_ring[ ( counters_opt->failure_cnt++ )%FD_TXN_PARSE_COUNTERS_RING_SZ ] = __LINE__; \
      }                                                                                                         \
      return 0UL;                                                                                               \
    }                                                                                                           \
  } while( 0 )
  /* CHECK that it is safe to read at least n more bytes assuming i is
     the current location. n is untrusted and could trigger overflow, so
     don't do i+n<=payload_sz */
  #define CHECK_LEFT( n ) CHECK( (n)<=(payload_sz-i) )
  /* READ_CHECKED_COMPACT_U16 safely reads a compact-u16 from the
     indicated location in the payload.  It stores the resulting value
     in the ushort variable called var_name.  It stores the size in
     out_sz. */
  #define READ_CHECKED_COMPACT_U16( out_sz, var_name, where )               \
    do {                                                                    \
      ulong _where = (where);                                               \
      ulong _out_sz = fd_cu16_dec_sz( payload+_where, payload_sz-_where );  \
      CHECK( _out_sz );                                                     \
      (var_name) = fd_cu16_dec_fixed( payload+_where, _out_sz );            \
      (out_sz)   = _out_sz;                                                 \
    } while( 0 )

  /* Minimal instr has 1B for program id, 1B for an acct_addr list
     containing no accounts, 1B for length-0 instruction data */
  #define MIN_INSTR_SZ (3UL)
  CHECK( payload_sz<=FD_TXN_MTU );

  /* The documentation sometimes calls signature_cnt a compact-u16 and
     sometimes a u8.  Because of transaction size limits, even allowing
     for a 3k transaction caps the signatures at 48, so we're
     comfortably in the range where a compact-u16 and a u8 are
     represented the same way. */
  CHECK_LEFT( 1UL                               );   uchar signature_cnt  = payload[ i ];     i++;
  /* Must have at least one signer for the fee payer */
  CHECK( allow_zero_signatures | ((1UL<=signature_cnt) & (signature_cnt<=FD_TXN_SIG_MAX)) );
  CHECK_LEFT( FD_TXN_SIGNATURE_SZ*signature_cnt );   ulong signature_off  =          i  ;     i+=FD_TXN_SIGNATURE_SZ*signature_cnt;

  /* Not actually parsing anything, just store. */   ulong message_off    =          i  ;
  CHECK_LEFT( 1UL                               );   uchar header_b0      = payload[ i ];     i++;

  uchar transaction_version;
  if( FD_LIKELY( (ulong)header_b0 & 0x80UL ) ) {
    /* This is a versioned transaction */
    transaction_version = header_b0 & 0x7F;
    CHECK( transaction_version==FD_TXN_V0 ); /* Only recognized one so far */

    CHECK_LEFT( 1UL                             );   CHECK(  signature_cnt==payload[ i ] );   i++;
  } else {
    transaction_version = FD_TXN_VLEGACY;
    CHECK( signature_cnt==header_b0 );
  }
  CHECK_LEFT( 1UL                               );   uchar ro_signed_cnt  = payload[ i ];     i++;
  /* Must have at least one writable signer for the fee payer */
  CHECK( allow_zero_signatures | (ro_signed_cnt<signature_cnt ) );

  CHECK_LEFT( 1UL                               );   uchar ro_unsigned_cnt= payload[ i ];     i++;

  ushort acct_addr_cnt = (ushort)0;
  READ_CHECKED_COMPACT_U16( bytes_consumed,                acct_addr_cnt,            i );     i+=bytes_consumed;
  CHECK( (signature_cnt<=acct_addr_cnt) & (acct_addr_cnt<=FD_TXN_ACCT_ADDR_MAX) );
  CHECK( (ulong)signature_cnt+(ulong)ro_unsigned_cnt<=(ulong)acct_addr_cnt );



  CHECK_LEFT( FD_TXN_ACCT_ADDR_SZ*acct_addr_cnt );   ulong acct_addr_off  =          i  ;     i+=FD_TXN_ACCT_ADDR_SZ*acct_addr_cnt;
  CHECK_LEFT( FD_TXN_BLOCKHASH_SZ               );   ulong recent_blockhash_off =    i  ;     i+=FD_TXN_BLOCKHASH_SZ;

  ushort instr_cnt = (ushort)0;
  READ_CHECKED_COMPACT_U16( bytes_consumed,                instr_cnt,                i );     i+=bytes_consumed;

  CHECK( (ulong)instr_cnt<=FD_TXN_INSTR_MAX     );
  CHECK_LEFT( MIN_INSTR_SZ*instr_cnt            );
  /* If it has >0 instructions, it must have at least one other account
     address (the program id) that can't be the fee payer */
  CHECK( allow_zero_signatures | ((ulong)acct_addr_cnt>(!!instr_cnt)) );

  fd_txn_t * parsed = (fd_txn_t *)out_buf;

  if( parsed ) {
    parsed->transaction_version           = transaction_version;
    parsed->signature_cnt                 = signature_cnt;
    parsed->signature_off                 = (ushort)signature_off;
    parsed->message_off                   = (ushort)message_off;
    parsed->readonly_signed_cnt           = ro_signed_cnt;
    parsed->readonly_unsigned_cnt         = ro_unsigned_cnt;
    parsed->acct_addr_cnt                 = acct_addr_cnt;
    parsed->acct_addr_off                 = (ushort)acct_addr_off;
    parsed->recent_blockhash_off          = (ushort)recent_blockhash_off;
    /* Need to assign addr_table_lookup_cnt,
       addr_table_adtl_writable_cnt, addr_table_adtl_cnt,
       _padding_reserved_1 later */
    parsed->instr_cnt                     = instr_cnt;
  }

  uchar max_acct = 0UL;
  for( ulong j=0UL; j<instr_cnt; j++ ) {

    /* Parsing instruction */
    ushort acct_cnt = (ushort)0;
    ushort data_sz  = (ushort)0;
    CHECK_LEFT( MIN_INSTR_SZ                    );   uchar program_id     = payload[ i ];     i++;
    READ_CHECKED_COMPACT_U16( bytes_consumed,             acct_cnt,                  i );     i+=bytes_consumed;
    CHECK_LEFT( acct_cnt                        );   ulong acct_off       =          i  ;
    for( ulong k=0; k<acct_cnt; k++ ) { max_acct=fd_uchar_max( max_acct,  payload[ k+i ] ); } i+=acct_cnt;
    READ_CHECKED_COMPACT_U16( bytes_consumed,             data_sz,                   i );     i+=bytes_consumed;
    CHECK_LEFT( data_sz                         );   ulong data_off       =          i  ;     i+=data_sz;

    /* Account 0 is the fee payer and the program can't be the fee
       payer.  The fee payer account must be owned by the system
       program, but the program must be an executable account and the
       system program is not permitted to own any executable account.
       As of https://github.com/solana-labs/solana/issues/25034, the
       program ID can't come from a table. */
    CHECK( allow_zero_signatures | ((0UL < (ulong)program_id) & ((ulong)program_id < (ulong)acct_addr_cnt) ) );

    if( parsed ){
      parsed->instr[ j ].program_id          = program_id;
      parsed->instr[ j ]._padding_reserved_1 = (uchar)0;
      parsed->instr[ j ].acct_cnt            = acct_cnt;
      parsed->instr[ j ].data_sz             = data_sz;
      /* By our invariant, i<size when it was copied into acct_off and
         data_off, and size<=USHORT_MAX from above, so this cast is safe */
      parsed->instr[ j ].acct_off            = (ushort)acct_off;
      parsed->instr[ j ].data_off            = (ushort)data_off;
    }
  }
  #undef MIN_INSTR_SIZE

  ushort addr_table_cnt               = 0;
  ulong  addr_table_adtl_writable_cnt = 0;
  ulong  addr_table_adtl_cnt          = 0;

  /* parsed->instr_cnt set above, so calling get_address_tables is safe */
  fd_txn_acct_addr_lut_t * address_tables = (parsed == NULL) ? NULL : fd_txn_get_address_tables( parsed );
  if( FD_LIKELY( transaction_version==FD_TXN_V0 ) ) {
  #define MIN_ADDR_LUT_SIZE (34UL)
    READ_CHECKED_COMPACT_U16( bytes_consumed,             addr_table_cnt,            i );     i+=bytes_consumed;
    CHECK( addr_table_cnt <= FD_TXN_ADDR_TABLE_LOOKUP_MAX );
    CHECK_LEFT( MIN_ADDR_LUT_SIZE*addr_table_cnt );

    for( ulong j=0; j<addr_table_cnt; j++ ) {
      CHECK_LEFT( FD_TXN_ACCT_ADDR_SZ           );   ulong addr_off       =          i  ;     i+=FD_TXN_ACCT_ADDR_SZ;

      ushort writable_cnt = 0;
      ushort readonly_cnt = 0;
      READ_CHECKED_COMPACT_U16( bytes_consumed,            writable_cnt,             i );     i+=bytes_consumed;
      CHECK_LEFT( writable_cnt                  );   ulong writable_off   =          i  ;     i+=writable_cnt;
      READ_CHECKED_COMPACT_U16( bytes_consumed,            readonly_cnt,             i );     i+=bytes_consumed;
      CHECK_LEFT( readonly_cnt                  );   ulong readonly_off   =          i  ;     i+=readonly_cnt;

      CHECK( writable_cnt<=FD_TXN_ACCT_ADDR_MAX-acct_addr_cnt ); /* implies <256 ... */
      CHECK( readonly_cnt<=FD_TXN_ACCT_ADDR_MAX-acct_addr_cnt );
      CHECK( (ushort)1   <=writable_cnt+readonly_cnt          ); /* ... so the sum can't overflow */
      if( address_tables ) {
        address_tables[ j ].addr_off      = (ushort)addr_off;
        address_tables[ j ].writable_cnt  = (uchar )writable_cnt;
        address_tables[ j ].readonly_cnt  = (uchar )readonly_cnt;
        address_tables[ j ].writable_off  = (ushort)writable_off;
        address_tables[ j ].readonly_off  = (ushort)readonly_off;
      }

      addr_table_adtl_writable_cnt += (ulong)writable_cnt;
      addr_table_adtl_cnt          += (ulong)writable_cnt + (ulong)readonly_cnt;
    }
  }
  #undef MIN_ADDR_LUT_SIZE
  /* Check for leftover bytes if out_sz_opt not specified. */
  CHECK( (payload_sz_opt!=NULL) | (i==payload_sz) );

  CHECK( acct_addr_cnt+addr_table_adtl_cnt<=FD_TXN_ACCT_ADDR_MAX ); /* implies addr_table_adtl_cnt<256 */

  /* Final validation that all the account address indices are in range */
  CHECK( max_acct < acct_addr_cnt + addr_table_adtl_cnt );

  if( parsed ) {
    /* Assign final variables */
    parsed->addr_table_lookup_cnt         = (uchar)addr_table_cnt;
    parsed->addr_table_adtl_writable_cnt  = (uchar)addr_table_adtl_writable_cnt;
    parsed->addr_table_adtl_cnt           = (uchar)addr_table_adtl_cnt;
    parsed->_padding_reserved_1           = (uchar)0;
  }

  if( FD_LIKELY( counters_opt   ) ) counters_opt->success_cnt++;
  if( FD_LIKELY( payload_sz_opt ) ) *payload_sz_opt = i;
  return fd_txn_footprint( instr_cnt, addr_table_cnt );

  #undef CHECK
  #undef CHECK_LEFT
  #undef READ_CHECKED_COMPACT_U16
}
