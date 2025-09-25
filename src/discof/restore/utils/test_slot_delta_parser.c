#include "fd_slot_delta_parser.h"

#include "../../../util/fd_util.h"

static void
entry_cb_no_err( void *                        _ctx,
                fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  FD_TEST( entry->slot==1000UL );
  FD_TEST( entry->blockhash[0]==1 && entry->blockhash[1]==2 && entry->blockhash[2]==3 );
  FD_TEST( entry->txnhash[0]==4 && entry->txnhash[1]==5 && entry->txnhash[2]==6 );
  FD_TEST( entry->result==0U );
}

static void
entry_cb_with_txn_err( void *                    _ctx,
                       fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  FD_TEST( entry->slot==1000UL );
  FD_TEST( entry->blockhash[0]==1 && entry->blockhash[1]==2 && entry->blockhash[2]==3 );
  FD_TEST( entry->txnhash[0]==4 && entry->txnhash[1]==5 && entry->txnhash[2]==6 );
  FD_TEST( entry->result==42U );
}

static void
entry_cb_with_txn_custom_err( void *                    _ctx,
                              fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  FD_TEST( entry->slot==1000UL );
  FD_TEST( entry->blockhash[0]==1 && entry->blockhash[1]==2 && entry->blockhash[2]==3 );
  FD_TEST( entry->txnhash[0]==4 && entry->txnhash[1]==5 && entry->txnhash[2]==6 );
  FD_TEST( entry->result==12U );
}

static void
entry_cb_with_instr_err( void *                        _ctx,
                         fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  FD_TEST( entry->slot==1000UL );
  FD_TEST( entry->blockhash[0]==1 && entry->blockhash[1]==2 && entry->blockhash[2]==3 );
  FD_TEST( entry->txnhash[0]==4 && entry->txnhash[1]==5 && entry->txnhash[2]==6 );
  FD_TEST( entry->result==15U );
}

static void
entry_cb_with_instr_custom_err( void *                        _ctx,
                                fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  FD_TEST( entry->slot==1000UL );
  FD_TEST( entry->blockhash[0]==1 && entry->blockhash[1]==2 && entry->blockhash[2]==3 );
  FD_TEST( entry->txnhash[0]==4 && entry->txnhash[1]==5 && entry->txnhash[2]==6 );
  FD_TEST( entry->result==16U );
}

static void
entry_cb_with_instr_borsh_io_err( void *                        _ctx,
                                  fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  FD_TEST( entry->slot==1000UL );
  FD_TEST( entry->blockhash[0]==1 && entry->blockhash[1]==2 && entry->blockhash[2]==3 );
  FD_TEST( entry->txnhash[0]==4 && entry->txnhash[1]==5 && entry->txnhash[2]==6 );
  FD_TEST( entry->result==44U );
}

static void
entry_cb_multiple( void *                        _ctx,
                   fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  static uint call_cnt = 0U;
  if( FD_LIKELY( call_cnt<7 ) ) FD_TEST( entry->slot==1000UL );
  else                          FD_TEST( entry->slot==1001UL );

  if( FD_LIKELY( call_cnt<6 ) )       FD_TEST( entry->blockhash[0]==0 && entry->blockhash[1]==0 && entry->blockhash[2]==0 );
  else if( FD_LIKELY( call_cnt==6 ) ) FD_TEST( entry->blockhash[0]==0 && entry->blockhash[1]==call_cnt && entry->blockhash[2]==call_cnt );
  else                                FD_TEST( entry->blockhash[0]==1 && entry->blockhash[1]==7 && entry->blockhash[2]==7 );

  FD_TEST( entry->txnhash[0]==call_cnt && entry->txnhash[1]==call_cnt && entry->txnhash[2]==call_cnt );

  if( FD_LIKELY( call_cnt<5 ) )       FD_TEST( entry->result==(uchar)call_cnt );
  else if( FD_LIKELY( call_cnt==5 ) ) FD_TEST( entry->result==44U );
  else if( FD_LIKELY( call_cnt==6 ) ) FD_TEST( entry->result==0U );
  else if( FD_LIKELY( call_cnt<12 ) ) FD_TEST( entry->result==call_cnt-7U );
  else                                FD_TEST( entry->result==44U );

  call_cnt++;
  if( FD_LIKELY( call_cnt==13U ) ) call_cnt=0U;
}

static void
entry_cb_multiple_v2( void *                     _ctx,
                   fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;

  static uint call_cnt = 0U;
  if( FD_LIKELY( call_cnt<6 ) ) FD_TEST( entry->slot==1000UL );
  else                          FD_TEST( entry->slot==1002UL );

  if( FD_LIKELY( call_cnt<5 ) )       FD_TEST( entry->blockhash[0]==0 && entry->blockhash[1]==0 && entry->blockhash[2]==0 );
  else if( FD_LIKELY( call_cnt==5 ) ) FD_TEST( entry->blockhash[0]==0 && entry->blockhash[1]==call_cnt && entry->blockhash[2]==call_cnt );
  else                                FD_TEST( entry->blockhash[0]==2 && entry->blockhash[1]==6 && entry->blockhash[2]==6 );

  FD_TEST( entry->txnhash[0]==call_cnt && entry->txnhash[1]==call_cnt && entry->txnhash[2]==call_cnt );

  if( FD_LIKELY( call_cnt<5 ) )       FD_TEST( entry->result==(uchar)call_cnt );
  else if( FD_LIKELY( call_cnt==5 ) ) FD_TEST( entry->result==0U );
  else                                FD_TEST( entry->result==call_cnt-6U );

  call_cnt++;
  if( FD_LIKELY( call_cnt==11U ) ) call_cnt=0U;
}

static void
entry_cb_noop( void *                        _ctx,
               fd_sstxncache_entry_t const * entry ) {
  (void)_ctx;
  (void)entry;
  FD_TEST( 1==2 ); /* should not be called */
}

static void
mock_one_input( uchar * input,
                ulong   input_sz,
                int     is_root,
                ulong   slot ) {
  FD_TEST( input_sz>=93UL );
  uchar * p = input;

  /* len is 1 */
  *(ulong *)p = 1UL;
  p += sizeof(ulong);

  /* slot is 1000 */
  *(ulong *)p = slot;
  p += sizeof(ulong);

  /* is root is 1 */
  *p = (uchar)is_root;
  p += sizeof(uchar);

  /* status len */
  *(ulong *)p = 1UL;
  p += sizeof(ulong);

  /* blockhash */
  uchar blockhash[ 32UL ] = {1, 2, 3};
  fd_memcpy( p, blockhash, 32UL );
  p += 32UL;

  /* txn idx */
  *(ulong *)p = 12345UL;
  p += sizeof(ulong);

  /* cache status len */
  *(ulong *)p = 1UL;
  p += sizeof(ulong);

  /* key slice */
  uchar key_slice[ 20UL ] = {4, 5, 6};
  fd_memcpy( p, key_slice, 20UL );
  p += 20UL;
}

#define MOCK_ERROR_TYPE_NONE           (0U)
#define MOCK_ERROR_TYPE_TXN            (1U)
#define MOCK_ERROR_TYPE_TXN_CUSTOM     (2U)
#define MOCK_ERROR_TYPE_INSTR          (3U)
#define MOCK_ERROR_TYPE_INSTR_CUSTOM   (4U)
#define MOCK_ERROR_TYPE_INSTR_BORSH_IO (5U)

static uchar *
insert_error( uchar * input,
              ulong   input_sz,
              uint    error_type,
              uint    error_code ) {
  uchar * p = input;

  /* result */
  switch( error_type ) {
    case MOCK_ERROR_TYPE_NONE:
      FD_TEST( input_sz>=4UL );
      *(uint *)p = 0U;
      p += sizeof(uint);
      break;
    case MOCK_ERROR_TYPE_TXN:
      FD_TEST( input_sz>=8UL );
      *(uint *)p = 1U;
      p += sizeof(uint);
      *(uint *)p = (uint)error_code;
      p += sizeof(uint);
      break;
    case MOCK_ERROR_TYPE_TXN_CUSTOM:
      FD_TEST( input_sz>=9UL );
      *(uint *)p = 1U;
      p += sizeof(uint);
      *(uint *)p = 30U;
      p += sizeof(uint);
      *p = (uchar)error_code;
      p += sizeof(uchar);
      break;
    case MOCK_ERROR_TYPE_INSTR:
      FD_TEST( input_sz>=13UL );
      *(uint *)p = 1U;
      p += sizeof(uint);
      *(uint *)p = 8U;
      p += sizeof(uint);
      *p = 0U; /* instr idx */
      p += sizeof(uchar);
      *(uint *)p = (uint)error_code;
      p += sizeof(uint);
      break;
    case MOCK_ERROR_TYPE_INSTR_CUSTOM:
      FD_TEST( input_sz>=17UL );
      *(uint *)p = 1U;
      p += sizeof(uint);
      *(uint *)p = 8U;
      p += sizeof(uint);
      *p = 0U; /* instr idx */
      p += sizeof(uchar);
      *(uint *)p = 25U;
      p += sizeof(uint);
      *(uint *)p = (uint)error_code;
      p += sizeof(uint);
      break;
    case MOCK_ERROR_TYPE_INSTR_BORSH_IO:
      FD_TEST( input_sz>=29UL );
      *(uint *)p = 1U;
      p += sizeof(uint);
      *(uint *)p = 8U;
      p += sizeof(uint);
      *p = 0U; /* instr idx */
      p += sizeof(uchar);
      *(uint *)p = 44U;
      p += sizeof(uint);
      *(ulong *)p = 8UL;
      p += sizeof(ulong);
      char const * err_str = "1234567";
      fd_memcpy( p, err_str, 8UL );
      p += 8UL;
      break;
    default:
      FD_LOG_ERR(( "unknown error type %u", error_type ));
      break;
  }
  return p;
}

static void
mock_one_input_with_error( uchar * input,
                           ulong   input_sz,
                           int     is_root,
                           ulong   slot,
                           uint    error_type,
                           uint    error_code ) {
  FD_TEST( input_sz>=93UL );
  mock_one_input( input, input_sz, is_root, slot );
  uchar * p = input;
  p += 93UL;

  insert_error( p, input_sz - 93UL, error_type, error_code );
}

static uchar *
mock_slot_delta_input( uchar * input,
                       ulong   input_sz,
                       ulong   num_slot_deltas,
                       ulong * slots,
                       ulong * num_statuses,
                       ulong * num_cache_statuses,
                       uint *  error_types,
                       uint *  error_codes ) {
  uchar * p = input;
  uchar num_entries = 0;

  /* len */
  *(ulong *)p = num_slot_deltas;
  p += sizeof(ulong);

  for( ulong i=0UL; i<num_slot_deltas; i++ ) {
    *(ulong *)p = slots[i]; /* slot */
    p += sizeof(ulong);

    *p = 1; /* is_root */
    p += sizeof(uchar);

    *(ulong *)p = num_statuses[i]; /* status len */
    p += sizeof(ulong);

    for( ulong j=0UL; j<num_statuses[i]; j++ ) {
      uchar blockhash[ 32UL ] = {(uchar)i, num_entries, num_entries};
      fd_memcpy( p, blockhash, 32UL );
      p += 32UL;

      *(ulong *)p = 12345UL; /* txn idx */
      p += sizeof(ulong);

      *(ulong *)p = num_cache_statuses[j]; /* cache status len */
      p += sizeof(ulong);

      for( ulong k=0UL; k<num_cache_statuses[j]; k++ ) {
        uchar key_slice[ 20UL ] = {num_entries, num_entries, num_entries};
        fd_memcpy( p, key_slice, 20UL );
        p += 20UL;

        p = insert_error( p, input_sz - (ulong)(p - input), error_types[k], error_codes[k] );
        num_entries++;
      }
    }
  }
  return p;
}

static void
consume_piecewise( fd_slot_delta_parser_t * parser,
                   uchar const *            input,
                   ulong                    input_sz,
                   ulong                    chunk_sz,
                   int                      expected_result ) {
  ulong bytes = input_sz;
  uchar const * p = input;
  while( bytes ) {
    if( FD_LIKELY( bytes>chunk_sz ) ) {
      FD_TEST( fd_slot_delta_parser_consume( parser, p, chunk_sz )==1 );
      bytes -= chunk_sz;
      p     += chunk_sz;
    } else {
      FD_TEST( fd_slot_delta_parser_consume( parser, p, bytes )==expected_result );
      bytes = 0UL;
      p    += bytes;
    }
  }
}

static void
test_one_entry( fd_slot_delta_parser_t * parser ) {
  uchar input[ 97UL ];
  fd_slot_delta_parser_init( parser, entry_cb_no_err, NULL );

  mock_one_input_with_error( input, sizeof(input), 1, 1000UL, MOCK_ERROR_TYPE_NONE, 0 );

  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  /* consume piece wise */
  fd_slot_delta_parser_init( parser, entry_cb_no_err, NULL );
  consume_piecewise( parser, input, sizeof(input), 20UL, 0 );

  /* consume piece wise */
  fd_slot_delta_parser_init( parser, entry_cb_no_err, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_one_entry_not_root( fd_slot_delta_parser_t * parser ) {
  uchar input[ 97UL ];
  mock_one_input_with_error( input, sizeof(input), 0, 1000UL, MOCK_ERROR_TYPE_NONE, 0 );
  fd_slot_delta_parser_init( parser, entry_cb_no_err, NULL );
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==FD_SLOT_DELTA_PARSER_ERROR_SLOT_IS_NOT_ROOT );
}

static void
test_one_entry_with_txn_error( fd_slot_delta_parser_t * parser ) {
  uchar input[ 101UL ];
  fd_slot_delta_parser_init( parser, entry_cb_with_txn_err, NULL );
  mock_one_input_with_error( input, sizeof(input), 1, 1000UL, MOCK_ERROR_TYPE_TXN, 42U );

  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_with_txn_err, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_one_entry_with_txn_custom_error( fd_slot_delta_parser_t * parser ) {
  uchar input[ 102UL ];
  fd_slot_delta_parser_init( parser, entry_cb_with_txn_custom_err, NULL );

  mock_one_input_with_error( input, sizeof(input), 1, 1000UL, MOCK_ERROR_TYPE_TXN_CUSTOM, 12U );

  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_with_txn_custom_err, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_one_entry_with_instr_error( fd_slot_delta_parser_t * parser ) {
  uchar input[ 106UL ];
  fd_slot_delta_parser_init( parser, entry_cb_with_instr_err, NULL );

  mock_one_input_with_error( input, sizeof(input), 1, 1000UL, MOCK_ERROR_TYPE_INSTR, 15U );

  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_with_instr_err, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_one_entry_with_instr_custom_error( fd_slot_delta_parser_t * parser ) {
  uchar input[ 110UL ];
  fd_slot_delta_parser_init( parser, entry_cb_with_instr_custom_err, NULL );

  mock_one_input_with_error( input, sizeof(input), 1, 1000UL, MOCK_ERROR_TYPE_INSTR_CUSTOM, 16U );

  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_with_instr_custom_err, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_one_entry_with_instr_borsh_io_error( fd_slot_delta_parser_t * parser ) {
  uchar input[ 122UL ];
  fd_slot_delta_parser_init( parser, entry_cb_with_instr_borsh_io_err, NULL );

  mock_one_input_with_error( input, sizeof(input), 1, 1000UL, MOCK_ERROR_TYPE_INSTR_BORSH_IO, 0U );

  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_with_instr_borsh_io_err, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_multiple_entries( fd_slot_delta_parser_t * parser ) {
  uchar input[ 627UL ];
  ulong slots[ 3UL ]              = {1000UL, 1001UL, 1002UL};
  ulong num_statuses[ 3UL ]       = {2UL, 1UL, 0UL};
  ulong num_cache_statuses[ 2UL ] = {6UL, 1UL};
  uint  error_types[ 6UL ]        = {MOCK_ERROR_TYPE_NONE, MOCK_ERROR_TYPE_TXN, MOCK_ERROR_TYPE_TXN_CUSTOM, MOCK_ERROR_TYPE_INSTR, MOCK_ERROR_TYPE_INSTR_CUSTOM, MOCK_ERROR_TYPE_INSTR_BORSH_IO};
  uint  error_codes[ 6UL ]        = {0U, 1U, 2U, 3U, 4U, 5U};

  uchar * p = mock_slot_delta_input( input, sizeof(input), 3UL, slots, num_statuses, num_cache_statuses, error_types, error_codes );
  FD_TEST( (ulong)(p - input)==627UL );

  fd_slot_delta_parser_init( parser, entry_cb_multiple, NULL );
  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_multiple, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_multiple_entries_v2( fd_slot_delta_parser_t * parser ) {
  uchar input[ 577UL ];
  ulong slots[ 3UL ]              = {1000UL, 1001UL, 1002UL};
  ulong num_statuses[ 3UL ]       = {3UL, 0UL, 1UL};
  ulong num_cache_statuses[ 3UL ] = {5UL, 0UL, 1UL};
  uint  error_types[ 5UL ]        = {MOCK_ERROR_TYPE_NONE, MOCK_ERROR_TYPE_TXN, MOCK_ERROR_TYPE_TXN_CUSTOM, MOCK_ERROR_TYPE_INSTR, MOCK_ERROR_TYPE_INSTR_CUSTOM};
  uint  error_codes[ 5UL ]        = {0U, 1U, 2U, 3U, 4U};

  uchar * p = mock_slot_delta_input( input, sizeof(input), 3UL, slots, num_statuses, num_cache_statuses, error_types, error_codes );
  FD_TEST( (ulong)(p - input)==577UL );

  fd_slot_delta_parser_init( parser, entry_cb_multiple_v2, NULL );
  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_multiple_v2, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_multiple_slot_deltas_no_entries( fd_slot_delta_parser_t * parser ) {
  uchar input[ 203UL ];
  ulong slots[ 3UL ]              = {1000UL, 1001UL, 1002UL};
  ulong num_statuses[ 3UL ]       = {1UL, 1UL, 1UL};
  ulong num_cache_statuses[ 2UL ] = {0UL};

  uchar * p = mock_slot_delta_input( input, sizeof(input), 3UL, slots, num_statuses, num_cache_statuses, NULL, NULL );
  FD_TEST( (ulong)(p - input)==203UL );

  fd_slot_delta_parser_init( parser, entry_cb_noop, NULL );
  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==0 );

  fd_slot_delta_parser_init( parser, entry_cb_noop, NULL );
  consume_piecewise( parser, input, sizeof(input), 3UL, 0 );
}

static void
test_duplicate_slots( fd_slot_delta_parser_t * parser ) {
  uchar input[ 577UL ];
  ulong slots[ 3UL ]              = {1000UL, 1001UL, 1000UL};
  ulong num_statuses[ 3UL ]       = {3UL, 0UL, 1UL};
  ulong num_cache_statuses[ 3UL ] = {5UL, 0UL, 1UL};
  uint  error_types[ 5UL ]        = {MOCK_ERROR_TYPE_NONE, MOCK_ERROR_TYPE_TXN, MOCK_ERROR_TYPE_TXN_CUSTOM, MOCK_ERROR_TYPE_INSTR, MOCK_ERROR_TYPE_INSTR_CUSTOM};
  uint  error_codes[ 5UL ]        = {0U, 1U, 2U, 3U, 4U};

  uchar * p = mock_slot_delta_input( input, sizeof(input), 3UL, slots, num_statuses, num_cache_statuses, error_types, error_codes );
  FD_TEST( (ulong)(p - input)==577UL );

  fd_slot_delta_parser_init( parser, NULL, NULL );
  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==FD_SLOT_DELTA_PARSER_ERROR_SLOT_HASH_MULTIPLE_ENTRIES );
}

static void
test_too_many_entries( fd_slot_delta_parser_t * parser ) {
  uchar input[ 5125UL ];
  ulong slots[ 301UL ];
  ulong num_statuses[ 301UL ];

  for( ulong i=0UL; i<301UL; i++ ) {
    slots[i]        = 1000UL + i;
    num_statuses[i] = 0UL;
  }

  uchar * p = mock_slot_delta_input( input, sizeof(input), 301UL, slots, num_statuses, NULL, NULL, NULL );
  FD_TEST( (ulong)(p - input)==5125UL );

  fd_slot_delta_parser_init( parser, NULL, NULL );
  /* consume all at once */
  FD_TEST( fd_slot_delta_parser_consume( parser, input, sizeof(input) )==FD_SLOT_DELTA_PARSER_ERROR_TOO_MANY_ENTRIES );
}

int main( int     argc,
          char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );

  FD_TEST( wksp );
  void * _slot_delta_parser_mem = fd_wksp_alloc_laddr( wksp, fd_slot_delta_parser_align(), fd_slot_delta_parser_footprint(), 1UL );
  fd_slot_delta_parser_t * slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( _slot_delta_parser_mem ) );
  FD_TEST( slot_delta_parser );

  test_one_entry( slot_delta_parser );
  test_one_entry_not_root( slot_delta_parser );

  test_one_entry_with_txn_error( slot_delta_parser );
  test_one_entry_with_txn_custom_error( slot_delta_parser );
  test_one_entry_with_instr_error( slot_delta_parser );
  test_one_entry_with_instr_custom_error( slot_delta_parser );
  test_one_entry_with_instr_borsh_io_error( slot_delta_parser );

  test_multiple_entries( slot_delta_parser );
  test_multiple_entries_v2( slot_delta_parser );
  test_multiple_slot_deltas_no_entries( slot_delta_parser );
  test_duplicate_slots( slot_delta_parser );
  test_too_many_entries( slot_delta_parser );

  fd_wksp_free_laddr( fd_slot_delta_parser_delete( fd_slot_delta_parser_leave( slot_delta_parser ) ) );

  return 0;
}
