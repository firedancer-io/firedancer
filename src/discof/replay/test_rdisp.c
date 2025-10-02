#include <stdalign.h>

#include "fd_rdisp.h"
#if FD_HAS_HOSTED
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#define TEST_FOOTPRINT (512UL*1024UL*1024UL)
uchar footprint[ TEST_FOOTPRINT ] __attribute__((aligned(128)));
uint  verify_scratch[ 512UL ];

#define SEED 17UL

/* so that if/when we change RDISP_BLOCK_TAG_T, only one function has to
   change. */
static inline FD_RDISP_BLOCK_TAG_T tag( ulong x ) { return x; }
static inline int tag_eq( FD_RDISP_BLOCK_TAG_T t1, ulong t2 ) { return t1==t2; }

static ulong
add_txn( fd_rdisp_t *         rdisp,
         fd_rng_t   *         rng,
         FD_RDISP_BLOCK_TAG_T tag,
         char const *         writable,
         char const *         readonly,
         int                  serializing ) {
  char categorized[3][2][128]; /* (signer, nonsigner, alt) x (writeble, readonly) x accts */
  ulong cat_cnts[3][2] = { 0 };

  for( ulong j=0UL; j<2UL; j++ ) {
    char const * str = fd_ptr_if( j==0UL, writable, readonly );
    while( *str ) {
      ulong cat = fd_rng_uint_roll( rng, 3UL );
      categorized[cat][j][ cat_cnts[cat][j]++ ] = *str;
      str++;
    }
  }

  FD_TEST( cat_cnts[0][0]+cat_cnts[0][1]+cat_cnts[1][0]+cat_cnts[1][1]<=38UL );

  uchar _txn[ sizeof(fd_txn_t) ] __attribute__((aligned(alignof(fd_txn_t)))) = { 0 };

  fd_txn_t * txn = (fd_txn_t *)fd_type_pun( _txn );
  txn->transaction_version = FD_TXN_V0;
  txn->signature_cnt = (uchar)(cat_cnts[0][0]+cat_cnts[0][1]);
  txn->readonly_signed_cnt = (uchar)cat_cnts[0][1];
  txn->readonly_unsigned_cnt = (uchar)cat_cnts[1][1];
  txn->acct_addr_cnt = (uchar)(cat_cnts[0][0]+cat_cnts[0][1]+cat_cnts[1][0]+cat_cnts[1][1]);
  txn->acct_addr_off = 0;
  txn->addr_table_lookup_cnt = 1;
  txn->addr_table_adtl_writable_cnt = (uchar)cat_cnts[2][0];
  txn->addr_table_adtl_cnt = (uchar)(cat_cnts[2][0]+cat_cnts[2][1]);

  uchar payload[ 1232 ];
  fd_acct_addr_t * acct = (fd_acct_addr_t *)fd_type_pun( payload );
  for( ulong i=0UL; i<4UL; i++ ) for( ulong j=0UL; j<cat_cnts[i>>1][i&1]; j++ ) memset( acct++, categorized[i>>1][i&1][j], 32UL );
  fd_acct_addr_t alt[ 128 ];
  acct = alt;
  for( ulong i=4UL; i<6UL; i++ ) for( ulong j=0UL; j<cat_cnts[2][i&1]; j++ ) memset( acct++, categorized[2][i&1][j], 32UL );

  fd_acct_addr_t const * _alt = serializing && fd_rng_uint_roll( rng, 2U )==0U ? NULL : alt;

  return fd_rdisp_add_txn( rdisp, tag, txn, payload, _alt, serializing );
}

static void ushort_to_acct( fd_acct_addr_t * a, ushort v ) { for( ulong k=0UL; k<16UL; k++ ) FD_STORE( ushort, a->b+2UL*k, v ); }

static ulong
add_txn2( fd_rdisp_t *         rdisp,
          fd_rng_t   *         rng,
          FD_RDISP_BLOCK_TAG_T tag,
          ushort const *       accts,
          ulong                acct_cnt ) {
  ushort categorized[3][2][128]; /* (signer, nonsigner, alt) x (writeble, readonly) x accts */
  ulong  cat_cnts[3][2] = { 0 };

  for( ulong i=0UL; i<acct_cnt; i++ ) {
    ulong cat = fd_rng_uint_roll( rng, 3UL );
    ushort a = accts[i];
    categorized[cat][1-(a>>15)][ cat_cnts[cat][1-(a>>15)]++ ] = a&0x7FFF;
  }

  FD_TEST( cat_cnts[0][0]+cat_cnts[0][1]+cat_cnts[1][0]+cat_cnts[1][1]<=38UL );

  uchar _txn[ sizeof(fd_txn_t) ] __attribute__((aligned(alignof(fd_txn_t)))) = { 0 };

  fd_txn_t * txn = (fd_txn_t *)fd_type_pun( _txn );
  txn->transaction_version = FD_TXN_V0;
  txn->signature_cnt = (uchar)(cat_cnts[0][0]+cat_cnts[0][1]);
  txn->readonly_signed_cnt = (uchar)cat_cnts[0][1];
  txn->readonly_unsigned_cnt = (uchar)cat_cnts[1][1];
  txn->acct_addr_cnt = (uchar)(cat_cnts[0][0]+cat_cnts[0][1]+cat_cnts[1][0]+cat_cnts[1][1]);
  txn->acct_addr_off = 0;
  txn->addr_table_lookup_cnt = 1;
  txn->addr_table_adtl_writable_cnt = (uchar)cat_cnts[2][0];
  txn->addr_table_adtl_cnt = (uchar)(cat_cnts[2][0]+cat_cnts[2][1]);

  uchar payload[ 1232 ];
  fd_acct_addr_t * acct = (fd_acct_addr_t *)fd_type_pun( payload );
  for( ulong i=0UL; i<4UL; i++ ) for( ulong j=0UL; j<cat_cnts[i>>1][i&1]; j++ ) ushort_to_acct( acct++, categorized[i>>1][i&1][j] );
  fd_acct_addr_t alt[ 128 ];
  acct = alt;
  for( ulong i=4UL; i<6UL; i++ ) for( ulong j=0UL; j<cat_cnts[2][i&1]; j++ ) ushort_to_acct( acct++, categorized[2][i&1][j] );

  return fd_rdisp_add_txn( rdisp, tag, txn, payload, alt, 0 );
}

static inline ulong
pop_option( ulong * indices,
            ulong   cnt,
            ulong   idx ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( indices[i]==idx ) { indices[i] |= 0x8000000000UL; return idx; }
  }
  return 0UL;
}

typedef struct {
  long timeout;
  uint exec_idx;
  uint txn_idx;
} event_t;
#define PRQ_NAME eq
#define PRQ_T    event_t
#include "../../util/tmpl/fd_prq.c"

static void                               /* unused in non-hosted */
test_mainnet( char const * filename       FD_PARAM_UNUSED,
              ulong        exec_cnt       FD_PARAM_UNUSED,
              ulong        ticks_per_cu   FD_PARAM_UNUSED,
              ulong        staging_lane   FD_PARAM_UNUSED,
              int          check_results  FD_PARAM_UNUSED ) {
  if( (!FD_HAS_HOSTED) || FD_UNLIKELY( !filename ) ) {
    FD_LOG_NOTICE(( "skipping mainnet test.  No --block-file supplied" ));
    return;
  }

#if FD_HAS_HOSTED
  int fdesc = open( filename, O_RDONLY );
  if( FD_UNLIKELY( fdesc==-1 ) ) FD_LOG_ERR(( "opening %s failed. (%i-%s)", filename, errno, fd_io_strerror( errno ) ));
  struct stat sb[1];
  FD_TEST( 0==fstat( fdesc, sb ) );
  ulong file_sz = (ulong)sb->st_size;
  void * ptr = mmap( NULL, file_sz, PROT_READ, MAP_PRIVATE, fdesc, 0L );
  FD_TEST( ptr!=MAP_FAILED );

#define MAX_TXN_PER_BLOCK (5UL*1024UL)
#define MAX_ACCT_PER_BLOCK (16UL*1024UL)
  struct __attribute__((packed)) {
    uint cus_consumed;
    uint txn_payload_sz;
    uint alt_addr_cnt;
    uint acct_cnt;
  } const * parse_ptr;
  parse_ptr = ptr;

  /* transaction i's data is found at acct_result_per_txn[i][j], where
     0<=j<acct_cnt[i] */
  struct __attribute__((packed)) {
    ushort idx;
    ushort w_ver;
  } const * acct_result_per_txn[ MAX_TXN_PER_BLOCK ] = { NULL };
  uchar acct_cnt[ MAX_TXN_PER_BLOCK ];
  uint  cus_consumed[ MAX_TXN_PER_BLOCK ];
  ulong txn_cnt = 0UL;

  FD_TEST( fd_rdisp_footprint( MAX_TXN_PER_BLOCK, 1UL )<TEST_FOOTPRINT );
  fd_rdisp_t * disp = fd_rdisp_join( fd_rdisp_new( footprint, MAX_TXN_PER_BLOCK, 1UL, SEED ) );
  FD_TEST( disp );

  long insert_duration = -fd_tickcount();
  FD_TEST( 0==fd_rdisp_add_block( disp, tag( 0UL ), staging_lane ) );

  while( (ulong)parse_ptr<(ulong)ptr + file_sz ) {
    uchar _txn[ FD_TXN_MAX_SZ ] __attribute__((aligned(2)));

    ulong payload_sz = parse_ptr->txn_payload_sz;
    uchar const * payload = (uchar const *)(parse_ptr+1);
    FD_TEST( fd_txn_parse( payload, payload_sz, _txn, NULL ) );

    fd_acct_addr_t const * alt = (fd_acct_addr_t const *)(payload + payload_sz);
    FD_TEST( parse_ptr->acct_cnt<256U );

    ulong txn_idx = fd_rdisp_add_txn( disp, tag( 0UL ), (fd_txn_t const *)_txn, payload, alt, 0 );
    FD_TEST( txn_idx>0UL );

    cus_consumed[ txn_idx ] = parse_ptr->cus_consumed;
    acct_cnt    [ txn_idx ] = (uchar)parse_ptr->acct_cnt;
    acct_result_per_txn[ txn_idx ] = (void const *)(alt + parse_ptr->alt_addr_cnt);

    parse_ptr = (void const *)(acct_result_per_txn[ txn_idx ] + parse_ptr->acct_cnt);
    txn_cnt++;
  }
  insert_duration += fd_tickcount();


  ushort current_ver[ MAX_ACCT_PER_BLOCK ] = { 0 };

  FD_TEST( exec_cnt<=64UL );
  FD_TEST( eq_footprint( exec_cnt )<256UL );
  uchar prq_mem[ 256UL ] __attribute__((aligned(32UL)));
  event_t * eq = eq_join( eq_new( prq_mem, exec_cnt ) );
  ulong free = fd_ulong_mask_lsb( (int)exec_cnt );

  long sched_duration = -fd_tickcount();
  long advanced_ticks = 0UL;
  ulong txn_remaining = txn_cnt;
  while( txn_remaining ) {
    ulong ready = 0UL;
    while( eq_cnt( eq ) && eq->timeout<fd_tickcount() + advanced_ticks ) {
      fd_rdisp_complete_txn( disp, eq->txn_idx );
      free |= 1UL<<eq->exec_idx;
      if( FD_UNLIKELY( check_results ) ) {
        for( ulong i=0UL; i<acct_cnt[ eq->txn_idx ]; i++ ) {
          FD_TEST( current_ver[ acct_result_per_txn[ eq->txn_idx ][ i ].idx ]==(0x7FFF&acct_result_per_txn[ eq->txn_idx ][ i ].w_ver) );
          current_ver[ acct_result_per_txn[ eq->txn_idx ][ i ].idx ] = (ushort)(current_ver[ acct_result_per_txn[ eq->txn_idx ][ i ].idx ] +
                                                                                (acct_result_per_txn[ eq->txn_idx ][ i ].w_ver>>15) );
        }
      }
      eq_remove_min( eq );
      txn_remaining--;
    }
    if( FD_LIKELY( free && 0UL!=(ready=fd_rdisp_get_next_ready( disp, tag( 0UL ) ) ) ) ) {
      event_t new_e[1] = {{
        .timeout  = fd_tickcount() + advanced_ticks + (long)(cus_consumed[ ready ]*ticks_per_cu),
        .exec_idx = (uint)fd_ulong_find_lsb( free ),
        .txn_idx  = (uint)ready
      }};
      eq_insert( eq, new_e );
      free = fd_ulong_pop_lsb( free );
      if( FD_UNLIKELY( check_results ) ) {
        for( ulong i=0UL; i<acct_cnt[ ready ]; i++ )
          FD_TEST( current_ver[ acct_result_per_txn[ ready ][ i ].idx ]==(0x7FFF&acct_result_per_txn[ ready ][ i ].w_ver) );
      }
    } else if( FD_LIKELY( eq_cnt( eq ) ) ) {
      /* We weren't able to schedule anything, so skip forward in time
         until the next transaction is done. */
      advanced_ticks += fd_long_max( 0L, eq->timeout-(fd_tickcount()+advanced_ticks) );
    } /* else, we're done, and we'll break next iteration */
  }
  sched_duration += fd_tickcount();

# if FD_HAS_DOUBLE
  double ticks_per_ns = fd_tempo_tick_per_ns( NULL );
  FD_LOG_NOTICE(( "inserting %lu transactions took %f ms", txn_cnt, (double)insert_duration/ticks_per_ns * 1e-6 ));
  FD_LOG_NOTICE(( "scheduling took %f ms of work at the replay tile, and an estimated %f ms total time with %lu exec tiles and %f ns/CU",
        (double)sched_duration/ticks_per_ns * 1e-6, (double)(sched_duration+advanced_ticks)/ticks_per_ns * 1e-6, exec_cnt, (double)ticks_per_cu/ticks_per_ns ));
# else
  FD_LOG_NOTICE(( "inserting %lu transactions took %li ms", txn_cnt, insert_duration ));
  FD_LOG_NOTICE(( "scheduling took %li ticks of work at the replay tile, and an estimated %li ticks total time with %lu exec tiles and %lu ticks/CU",
        sched_duration, sched_duration+advanced_ticks, exec_cnt, ticks_per_cu ));
# endif

  munmap( ptr, file_sz );
  close( fdesc );

#endif
}

#define SORT_NAME sn_sort
#define SORT_KEY_T ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../util/tmpl/fd_sort.c"

static void
random_test( fd_rng_t * rng,
             ulong      iterations ) {
  FD_LOG_NOTICE(( "testing random graphs" ));

  ulong depth       = 300UL;
  ulong block_depth = 10UL;
  FD_TEST( fd_rdisp_footprint( depth, block_depth )<=TEST_FOOTPRINT && fd_rdisp_align()<=128UL ); /* if this fails, update the test */
  fd_rdisp_t * disp = fd_rdisp_join( fd_rdisp_new( footprint, depth, block_depth, SEED ) );   FD_TEST( disp );

  const int log_details = 0;

  for( ulong test_outer=0UL; test_outer<iterations; test_outer+=100UL ) {
    FD_LOG_NOTICE(( "iteration %lu/%lu. RNG at (%u, %lu)", test_outer, iterations, fd_rng_seq( rng ), fd_rng_idx( rng ) ));
    for( ulong test=test_outer; test<test_outer+100UL; test++ ) {
      struct {
        ulong  adj_matrix[64]; /* bit s of adj_matrix[d] is 1 if there's an edge from s to d */
        ushort acct_cnt[64];
        ushort acct[64][32]; /* high bit is 1 if write */
        /* internal ids are in [0, 64) and only independent per-lane.
           txn_ids are in [1, 300] and unique across all lanes. */
        uchar txn_id[64];
        uchar internal_id[301];

        ulong dispatched_pool[64];
        ulong dispatched_cnt;

        ulong dispatched;
        ulong expected;
        ulong inserted_cnt;
      } d[4];
      memset( d, '\0', sizeof(d) );


      /* Construct the graphs we're going to insert */
      for( ulong l=0UL; l<4UL; l++ ) {
        FD_TEST( 0UL==fd_rdisp_add_block( disp, tag( l ), l ) );

        memset( d[l].internal_id, '\xFF', sizeof(d[0].internal_id) );

        ulong edge_cnt = fd_rng_uint_roll( rng, 450U );
        for( ulong edge=0UL; edge<edge_cnt; edge++ ) {
          int edge_type = fd_rng_int_roll( rng, 4 );
          ulong cluster_cnt = fd_ulong_max( 2UL, fd_ulong_min( 16UL, 1UL+(ulong)(2.0f*fd_rng_float_exp( rng )+0.5f) ) );
          ulong selected_nodes[16];
          /* Use reservoir sampling to select cluster_cnt nodes without
             replacement */
          ulong selected = 0UL;
          for( ulong i=0UL; i<64UL; i++ ) {
            if( d[l].acct_cnt[i]==32UL ) continue;
            if( selected<cluster_cnt ) selected_nodes[selected++] = i;
            else {
              ulong j = fd_rng_uint_roll( rng, (uint)i );
              if( j<cluster_cnt ) selected_nodes[j] = i;
            }
          }
          sn_sort_inplace( selected_nodes, cluster_cnt );
          char line[256];
          char * cstr = fd_cstr_init( line );

          switch( edge_type ) {
            case 0: /* w-w */
              if( log_details ) cstr = fd_cstr_append_cstr( cstr, "w-w: " );
              for( ulong j=0UL; j<cluster_cnt; j++ ) {
                ulong n = selected_nodes[j];
                if( log_details ) cstr = fd_cstr_append_printf( cstr, "%lu, ", n );
                d[l].acct[n][d[l].acct_cnt[n]++] = (ushort)(0x8000 | edge);
                if( FD_LIKELY( j>0UL ) ) d[l].adj_matrix[n] |= 1UL << (selected_nodes[j-1UL]);
              }
              break;
            case 1: /* r-w */
              if( log_details ) cstr = fd_cstr_append_cstr( cstr, "r-w: " );
              for( ulong j=0UL; j<cluster_cnt; j++ ) {
                ulong n = selected_nodes[j];
                if( log_details ) cstr = fd_cstr_append_printf( cstr, "%lu, ", n );
                d[l].acct[n][d[l].acct_cnt[n]++] = (ushort)fd_ulong_if( j<cluster_cnt-1UL, edge, 0x8000UL | edge );
                if( FD_LIKELY( j<cluster_cnt-1UL ) ) d[l].adj_matrix[selected_nodes[cluster_cnt-1UL]] |= 1UL << n;
              }
              break;
            case 2: /* w-r */
              {
                ulong n0 = selected_nodes[0UL];
                if( log_details ) cstr = fd_cstr_append_cstr( cstr, "w-r: " );
                if( log_details ) cstr = fd_cstr_append_printf( cstr, "%lu; ", n0 );
                d[l].acct[n0][d[l].acct_cnt[n0]++] = (ushort)(0x8000 | edge);
                for( ulong j=1UL; j<cluster_cnt; j++ ) {
                  ulong n = selected_nodes[j];
                  if( log_details ) cstr = fd_cstr_append_printf( cstr, "%lu, ", n );
                  d[l].acct[n][d[l].acct_cnt[n]++] = (ushort)edge;
                  d[l].adj_matrix[n] |= 1UL << n0;
                }
                break;
              }
            case 3: /* r-r */
              if( log_details ) cstr = fd_cstr_append_cstr( cstr, "r-r: " );
              for( ulong j=0UL; j<cluster_cnt; j++ ) {
                ulong n = selected_nodes[j];
                if( log_details ) cstr = fd_cstr_append_printf( cstr, "%lu, ", n );
                d[l].acct[n][d[l].acct_cnt[n]++] = (ushort)edge;
              }
              break;
            default:
              break;
          }
          fd_cstr_fini( cstr );
          if( log_details ) FD_LOG_NOTICE(( "%lu: %s", edge, line ));
        }
      }


      while( (~d[0].dispatched)|(~d[1].dispatched)|(~d[2].dispatched)|(~d[3].dispatched) ) {
        ulong l = fd_rng_uint_roll( rng, 4U );
        ulong insert_cnt = 1UL + (ulong)fd_rng_uint_roll( rng, 4U );
        insert_cnt = fd_ulong_min( insert_cnt, 64UL-d[l].inserted_cnt );
        for( ulong i=0UL; i<insert_cnt; i++ ) {
          ulong txn = d[l].inserted_cnt + i;
          d[l].txn_id[txn] = (uchar)add_txn2( disp, rng, tag( l ), d[l].acct[txn], d[l].acct_cnt[txn] );
          d[l].internal_id[ d[l].txn_id[ txn ] ] = (uchar)txn;
          if( log_details ) FD_LOG_NOTICE(( "Lane %lu internal id %lu has txnid %hhu", l, txn, d[l].txn_id[txn] ));
        }
        d[l].inserted_cnt += insert_cnt;
        while( 1 ) {
          ulong id = fd_rdisp_get_next_ready( disp, tag( l ) );
          if( log_details ) FD_LOG_NOTICE(( "Lane %lu next ready %lu", l, id ));
          if( FD_UNLIKELY( id==0UL ) ) break;
          d[l].dispatched_pool[ d[l].dispatched_cnt++ ] = id;
          d[l].dispatched |= 1UL<<d[l].internal_id[ id ];
        }
        for( ulong i=0UL; i<d[l].inserted_cnt; i++ ) if( FD_UNLIKELY( !d[l].adj_matrix[i] ) ) d[l].expected |= 1UL<<i;
        FD_TEST( d[l].expected==d[l].dispatched );

        if( FD_UNLIKELY( insert_cnt==0UL && d[l].dispatched_cnt==0UL ) ) continue;

        FD_TEST( d[l].dispatched_cnt>0UL );
        /* Now pick one from dispatched_pool to complete it, and adjust
           adj_matrix appropriately. */
        uint selected_i = fd_rng_uint_roll( rng, (uint)d[l].dispatched_cnt );
        ulong selected = d[l].dispatched_pool[ selected_i ];
        if( log_details ) FD_LOG_NOTICE(( "completing %lu", selected ));
        fd_rdisp_complete_txn( disp, selected );
        d[l].dispatched_pool[ selected_i ] = d[l].dispatched_pool[ --d[l].dispatched_cnt ];

        ulong mask = ~(1UL<<d[l].internal_id[ selected ]);
        for( ulong i=0UL; i<64UL; i++ ) d[l].adj_matrix[i] &= mask;
        fd_rdisp_verify( disp, verify_scratch );
      }
      for( ulong l=0UL; l<4UL; l++ ) {
        /* Complete any outstanding ones */
        for( ulong i=0UL; i<d[l].dispatched_cnt; i++ ) fd_rdisp_complete_txn( disp, d[l].dispatched_pool[ i ] );

        fd_rdisp_remove_block( disp, tag( l ) );
        fd_rdisp_verify( disp, verify_scratch );
      }
    }
  }

  fd_rdisp_delete( fd_rdisp_leave( disp ) );
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  char const * block_file = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--block-file",        NULL, NULL   );
  ulong        exec_tiles = fd_env_strip_cmdline_ulong ( &argc, &argv, "--exec-tiles",        NULL, 8UL    );
  ulong        rand_iters = fd_env_strip_cmdline_ulong ( &argc, &argv, "--random-iterations", NULL, 1000UL );
  FD_LOG_NOTICE(( "Using --random-iterations %lu", rand_iters ));

  test_mainnet( block_file, exec_tiles, 20UL, 0UL, 1 );

  ulong depth       = 100UL;
  ulong block_depth = 10UL;
  FD_TEST( fd_rdisp_footprint( depth, block_depth )<=TEST_FOOTPRINT && fd_rdisp_align()<=128UL ); /* if this fails, update the test */

  fd_rdisp_staging_lane_info_t lane_info[ 4 ];

  fd_rdisp_t * disp = fd_rdisp_join( fd_rdisp_new( footprint, depth, block_depth, SEED ) );   FD_TEST( disp );

  /* operations on an unknown block fail */
  FD_TEST( -1==fd_rdisp_remove_block( disp, tag( 1UL ) ) );
  FD_TEST( 0UL==add_txn( disp, rng, tag( 1UL ), "ABC", "DEF", 0 ) );
  FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );

  FD_TEST( 0x0UL==fd_rdisp_staging_lane_info( disp, lane_info ) ); /* all free */

  FD_TEST( 0==fd_rdisp_add_block( disp, tag( 0UL ), 0 ) );
  FD_TEST( 0x1UL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST( -1==fd_rdisp_add_block( disp, tag( 0UL ), 0                 ) ); /* can't add again */
  FD_TEST( -1==fd_rdisp_add_block( disp, tag( 0UL ), FD_RDISP_UNSTAGED ) ); /* can't add again */

  FD_TEST(  0==fd_rdisp_add_block( disp, tag( 1UL ), FD_RDISP_UNSTAGED ) );
  FD_TEST( 0x1UL==fd_rdisp_staging_lane_info( disp, lane_info ) );

  FD_TEST(  0==fd_rdisp_add_block( disp, tag( 2UL ), 2 ) );
  FD_TEST( 0x5UL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 2UL ) ) );
  FD_TEST( 0x1UL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST(  0==fd_rdisp_add_block( disp, tag( 6UL ), 2 ) );
  FD_TEST( 0x5UL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST(  0==fd_rdisp_add_block( disp, tag( 2UL ), 2 ) );
  FD_TEST( 0x5UL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST( tag_eq( lane_info[ 0 ].schedule_ready_block, 0UL ) );
  FD_TEST( tag_eq( lane_info[ 0 ].insert_ready_block,   0UL ) );
  FD_TEST( tag_eq( lane_info[ 2 ].schedule_ready_block, 6UL ) );
  FD_TEST( tag_eq( lane_info[ 2 ].insert_ready_block,   2UL ) );
  FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 6UL ) ) );
  FD_TEST( 0x5UL==fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST( tag_eq( lane_info[ 2 ].schedule_ready_block, 2UL ) );

  ulong t0[3];
  ulong t1[3];
  ulong t2[3];
  ulong t3[3];
  /* 3 transactions that have to go in order */
  FD_TEST( 0UL!=(t1[0]=add_txn( disp, rng, tag( 1UL ), "ABC", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[1]=add_txn( disp, rng, tag( 1UL ), "A",   "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[2]=add_txn( disp, rng, tag( 1UL ), "AF",  "DE",  0 )) );
  fd_rdisp_verify( disp, verify_scratch );

  FD_TEST( t1[0]==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );   fd_rdisp_complete_txn( disp, t1[0] );
  FD_TEST( t1[1]==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );   fd_rdisp_complete_txn( disp, t1[1] );
  FD_TEST( t1[2]==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );   fd_rdisp_complete_txn( disp, t1[2] );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) ); /* empty */
  fd_rdisp_verify( disp, verify_scratch );

  /* 3 transactions that can go in any order */
  FD_TEST( 0UL!=(t1[0]=add_txn( disp, rng, tag( 1UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[1]=add_txn( disp, rng, tag( 1UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[2]=add_txn( disp, rng, tag( 1UL ), "C", "DE",  0 )) );
  fd_rdisp_verify( disp, verify_scratch );

  ulong last;
  last = fd_rdisp_get_next_ready( disp, tag( 1UL ) ); FD_TEST( pop_option( t1, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 1UL ) ); FD_TEST( pop_option( t1, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 1UL ) ); FD_TEST( pop_option( t1, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) ); /* empty */
  fd_rdisp_verify( disp, verify_scratch );

  FD_TEST( 0UL!=(t0[0]=add_txn( disp, rng, tag( 0UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t0[1]=add_txn( disp, rng, tag( 0UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t0[2]=add_txn( disp, rng, tag( 0UL ), "C", "DE",  0 )) );
  fd_rdisp_verify( disp, verify_scratch );

  FD_TEST( 0UL!=(t1[0]=add_txn( disp, rng, tag( 1UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[1]=add_txn( disp, rng, tag( 1UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t1[2]=add_txn( disp, rng, tag( 1UL ), "C", "DE",  0 )) );
  fd_rdisp_verify( disp, verify_scratch );

  FD_TEST( 0==fd_rdisp_promote_block( disp, tag( 1UL ), 0 ) );

  last = fd_rdisp_get_next_ready( disp, tag( 0UL ) ); FD_TEST( pop_option( t0, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 0UL ) ); FD_TEST( pop_option( t0, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 0UL ) ); FD_TEST( pop_option( t0, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 0UL ) ) ); /* empty */

  FD_TEST( 0==fd_rdisp_add_block( disp, tag( 3UL ), 0 ) );
  FD_TEST( 0UL!=(t3[0]=add_txn( disp, rng, tag( 3UL ), "A", "DEF", 0 )) );
  FD_TEST( 0UL!=(t3[1]=add_txn( disp, rng, tag( 3UL ), "B", "DEF", 0 )) );
  FD_TEST( 0UL!=(t3[2]=add_txn( disp, rng, tag( 3UL ), "C", "DE",  0 )) );

  FD_TEST(  0==fd_rdisp_remove_block ( disp, tag( 0UL ) ) );
  FD_TEST( -1==fd_rdisp_abandon_block( disp, tag( 0UL ) ) );
  FD_TEST(  0==fd_rdisp_abandon_block( disp, tag( 1UL ) ) );

  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 0UL ) ) );
  FD_TEST( 0UL  ==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) );

  last = fd_rdisp_get_next_ready( disp, tag( 3UL ) ); FD_TEST( pop_option( t3, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 3UL ) ); FD_TEST( pop_option( t3, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 3UL ) ); FD_TEST( pop_option( t3, 3UL, last ) ); fd_rdisp_complete_txn( disp, last );

  FD_TEST( 0UL!=(t2[0]=add_txn( disp, rng, tag( 2UL ), "ABC", "DEF", 0 )) );
  FD_TEST( 0UL!=(t2[1]=add_txn( disp, rng, tag( 2UL ), "A",   "DEF", 0 )) );
  FD_TEST( 0UL!=(t2[2]=add_txn( disp, rng, tag( 2UL ), "AF",  "DE",  0 )) );
  FD_TEST( t2[0]==fd_rdisp_get_next_ready( disp, tag( 2UL ) ) );   fd_rdisp_complete_txn( disp, t2[0] );
  FD_TEST( t2[1]==fd_rdisp_get_next_ready( disp, tag( 2UL ) ) );   fd_rdisp_complete_txn( disp, t2[1] );
  FD_TEST( t2[2]==fd_rdisp_get_next_ready( disp, tag( 2UL ) ) );   fd_rdisp_complete_txn( disp, t2[2] );

  /* Now it is possible to demote */
  FD_TEST(   (1UL<<2) & fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST( 0==fd_rdisp_demote_block( disp, tag( 2UL ) ) );
  FD_TEST( !((1UL<<2) & fd_rdisp_staging_lane_info( disp, lane_info )) );

  FD_TEST( 0UL!=(t2[0]=add_txn( disp, rng, tag( 2UL ), "ABC", "DEF", 0 )) );
  FD_TEST( 0UL!=(t2[1]=add_txn( disp, rng, tag( 2UL ), "A",   "DEF", 0 )) );
  FD_TEST( 0UL!=(t2[2]=add_txn( disp, rng, tag( 2UL ), "AF",  "DE",  0 )) );

  FD_TEST( !((1UL<<2) & fd_rdisp_staging_lane_info( disp, lane_info )) );
  FD_TEST( 0==fd_rdisp_promote_block( disp, tag( 2UL ), 3UL ) );
  FD_TEST(   (1UL<<3) & fd_rdisp_staging_lane_info( disp, lane_info ) );
  FD_TEST( t2[0]==fd_rdisp_get_next_ready( disp, tag( 2UL ) ) );   fd_rdisp_complete_txn( disp, t2[0] );
  FD_TEST( t2[1]==fd_rdisp_get_next_ready( disp, tag( 2UL ) ) );   fd_rdisp_complete_txn( disp, t2[1] );
  FD_TEST( t2[2]==fd_rdisp_get_next_ready( disp, tag( 2UL ) ) );   fd_rdisp_complete_txn( disp, t2[2] );

  FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 2UL ) ) );

  ulong t4[5];
  FD_TEST( 0==fd_rdisp_add_block( disp, tag( 4UL ), 1UL ) );

  /* Test serializing */
  FD_TEST( 0UL!=(t4[0]=add_txn( disp, rng, tag( 4UL ), "A", "J", 0 )) );
  FD_TEST( 0UL!=(t4[1]=add_txn( disp, rng, tag( 4UL ), "B", "J", 0 )) );
  FD_TEST( 0UL!=(t4[2]=add_txn( disp, rng, tag( 4UL ), "C", "J", 1 )) );
  FD_TEST( 0UL!=(t4[3]=add_txn( disp, rng, tag( 4UL ), "D", "J", 0 )) );
  FD_TEST( 0UL!=(t4[4]=add_txn( disp, rng, tag( 4UL ), "E", "J", 0 )) );

  last = fd_rdisp_get_next_ready( disp, tag( 4UL ) ); FD_TEST( pop_option( t4,     2UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 4UL ) ); FD_TEST( pop_option( t4,     2UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 4UL ) ); FD_TEST( last==t4[2]                     ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 4UL ) ); FD_TEST( pop_option( t4+3UL, 2UL, last ) ); fd_rdisp_complete_txn( disp, last );
  last = fd_rdisp_get_next_ready( disp, tag( 4UL ) ); FD_TEST( pop_option( t4+3UL, 2UL, last ) ); fd_rdisp_complete_txn( disp, last );
  FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 4UL ) ) );

  /* Tests that only apply for the non-simple dispatcher */
  if( 1 ) {
    FD_TEST( 0==fd_rdisp_add_block( disp, tag( 4UL ), 1UL ) );

    ulong txnf;
    FD_TEST( 0UL!=(txnf =add_txn( disp, rng, tag( 4UL ), "J", "F", 0 )) );
    /* All independent */
    FD_TEST( 0UL!=(t4[0]=add_txn( disp, rng, tag( 4UL ), "A", "J", 0 )) );
    FD_TEST( 0UL!=(t4[1]=add_txn( disp, rng, tag( 4UL ), "B", "J", 0 )) );
    FD_TEST( 0UL!=(t4[2]=add_txn( disp, rng, tag( 4UL ), "C", "J", 0 )) );
    FD_TEST( 0UL!=(t4[3]=add_txn( disp, rng, tag( 4UL ), "D", "J", 0 )) );
    FD_TEST( 0UL!=(t4[4]=add_txn( disp, rng, tag( 4UL ), "E", "J", 0 )) );
    ulong txnl;
    FD_TEST( txnf==fd_rdisp_get_next_ready( disp, tag( 4UL ) ) );   fd_rdisp_complete_txn( disp, txnf );

    for( ulong i=0UL; i<5UL; i++ ) { last = fd_rdisp_get_next_ready( disp, tag( 4UL ) ); FD_TEST( pop_option( t4, 5UL, last ) ); }
    fd_rdisp_complete_txn( disp, t4[4]&0xFFFFUL );  FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 4UL ) ) );
    fd_rdisp_complete_txn( disp, t4[0]&0xFFFFUL );  FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 4UL ) ) );
    FD_TEST( 0UL!=(txnl =add_txn( disp, rng, tag( 4UL ), "J", "F", 0 )) );
    fd_rdisp_complete_txn( disp, t4[3]&0xFFFFUL );  FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 4UL ) ) );
    fd_rdisp_complete_txn( disp, t4[1]&0xFFFFUL );  FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 4UL ) ) );
    fd_rdisp_complete_txn( disp, t4[2]&0xFFFFUL );

    FD_TEST( txnl==fd_rdisp_get_next_ready( disp, tag( 4UL ) ) );
    fd_rdisp_complete_txn( disp, txnl );

    FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 4UL ) ) );


    /* Test that it respects block boundaries */
    FD_TEST( 0==fd_rdisp_add_block( disp, tag( 0UL ), 1UL ) );

    FD_TEST( 0UL!=(t0[0]=add_txn( disp, rng, tag( 0UL ), "A", "J", 0 )) );
    FD_TEST( 0UL!=(t0[1]=add_txn( disp, rng, tag( 0UL ), "B", "J", 0 )) );
    FD_TEST( 0UL!=(t0[2]=add_txn( disp, rng, tag( 0UL ), "C", "J", 0 )) );

    FD_TEST( 0==fd_rdisp_add_block( disp, tag( 1UL ), 1UL ) );

    FD_TEST( 0UL!=(t1[0]=add_txn( disp, rng, tag( 1UL ), "D", "J", 0 )) );
    FD_TEST( 0UL!=(t1[1]=add_txn( disp, rng, tag( 1UL ), "E", "J", 0 )) );
    FD_TEST( 0UL!=(t1[2]=add_txn( disp, rng, tag( 1UL ), "F", "J", 0 )) );

    FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) ); /* not schedule-ready */
    for( ulong i=0UL; i<3UL; i++ ) { last = fd_rdisp_get_next_ready( disp, tag( 0UL ) ); FD_TEST( pop_option( t0, 3UL, last ) ); }
    FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 0UL ) ) ); /* empty */
    FD_TEST( 0UL==fd_rdisp_get_next_ready( disp, tag( 1UL ) ) ); /* not schedule-ready */
    for( ulong i=0UL; i<3UL; i++ ) fd_rdisp_complete_txn( disp, t0[i]&0xFFFFUL );
    FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 0UL ) ) );

    /* Now block 1 is schedule-ready */
    for( ulong i=0UL; i<3UL; i++ ) { last = fd_rdisp_get_next_ready( disp, tag( 1UL ) ); FD_TEST( pop_option( t1, 3UL, last ) ); }
    for( ulong i=0UL; i<3UL; i++ ) fd_rdisp_complete_txn( disp, t1[i]&0xFFFFUL );
    FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 1UL ) ) );
  }

  /* Thrash the account map */
  FD_TEST( 0==fd_rdisp_add_block( disp, tag( 0UL ), 1UL ) );
  ushort accts[38];
  ulong txn_idxs[100];
  ulong txn_cnt=0UL;
  for( ulong iter=0UL; iter<USHORT_MAX/38UL; iter++ ) {
    for( ulong j=0UL; j<38UL; j++ ) accts[j] = (ushort)(38UL*iter + j);
    ulong txn_idx = add_txn2( disp, rng, tag( 0UL ), accts, 38UL );
    FD_TEST( txn_idx==fd_rdisp_get_next_ready( disp, tag( 0UL ) ) );
    txn_idxs[txn_cnt++] = txn_idx;
    if( FD_UNLIKELY( txn_cnt==100UL ) ) while( txn_cnt ) fd_rdisp_complete_txn( disp, txn_idxs[--txn_cnt] );
  }
  while( txn_cnt ) fd_rdisp_complete_txn( disp, txn_idxs[--txn_cnt] );
  FD_TEST(  0==fd_rdisp_remove_block( disp, tag( 0UL ) ) );

  fd_rdisp_delete( fd_rdisp_leave( disp ) );


  FD_TEST( fd_rdisp_footprint( FD_RDISP_MAX_BLOCK_DEPTH, FD_RDISP_MAX_BLOCK_DEPTH )<=TEST_FOOTPRINT && fd_rdisp_align()<=128UL ); /* if this fails, update the test */

  disp = fd_rdisp_join( fd_rdisp_new( footprint, FD_RDISP_MAX_BLOCK_DEPTH, FD_RDISP_MAX_BLOCK_DEPTH, SEED ) );
  FD_TEST( disp );
  /* Fill block_depth, (remove one, add one) a bunch, then drain*/
  ulong txn_idx[ FD_RDISP_MAX_BLOCK_DEPTH*2UL ];
  for( ulong block=0UL; block<3UL*FD_RDISP_MAX_BLOCK_DEPTH; block++ ) {
    if( block>=FD_RDISP_MAX_BLOCK_DEPTH ) {
      ulong ablock = block-FD_RDISP_MAX_BLOCK_DEPTH;
      FD_TEST( txn_idx[ablock]==fd_rdisp_get_next_ready( disp, tag( ablock ) ) );
      fd_rdisp_complete_txn( disp, txn_idx[ablock] );
      FD_TEST( 0==fd_rdisp_remove_block( disp, tag( ablock ) ) );
    }
    if( block<2UL*FD_RDISP_MAX_BLOCK_DEPTH ) {
      FD_TEST( 0==fd_rdisp_add_block( disp, tag( block ), 0UL ) );
      txn_idx[block] = add_txn( disp, rng, tag( block ), "", "A", 0 );
      FD_TEST( txn_idx[block] );
    }
  }

  fd_rdisp_delete( fd_rdisp_leave( disp ) );

  random_test( rng, rand_iters );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
