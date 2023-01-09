#include "../fd_ballet.h"
#include "../../tango/dcache/fd_dcache.h"
#include "fd_compute_budget_program.h" /* FIXME: This should probably not be included */
#include "fd_pack.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#include <stdio.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
# define SHIFT(n) argv+=(n),argc-=(n)

  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "no arguments" ));
  char const * bin = argv[0];
  SHIFT(1);

  /* FIXME: CACHE ATTACHEMENTS? */

  int cnt = 0;
  while( argc ) {
    char const * cmd = argv[0];
    SHIFT(1);

    if( !strcmp( cmd, "help" ) ) {

      FD_LOG_NOTICE(( "\n\t"
        "Usage: %s [cmd] [cmd args] [cmd] [cmd args] ...\n\t"
        "Commands are:\n\t"
        "\n\t"
        "\thelp\n\t"
        "\t- Prints this message\n\t"
        "\n\t"
        "\tnew wksp-name dcache-addr bank-cnt txnq-sz cu-est-tbl-sz\n\t"
        "\t- Creates in wksp-name the data structures needed for a pack tile that schedules\n\t"
        "\t  transactions to bank-cnt banking threads, has a transaction priority\n\t"
        "\t  queue large enough to store txnq-sz pending transactions, outputs \n\t"
        "\t  transactions to the dcache stored at dcache-addr, and uses a\n\t"
        "\t  compute unit estimation table of size cu-est-tbl-sz.  cu-est-tbl-sz\n\t"
        "\t  must be a power of 2.  Prints the address of the region of memory\n\t"
        "\t  containing all the data structures.\n\t"
        "\n\t"
        "\tdelete pod-gaddr\n\t"
        "\t- Destroys the data structures that new created.\n\t"
        "\n\t"
        "\tload-cu subpod-gaddr cu-est-file reset\n\t"
        "\t- Loads the compute unit estimation information in cu-est-file into\n\t"
        "\t  the table located using the data, bank-cnt, txnq-sz, cu-est-tbl-sz keys\n\t"
        "\t  from subpod-gaddr.  If reset is non-zero, it resets the table before loading.\n\t"
        "\n\t"
        "", bin ));
      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "new" ) ) {

      if( FD_UNLIKELY( argc<5 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * wksp_name     =                   argv[0];
      char const * dcache_addr   =                   argv[1];
      ulong        bank_cnt      = fd_cstr_to_ulong( argv[2] );
      ulong        txnq_sz       = fd_cstr_to_ulong( argv[3] );
      ulong        cu_est_tbl_sz = fd_cstr_to_ulong( argv[4] );

      fd_wksp_t   * wksp = fd_wksp_attach( wksp_name );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_attach( \"%s\" ) failed\n\tDo %s help for help",
              cnt, cmd, wksp_name, bin ));
      }
      void * _dcache = fd_wksp_map( dcache_addr );
      if( FD_UNLIKELY( !_dcache ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help",
              cnt, cmd, dcache_addr, bin ));
      }


      ulong dcache_data_sz = fd_dcache_req_data_sz( sizeof(fd_txn_p_t), txnq_sz, 1UL, 1 );
      int        lg_tbl_sz = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*FD_TXN_ACCT_ADDR_MAX*bank_cnt ) );
      /* We need for the freelist always to have at least txnq_sz free elements.
         Since each chunk is in exactly one of:
       * freelist
       * txnq (at most txnq_sz)
       * outq (at most 1 per bank thread)
       Then we should initialize freelist with 2*txnq_sz+bank_cnt elements. */
      ulong freelist_sz = 2UL*txnq_sz+bank_cnt;


      fd_pack_bank_status_t *   bank_status;
      fd_pack_orderable_txn_t * last_scheduled;
      ulong *                   freelist;
      uchar *                   dcache;

      void * outq_shmem;
      void * txnq_shmem;
      void * r_accts_iu_shmem;
      void * w_accts_iu_shmem;
      void * cu_est_tbl_shmem;
      void * freelist_shmem;


      ulong scratch_top = 0UL;
#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))
      /* Measure space needed */
      SCRATCH_ALLOC( alignof(fd_pack_bank_status_t),    bank_cnt*sizeof(fd_pack_bank_status_t)     );
      SCRATCH_ALLOC( alignof(fd_pack_orderable_txn_t),  bank_cnt*sizeof(fd_pack_orderable_txn_t)   );
      SCRATCH_ALLOC( outq_align(),                      outq_footprint( bank_cnt )                 );
      SCRATCH_ALLOC( txnq_align( ),                     txnq_footprint( txnq_sz )                  );
      SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
      SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
      SCRATCH_ALLOC( fd_est_tbl_align( ),               fd_est_tbl_footprint( cu_est_tbl_sz )      );
      SCRATCH_ALLOC( freelist_align( ),                 freelist_footprint( freelist_sz)           );

      /* Allocate the chunk of memory */
      ulong gaddr = fd_wksp_alloc( wksp, 128UL, scratch_top, 0x9ACC711EUL ); /* PACC TILE */
      if( FD_UNLIKELY( !gaddr ) ) {
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_alloc( \"%s\", %lu, %lu ) failed\n\tDo %s help for help",
              cnt, cmd, wksp_name, 128UL, scratch_top, bin ));
      }
      void * shmem = fd_wksp_laddr( wksp, gaddr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i: %s: fd_wksp_laddr( \"%s\", %lu ) failed\n\tDo %s help for help",
              cnt, cmd, wksp_name, gaddr, bin ));
      }

      /* Get pointers to each individual object */
      scratch_top = (ulong)shmem;
      bank_status      = SCRATCH_ALLOC( alignof(fd_pack_bank_status_t),    bank_cnt*sizeof(fd_pack_bank_status_t)     );
      last_scheduled   = SCRATCH_ALLOC( alignof(fd_pack_orderable_txn_t),  bank_cnt*sizeof(fd_pack_orderable_txn_t)   );
      outq_shmem       = SCRATCH_ALLOC( outq_align(),                      outq_footprint( bank_cnt )                 );
      txnq_shmem       = SCRATCH_ALLOC( txnq_align( ),                     txnq_footprint( txnq_sz )                  );
      r_accts_iu_shmem = SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
      w_accts_iu_shmem = SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
      cu_est_tbl_shmem = SCRATCH_ALLOC( fd_est_tbl_align( ),               fd_est_tbl_footprint( cu_est_tbl_sz )      );
      freelist_shmem   = SCRATCH_ALLOC( freelist_align( ),                 freelist_footprint( freelist_sz )          );

      /* Initialize everything */
      fd_memset( bank_status,    0, bank_cnt*sizeof(fd_pack_bank_status_t)   );
      fd_memset( last_scheduled, 0, bank_cnt*sizeof(fd_pack_orderable_txn_t) );

      outq_shmem       = outq_new(       outq_shmem,       bank_cnt            );
      txnq_shmem       = txnq_new(       txnq_shmem,       txnq_sz             );
      r_accts_iu_shmem = acct_uses_new(  r_accts_iu_shmem, lg_tbl_sz           );
      w_accts_iu_shmem = acct_uses_new(  w_accts_iu_shmem, lg_tbl_sz           );
      cu_est_tbl_shmem = fd_est_tbl_new( cu_est_tbl_shmem, cu_est_tbl_sz, 1000UL, FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT );
      freelist_shmem   = freelist_new(   freelist_shmem,   freelist_sz         );

      /* Init free list */
      dcache              = fd_dcache_join( _dcache );
      freelist            = freelist_join( freelist_shmem );
      void  * dcache_base = wksp;
      if( fd_dcache_data_sz( dcache ) < dcache_data_sz ) {
        freelist_leave( freelist );
        fd_wksp_unmap( fd_dcache_leave( dcache  ) );
        fd_wksp_free( wksp, gaddr );
        fd_wksp_detach( wksp );
        FD_LOG_ERR(( "%i %s: dcache at %s was not large enough.  Data region must be at least %lu bytes.",
              cnt, cmd, dcache_addr, dcache_data_sz ));
      }
      ulong   chunk0      = fd_dcache_compact_chunk0( dcache_base, dcache );
      ulong   wmark       = fd_dcache_compact_wmark ( dcache_base, dcache, sizeof(fd_txn_p_t) );
      ulong   chunk       = chunk0;
      for( ulong i=0UL; i<2UL*txnq_sz+bank_cnt; i++ ) {
        freelist_push_tail( freelist, chunk );
        chunk = fd_dcache_compact_next( chunk, sizeof(fd_txn_p_t), chunk0, wmark );
      }
      freelist_leave( freelist );
      fd_wksp_unmap( fd_dcache_leave( dcache  ) );


      char buf[ FD_WKSP_CSTR_MAX ];
      printf( "%s\n", fd_wksp_cstr( wksp, gaddr, buf ) );

      fd_wksp_detach( wksp );

      FD_LOG_NOTICE(( "%i: %s %s %s %lu %lu %lu: success", cnt, cmd, wksp_name, dcache_addr, bank_cnt, txnq_sz, cu_est_tbl_sz ));
      SHIFT( 5 );

    } else if( !strcmp( cmd, "load-cu" ) ) {
      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * subpod_gaddr  =                   argv[0];
      char const * file_path     =                   argv[1];
      ulong        reset         = fd_cstr_to_ulong( argv[2] );

      FILE * f = fopen( file_path, "r" );
      if( FD_UNLIKELY( !f ) ) {
        FD_LOG_ERR(( "%i: %s: fopen( \"%s\", \"r\" ) failed\n\tDo %s help for help",
              cnt, cmd, file_path, bin ));
      }

      uchar const * subpod = fd_wksp_pod_attach( subpod_gaddr );
      if( FD_UNLIKELY( !subpod ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_pod_attach( \"%s\" ) failed\n\tDo %s help for help",
              cnt, cmd, subpod_gaddr, bin ));
      }


      ulong        bank_cnt      = fd_pod_query_ulong( subpod, "bank-cnt",      0UL  );
      ulong        txnq_sz       = fd_pod_query_ulong( subpod, "txnq-sz",       0UL  );
      ulong        cu_est_tbl_sz = fd_pod_query_ulong( subpod, "cu-est-tbl-sz", 0UL  );

      if( FD_UNLIKELY( !bank_cnt ) ) {
        fd_wksp_pod_detach( subpod );
        FD_LOG_ERR(( "%i: %s: fd_pod_query_ulong( \"%s\", \"bank-cnt\", 0 ) failed\n\tDo %s help for help",
              cnt, cmd, subpod_gaddr, bin ));
      }
      if( FD_UNLIKELY( !txnq_sz ) ) {
        fd_wksp_pod_detach( subpod );
        FD_LOG_ERR(( "%i: %s: fd_pod_query_ulong( \"%s\", \"txnq-sz\", 0 ) failed\n\tDo %s help for help",
              cnt, cmd, subpod_gaddr, bin ));
      }
      if( FD_UNLIKELY( !cu_est_tbl_sz ) ) {
        fd_wksp_pod_detach( subpod );
        FD_LOG_ERR(( "%i: %s: fd_pod_query_ulong( \"%s\", \"cu-est-tbl-sz\", 0 ) failed\n\tDo %s help for help",
              cnt, cmd, subpod_gaddr, bin ));
      }
      char * data = fd_wksp_pod_map(  subpod, "data" ); /* Terminates on failure */

      int   lg_tbl_sz   = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*FD_TXN_ACCT_ADDR_MAX*bank_cnt ) );
      ulong freelist_sz = 2UL*txnq_sz+bank_cnt;

      void * cu_est_tbl_shmem;
      ulong scratch_top = (ulong) data;
      /* */              SCRATCH_ALLOC( alignof(fd_pack_bank_status_t),    bank_cnt*sizeof(fd_pack_bank_status_t)     );
      /* */              SCRATCH_ALLOC( alignof(fd_pack_orderable_txn_t),  bank_cnt*sizeof(fd_pack_orderable_txn_t)   );
      /* */              SCRATCH_ALLOC( outq_align(),                      outq_footprint( bank_cnt )                 );
      /* */              SCRATCH_ALLOC( txnq_align( ),                     txnq_footprint( txnq_sz )                  );
      /* */              SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
      /* */              SCRATCH_ALLOC( acct_uses_align( ),                acct_uses_footprint( lg_tbl_sz )           );
      cu_est_tbl_shmem = SCRATCH_ALLOC( fd_est_tbl_align( ),               fd_est_tbl_footprint( cu_est_tbl_sz )      );
      /* */              SCRATCH_ALLOC( freelist_align( ),                 freelist_footprint( freelist_sz )          );

      if( reset )
        cu_est_tbl_shmem = fd_est_tbl_new( cu_est_tbl_shmem, cu_est_tbl_sz, 1000UL, FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT );

      fd_est_tbl_t * cu_est_tbl = fd_est_tbl_join( cu_est_tbl_shmem );

      struct {
        uchar  signature[ FD_TXN_SIGNATURE_SZ ];
        uchar  txn_failed;
        uchar  instr_idx;
        ushort data_len;
        int    instr_cost;
        uchar  prog_id[ FD_TXN_ACCT_ADDR_SZ ];
        uchar  instr_data[ 16UL ];
      } record;
      FD_STATIC_ASSERT( sizeof(record) == 120UL, "record_packing" );
      ulong read  = 0UL;
      ulong added = 0UL;
      while( fread( &record, 120UL, 1UL, f ) ) {
        read++;
        if( record.instr_cost < 0 ) continue; /* Transaction failed, etc. */

        ulong word1 = *(ulong*)record.prog_id;
        ulong word2 = (*(ulong*)(record.prog_id + sizeof(ulong))) & 0xFFFFFFFFFFFFFF00UL;
        /* Set last byte of word2 to first byte of instruction data (or 0 if there's no instruction data). */
        if( FD_LIKELY( record.data_len ) ) word2 ^= (ulong) record.instr_data[ 0UL ];
        ulong hash = (fd_ulong_hash( word1 ) ^ fd_ulong_hash( word2 ));

        fd_est_tbl_update( cu_est_tbl, hash, (uint) record.instr_cost );
        added++;
      }
      FD_LOG_NOTICE(( "%i: %s: Read %lu records, added %lu records.", cnt, cmd, read, added ));

      fclose( f );
      fd_est_tbl_leave( cu_est_tbl );
      fd_wksp_pod_unmap( data );
      fd_wksp_pod_detach( subpod );

      SHIFT( 3 );
#undef SCRATCH_ALLOC
    } else {

      FD_LOG_ERR(( "%i: %s: unknown command\n\t"
                   "Do %s help for help", cnt, cmd, bin ));

    }
    cnt++;
  }

  FD_LOG_NOTICE(( "processed %i commands", cnt ));

# undef SHIFT
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "No arguments" ));
  if( FD_UNLIKELY( argc>1 ) ) FD_LOG_ERR(( "fd_pack_ctl not supported on this platform" ));
  FD_LOG_NOTICE(( "processed 0 commands" ));
  fd_halt();
  return 0;
}

#endif

