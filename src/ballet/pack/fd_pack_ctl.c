#include "../fd_ballet.h"
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
        "\tnew-scratch wksp-name bank-cnt txnq-sz\n\t"
        "\t- Creates in wksp-name a scratch space for a pack tile that schedules\n\t"
        "\t  transactions to bank-cnt banking threads, has a transaction priority\n\t"
        "\t  queue large enough to store txnq-sz pending transactions.  bank-cnt must\n\t"
        "\t  be less than 256.  Prints the address of the resulting region of memory.\n\t"
        "\n\t"
        "\tnew-cu-est-tbl wksp-name cu-est-tbl-sz history default\n\t"
        "\t- Creates in wksp-name an empty compute unit estimation table of size cu-est-tbl-sz.\n\t"
        "\t  cu-est-tbl-sz must be a power of 2.  The table uses a decay based on history \n\t"
        "\t  (a larger value results in slower decay) and uses a default value of default\n\t."
        "\t  Prints the address of the resulting table.\n\t"
        "\n\t"
        "\tload-cu table-gaddr cu-est-file\n\t"
        "\t- Loads the compute unit estimation information in cu-est-file into\n\t"
        "\t  the table located at table-gaddr (the value printed by a new-cu-est-tbl\n\t"
        "\t  invocation).  Adds the new data to the existing data in the table.\n\t"
        "\t  To start from scratch, delete and recreate the table.\n\t"
        "\n\t"
        "\tdelete-cu-est-tbl table-gaddr\n\t"
        "\t- Destroys the compute unit estimation table and frees the associated memory.\n\t"
        "\n\t"
        "", bin ));
      FD_LOG_NOTICE(( "%i: %s: success", cnt, cmd ));

    } else if( !strcmp( cmd, "new-scratch" ) ) {

      if( FD_UNLIKELY( argc<3 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * wksp_name     =                   argv[0];
      ulong        bank_cnt      = fd_cstr_to_ulong( argv[1] );
      ulong        txnq_sz       = fd_cstr_to_ulong( argv[2] );


      ulong footprint = fd_pack_footprint( bank_cnt, txnq_sz );
      if( FD_UNLIKELY( !footprint ) ) {
        FD_LOG_ERR(( "%i: %s: fd_pack_footprint( %lu, %lu ) failed\n\tDo %s help for help",
              cnt, cmd, bank_cnt, txnq_sz, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      char * cstr_addr = fd_wksp_cstr_alloc( wksp_name, fd_pack_align(), footprint, 0, buf );
      if( FD_UNLIKELY( !cstr_addr ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_cstr_alloc( \"%s\", %lu, %lu ) failed\n\tDo %s help for help",
              cnt, cmd, wksp_name, bank_cnt, txnq_sz, bin ));
      printf( "%s\n", cstr_addr );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu: success", cnt, cmd, wksp_name, bank_cnt, txnq_sz ));
      SHIFT( 3 );
    } else if( !strcmp( cmd, "new-cu-est-tbl" ) ) {

      if( FD_UNLIKELY( argc<4 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * wksp_name     =                   argv[0];
      ulong        cu_est_tbl_sz = fd_cstr_to_ulong( argv[1] );
      ulong        history       = fd_cstr_to_ulong( argv[2] );
      uint         default_val   = fd_cstr_to_uint ( argv[3] );

      ulong footprint = fd_est_tbl_footprint( cu_est_tbl_sz );
      if( FD_UNLIKELY( !footprint ) ) {
        FD_LOG_ERR(( "%i: %s: fd_est_tbl_footprint( %lu ) failed\n\tDo %s help for help",
              cnt, cmd, cu_est_tbl_sz, bin ));
      }

      char buf[ FD_WKSP_CSTR_MAX ];
      char * cstr_addr = fd_wksp_cstr_alloc( wksp_name, fd_pack_align(), footprint, 0, buf );
      if( FD_UNLIKELY( !cstr_addr ) )
        FD_LOG_ERR(( "%i: %s: fd_wksp_cstr_alloc( \"%s\", %lu, %lu ) failed\n\tDo %s help for help",
              cnt, cmd, wksp_name, fd_pack_align(), footprint, bin ));


      void * shmem = fd_wksp_map( cstr_addr );
      if( FD_UNLIKELY( !shmem ) ) {
        fd_wksp_cstr_free( cstr_addr );
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help",
              cnt, cmd, cstr_addr, bin ));
      }
      if( FD_UNLIKELY( !fd_est_tbl_new( shmem, cu_est_tbl_sz, history, default_val ) ) ) {
        fd_wksp_cstr_free( cstr_addr );
        FD_LOG_ERR(( "%i: %s: fd_est_tbl_new( \"%s\", %lu, %lu, %u ) failed\n\tDo %s help for help",
              cnt, cmd, cstr_addr, cu_est_tbl_sz, history, default_val, bin ));
      }

      printf( "%s\n", cstr_addr );

      FD_LOG_NOTICE(( "%i: %s %s %lu %lu %u: success", cnt, cmd, wksp_name, cu_est_tbl_sz, history, default_val ));
      SHIFT( 4 );


    } else if( !strcmp( cmd, "load-cu" ) ) {
      if( FD_UNLIKELY( argc<2 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * table_gaddr   =                   argv[0];
      char const * file_path     =                   argv[1];

      FILE * f = fopen( file_path, "r" );
      if( FD_UNLIKELY( !f ) ) {
        FD_LOG_ERR(( "%i: %s: fopen( \"%s\", \"r\" ) failed\n\tDo %s help for help",
              cnt, cmd, file_path, bin ));
      }

      void * cu_est_tbl_shmem = fd_wksp_map( table_gaddr );
      if( FD_UNLIKELY( !cu_est_tbl_shmem ) ) {
        fclose( f );
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help",
              cnt, cmd, table_gaddr, bin ));
      }

      fd_est_tbl_t * cu_est_tbl = fd_est_tbl_join( cu_est_tbl_shmem );
      if( FD_UNLIKELY( !cu_est_tbl ) ) {
        fd_wksp_unmap( cu_est_tbl_shmem );
        fclose( f );
        FD_LOG_ERR(( "%i: %s: fd_est_tbl_join( \"%s\" ) failed\n\tDo %s help for help",
              cnt, cmd, table_gaddr, bin ));
      }

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

      fd_est_tbl_leave( cu_est_tbl );
      fd_wksp_unmap( cu_est_tbl_shmem );
      fclose( f );

      FD_LOG_NOTICE(( "%i: %s %s %s: success", cnt, cmd, table_gaddr, file_path ));
      SHIFT( 2 );
    } else if( !strcmp( cmd, "delete-cu-est-tbl" ) ) {
      if( FD_UNLIKELY( argc<1 ) ) FD_LOG_ERR(( "%i: %s: too few arguments\n\tDo %s help for help", cnt, cmd, bin ));

      char const * table_gaddr   =                   argv[0];

      void * cu_est_tbl_shmem = fd_wksp_map( table_gaddr );
      if( FD_UNLIKELY( !cu_est_tbl_shmem ) ) {
        FD_LOG_ERR(( "%i: %s: fd_wksp_map( \"%s\" ) failed\n\tDo %s help for help",
              cnt, cmd, table_gaddr, bin ));
      }
      fd_est_tbl_delete( cu_est_tbl_shmem );

      fd_wksp_unmap( cu_est_tbl_shmem );

      fd_wksp_cstr_free( table_gaddr );

      SHIFT( 1 );
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

