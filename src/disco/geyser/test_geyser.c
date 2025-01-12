#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include "fd_geyser.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/base64/fd_base64.h"

static void
my_execute_fun(fd_replay_notif_msg_t const * msg, void * arg) {
  (void)arg;
  char bank_hash[50];
  fd_base58_encode_32(msg->slot_exec.bank_hash.uc, 0, bank_hash);
  printf( "\"execute\":{\"parent\":%lu,\"smr\":%lu,\"slot\":%lu,\"bank_hash\":\"%s\",\"transactions\":%lu}\n",
          msg->slot_exec.parent, msg->slot_exec.root, msg->slot_exec.slot, bank_hash, msg->slot_exec.transaction_count );
}

static void
my_block_fun(ulong slot, fd_block_map_t const * meta, fd_hash_t const * parent, uchar const * data, ulong data_sz, void * arg) {
  (void)data;
  (void)arg;
  char bank_hash[50];
  fd_base58_encode_32(meta->bank_hash.uc, 0, bank_hash);
  char parent_hash[50];
  fd_base58_encode_32(parent->uc, 0, parent_hash);
  printf( "\"block\":{\"slot\":%lu,\"bank_hash\":\"%s\",\"parent_hash\":\"%s\",\"height\":%lu,\"data_sz\":%lu}\n",
          slot, bank_hash, parent_hash, meta->height, data_sz );
}

static void
my_entry_fun(ulong slot, fd_microblock_hdr_t * entry, void * arg) {
  (void)arg;
  char hash[50];
  fd_base58_encode_32(entry->hash, 0, hash);
  printf( "\"entry\":{\"slot\":%lu,\"hash_cnt\":%lu,\"hash\":\"%s\",\"txn_cnt\":%lu}\n",
          slot, entry->hash_cnt, hash, entry->txn_cnt );
}

static void
my_txn_fun(ulong slot, fd_txn_t const * txn, void const * raw, ulong txn_sz, void * arg) {
  (void)arg;
  fd_txn_key_t const * sigs = (fd_txn_key_t const *)( (ulong)raw + (ulong)txn->signature_off );
  char sig_txt[100];
  fd_base58_encode_64((uchar const*)sigs, 0, sig_txt);
  printf( "\"txn\":{\"slot\":%lu,\"sig\":\"%s\",\"txn_sz\":%lu}\n",
          slot, sig_txt, txn_sz );
}

static void
my_acct_fun(ulong slot, uchar txn_sig[64U], fd_hash_t const * address, fd_account_meta_t const * meta, void const * data, ulong data_sz, void * arg) {
  (void)data;
  (void)arg;
  char sig_txt[100];
  fd_base58_encode_64(txn_sig, 0, sig_txt);
  char addr_txt[50];
  fd_base58_encode_32(address->uc, 0, addr_txt);
  char owner_txt[50];
  fd_base58_encode_32(meta->info.owner, 0, owner_txt);
  printf( "\"acct\":{\"slot\":%lu,\"txn_sig\":\"%s\",\"address\":\"%s\",\"onwer\":\"%s\",\"lamports\":%lu,\"data_sz\":%lu}\n",
          slot, sig_txt, addr_txt, owner_txt, meta->info.lamports, data_sz );
}

static void
init_args( int * argc, char *** argv, fd_geyser_args_t * args ) {
  memset( args, 0, sizeof(fd_geyser_args_t) );

  char const * funk_file = fd_env_strip_cmdline_cstr( argc, argv, "--funk-file", NULL, NULL );
  if( FD_UNLIKELY( !funk_file ))
    FD_LOG_ERR(( "--funk-file argument is required" ));
  args->funk_file = funk_file;

  args->blockstore_wksp = fd_env_strip_cmdline_cstr ( argc, argv, "--wksp-name-blockstore", NULL, "fd1_bstore.wksp" );

  if( fd_env_strip_cmdline_int ( argc, argv, "--notify-execution", NULL, 0 ) ) {
    args->execute_fun = my_execute_fun;
  }

  if( fd_env_strip_cmdline_int ( argc, argv, "--notify-block", NULL, 0 ) ) {
    args->block_fun = my_block_fun;
  }

  if( fd_env_strip_cmdline_int ( argc, argv, "--notify-entry", NULL, 0 ) ) {
    args->entry_fun = my_entry_fun;
  }

  if( fd_env_strip_cmdline_int ( argc, argv, "--notify-txn", NULL, 0 ) ) {
    args->txn_fun = my_txn_fun;
  }

  if( fd_env_strip_cmdline_int ( argc, argv, "--notify-acct", NULL, 0 ) ) {
    args->acct_fun = my_acct_fun;
  }
}

static int stopflag = 0;
static void
signal1( int sig ) {
  (void)sig;
  stopflag = 1;
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_geyser_args_t args;

#define SMAX 1LU<<28
  uchar * smem = aligned_alloc( FD_SCRATCH_SMEM_ALIGN,
                                fd_ulong_align_up( fd_scratch_smem_footprint( SMAX  ), FD_SCRATCH_SMEM_ALIGN ) );
  ulong fmem[16U];
  fd_scratch_attach( smem, fmem, SMAX, 16U );

  init_args( &argc, &argv, &args );

  struct sigaction sa = {
    .sa_handler = signal1,
    .sa_flags   = 0,
  };
  if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sigaction( SIGINT, &sa, NULL ) ) )
    FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_geyser_t * geyser = fd_geyser_join( fd_geyser_new( aligned_alloc( fd_geyser_align(), fd_geyser_footprint() ), &args ) );

  while( !stopflag ) {
    fd_geyser_poll( geyser );
  }

  free( fd_geyser_delete( fd_geyser_leave( geyser ) ) );

  fd_scratch_detach( NULL );

  fd_halt();
  return 0;
}
