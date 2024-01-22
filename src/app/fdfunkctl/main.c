#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include "../../util/fd_util.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../funk/fd_funk.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../flamenco/types/fd_types_yaml.h"

static void usage(char const * progname) {
  fprintf(stderr, "USAGE: %s\n", progname);
  fprintf(stderr, " --wksp <name>                      funk workspace name\n");
  fprintf(stderr, " --cmd load --file <file>           load a workspace backup file into the wksp\n");
  fprintf(stderr, "       backup --file <file>         create a workspace backup file from the wksp\n");
  fprintf(stderr, "       verify                       verify funk integrity\n");
  fprintf(stderr, "       print-txns                   print the tree of transactions\n");
  fprintf(stderr, "       publish-txn --xid <xid>      publish/commit the given transaction\n");
  fprintf(stderr, "       cancel-txn --xid <xid>       cancel the given transaction\n");
  fprintf(stderr, "       merge-txn --xid <xid>        merge the given transaction into its parent\n");
  fprintf(stderr, "       inspect-txn --xid <xid>      list all the modified records in the given transaction\n");
  fprintf(stderr, "       publish-all-txns             publish all unpublished transaction\n");
  fprintf(stderr, "       cancel-all-txns              cancel all unpublished transaction\n");
  fprintf(stderr, "       inspect-raw --key <key:xid>  dump the given record in raw hex, :xid is optional\n");
  fprintf(stderr, "       inspect-acct --key <key:xid> inspect the record as an account, :xid is optional\n");
  fprintf(stderr, "                    --type <type>   optional flag to decode as a bincode type\n");
  fprintf(stderr, "       find-acct --pubkey <pubkey>  find all versions of an account\n");
  fprintf(stderr, " --out <file>                       print to the given file\n");
  fprintf(stderr, " --loglevel <level>                 Set logging level\n");
}

static FILE * outf = NULL;

static void
load_cmd(fd_wksp_t * wksp, const char* file) {
  FD_LOG_NOTICE(("reading %s", file));
  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));
  int err = fd_wksp_restore(wksp, file, (uint)hashseed);
  if (err)
    FD_LOG_ERR(("load failed: error %d", err));
  FD_LOG_NOTICE(("success!"));
}

static void
backup_cmd(fd_wksp_t * wksp, const char* file) {
  FD_LOG_NOTICE(("writing %s", file));
  unlink(file);
  int err = fd_wksp_checkpt(wksp, file, 0666, 0, NULL);
  if (err)
    FD_LOG_ERR(("backup failed: error %d", err));
  FD_LOG_NOTICE(("success!"));
}

static void
print_txns_cmd(fd_funk_t * funk, ulong idx, uint indent, int last) {
  fd_wksp_t *     wksp    = fd_funk_wksp( funk );
  fd_funk_txn_t * map     = fd_funk_txn_map( funk, wksp );
  ulong child_idx;
  for (uint i = 0; i < indent; ++i) fprintf(outf, "  ");
  if (idx == FD_FUNK_TXN_IDX_NULL) {
    fprintf(outf, "{ \"xid\":\"%32J\", \"children\":[\n", fd_funk_root(funk));
    child_idx = fd_funk_txn_idx( funk->child_head_cidx );
  } else {
    fprintf(outf, "{ \"idx\":%lu, \"xid\":\"%32J\", \"children\":[\n",
            idx, fd_funk_txn_xid(&map[idx]));
    child_idx = fd_funk_txn_idx( map[ idx ].child_head_cidx );
  }
  while( !fd_funk_txn_idx_is_null( child_idx ) ) {
    ulong next = fd_funk_txn_idx( map[ child_idx ].sibling_next_cidx );
    print_txns_cmd(funk, child_idx, indent+1, fd_funk_txn_idx_is_null(next));
    child_idx = next;
  }
  for (uint i = 0; i < indent; ++i) fprintf(outf, "  ");
  if (last)
    fprintf(outf, "] }\n");
  else
    fprintf(outf, "] },\n");
}

static fd_funk_txn_t *
resolve_txn(fd_funk_t * funk, const char * xid_str) {
  fd_wksp_t *     wksp    = fd_funk_wksp( funk );
  fd_funk_txn_t * map     = fd_funk_txn_map( funk, wksp );
  fd_funk_txn_xid_t xid;
  if (NULL == fd_base58_decode_32(xid_str, xid.uc))
    FD_LOG_ERR(("invalid base58 encoding"));
  if (memcmp(fd_funk_root(funk), &xid, 32) == 0)
    return NULL; // Root transaction
  fd_funk_txn_t * txn = fd_funk_txn_query(&xid, map);
  if (NULL == txn)
    FD_LOG_ERR(("no transaction with that xid"));
  return txn;
}

static void
publish_txn_cmd(fd_funk_t * funk, const char * xid_str) {
  fd_funk_txn_t * txn = resolve_txn(funk, xid_str);
  FD_TEST(fd_funk_txn_publish(funk, txn, 1) > 0);
  FD_LOG_NOTICE(("success!"));
}

static void
cancel_txn_cmd(fd_funk_t * funk, const char * xid_str) {
  fd_funk_txn_t * txn = resolve_txn(funk, xid_str);
  FD_TEST(fd_funk_txn_cancel(funk, txn, 1) > 0);
  FD_LOG_NOTICE(("success!"));
}

static void
merge_txn_cmd(fd_funk_t * funk, const char * xid_str) {
  fd_funk_txn_t * txn = resolve_txn(funk, xid_str);
  FD_TEST(FD_FUNK_SUCCESS == fd_funk_txn_merge(funk, txn, 1));
  FD_LOG_NOTICE(("success!"));
}

static void
inspect_txn_cmd(fd_funk_t * funk, const char * xid_str) {
  fd_funk_txn_t * txn = resolve_txn(funk, xid_str);
  fprintf(outf, "[\n");
  fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
  while (NULL != rec) {
    fd_funk_rec_t const * next = fd_funk_txn_next_rec( funk, rec );
    fprintf(outf, "  { \"key\":\"%32J.%32J\", \"len\":%lu }%s\n",
            rec->pair.key->uc, rec->pair.key->uc + 32U, fd_funk_val_sz(rec), (next == NULL ? "" : ","));
    rec = next;
  }
  fprintf(outf, "]\n");
}

static void
publish_all_cmd(fd_funk_t * funk) {
  fd_wksp_t *     wksp    = fd_funk_wksp( funk );
  fd_funk_txn_t * map     = fd_funk_txn_map( funk, wksp );
  do {
    ulong idx = fd_funk_txn_idx( funk->child_head_cidx );
    if (idx == FD_FUNK_TXN_IDX_NULL)
      break;
    FD_TEST(fd_funk_txn_publish(funk, &map[idx], 1) > 0);
  } while (1);
  FD_LOG_NOTICE(("success!"));
}

static void
cancel_all_cmd(fd_funk_t * funk) {
  fd_funk_txn_cancel_all(funk, 1);
  FD_LOG_NOTICE(("success!"));
}

static fd_funk_rec_t const *
resolve_rec(fd_funk_t * funk, const char * key_str) {
  char tmp[FD_BASE58_ENCODED_32_LEN];
  fd_funk_rec_key_t key;
  const char * p;
  uint i = 0;
  for (p = key_str; *p != '.'; ++p, ++i) {
    if (*p == '\0' || i > sizeof(tmp)-1U)
      FD_LOG_ERR(("invalid record key format"));
    tmp[i] = *p;
  }
  tmp[i] = '\0';
  if (NULL == fd_base58_decode_32(tmp, key.uc))
    FD_LOG_ERR(("invalid base58 encoding"));
  i = 0;
  for (++p; *p != '\0' && *p != ':'; ++p, ++i) {
    if (i > sizeof(tmp)-1U)
      FD_LOG_ERR(("invalid record key format"));
    tmp[i] = *p;
  }
  tmp[i] = '\0';
  if (NULL == fd_base58_decode_32(tmp, key.uc + 32U))
    FD_LOG_ERR(("invalid base58 encoding"));

  fd_funk_txn_t * txn;
  if (*p == '\0') {
    txn = NULL; /* root */
  } else {
    ++p; /* Skip ':' */
    fd_funk_txn_xid_t xid;
    if (NULL == fd_base58_decode_32(p, xid.uc))
      FD_LOG_ERR(("invalid base58 encoding"));
    if (memcmp(fd_funk_root(funk), &xid, 32) == 0)
      txn = NULL; /* root */
    else {
      fd_wksp_t *     wksp    = fd_funk_wksp( funk );
      fd_funk_txn_t * map     = fd_funk_txn_map( funk, wksp );
      txn = fd_funk_txn_query(&xid, map);
      if (NULL == txn)
        FD_LOG_ERR(("no transaction with that xid"));
    }
  }
  fd_funk_rec_t const * rec = fd_funk_rec_query_const(funk, txn, &key);
  if (NULL == rec)
    FD_LOG_ERR(("record not found"));
  return rec;
}

static void
inspect_raw_cmd(fd_funk_t * funk, const char * key_str) {
  fd_funk_rec_t const * rec = resolve_rec(funk, key_str);
  ulong len = fd_funk_val_sz(rec);
  fprintf(outf, "{ \"key\":\"%32J.%32J:%32J\", \"len\":%lu \"data\":\"",
          rec->pair.key->uc, rec->pair.key->uc + 32U, rec->pair.xid->uc, len);
  uchar const * val = (uchar const *)fd_funk_val(rec, fd_funk_wksp( funk ));
  for (ulong i = 0; i < len; ++i) {
    static const char * DIGITS = "0123456789ABCDEF";
    fputc(DIGITS[(val[i] >> 4U)&0xf], outf);
    fputc(DIGITS[val[i]&0xf], outf);
  }
  fprintf(outf, "\"}\n");
}

static void
type_lookup(const char *type, fd_types_funcs_t * t) {
  char fp[255];

#pragma GCC diagnostic ignored "-Wpedantic"
  sprintf(fp, "%s_footprint", type);
  t->footprint_fun = dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_align", type);
  t->align_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_new", type);
  t->new_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_decode", type);
  t->decode_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_walk", type);
  t->walk_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_encode", type);
  t->encode_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_destroy", type);
  t->destroy_fun =  dlsym(RTLD_DEFAULT, fp);

  sprintf(fp, "%s_size", type);
  t->size_fun =  dlsym(RTLD_DEFAULT, fp);

  if ((  t->footprint_fun == NULL) ||
      (  t->align_fun == NULL) ||
      (  t->new_fun == NULL) ||
      (  t->decode_fun == NULL) ||
      (  t->walk_fun == NULL) ||
      (  t->encode_fun == NULL) ||
      (  t->destroy_fun == NULL) ||
      (  t->size_fun == NULL))
    FD_LOG_ERR(("unknown type name"));
}

static void
inspect_acct_cmd(fd_funk_t * funk, const char * key_str, char const * type) {
  fd_funk_rec_t const * rec = resolve_rec(funk, key_str);
  if (!fd_acc_mgr_is_key(rec->pair.key))
    FD_LOG_ERR(("not an account record"));
  fprintf(outf, "{ \"key\":\"%32J.%32J:%32J\", ", rec->pair.key->uc, rec->pair.key->uc + 32U, rec->pair.xid->uc);
  uchar const * raw = (uchar const *)fd_funk_val(rec, fd_funk_wksp( funk ));
  fd_account_meta_t const * meta = (fd_account_meta_t const *)raw;
  fprintf(outf, "\"hlen\":%hu, \"dlen\":%lu, \"hash\":\"%32J\", \"slot\":%lu, ",
          meta->hlen, meta->dlen, meta->hash, meta->slot);
  fprintf(outf, "\"lamports\":%lu, \"rent_epoch\":%lu, \"owner\":\"%32J\", \"executable\":%d",
          meta->info.lamports, meta->info.rent_epoch, meta->info.owner, (int)meta->info.executable);

  if (type != NULL) {
    fd_types_funcs_t tfuns;
    type_lookup(type, &tfuns);
    fprintf(outf, ", \"content\":\"");

    fd_scratch_push();
    fd_bincode_decode_ctx_t decode = {
      .data    = raw + meta->hlen,
      .dataend = raw + meta->hlen + meta->dlen,
      .valloc  = fd_scratch_virtual()
    };
    fd_flamenco_yaml_t * yaml =
      fd_flamenco_yaml_init( fd_flamenco_yaml_new(
        fd_scratch_alloc( fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ), outf );
    char* d = fd_valloc_malloc( decode.valloc, tfuns.align_fun(), tfuns.footprint_fun() );
    tfuns.new_fun(d);
    int err = tfuns.decode_fun( d, &decode );
    if( FD_UNLIKELY( err!=0 ) )
      FD_LOG_ERR(("decode failed"));
    tfuns.walk_fun(yaml, d, fd_flamenco_yaml_walk, NULL, 0U );
    fd_scratch_pop();

    fprintf(outf, "\"");
  }
  fprintf(outf, " }\n");
}

static void
find_acct_cmd(fd_funk_t * funk, const char * pubkey_str) {
  fd_pubkey_t pubkey;
  if (NULL == fd_base58_decode_32(pubkey_str, pubkey.uc))
    FD_LOG_ERR(("invalid base58 encoding"));
  fd_funk_rec_key_t key = fd_acc_mgr_key(&pubkey);
  fd_wksp_t *     wksp    = fd_funk_wksp( funk );          /* Previously verified */
  fd_funk_txn_t * map     = fd_funk_txn_map( funk, wksp ); /* Previously verified */
  fprintf(outf, "[");
  int first = 1;
  for( fd_funk_txn_map_iter_t iter = fd_funk_txn_map_iter_init( map );
       !fd_funk_txn_map_iter_done( map, iter );
       iter = fd_funk_txn_map_iter_next( map, iter ) ) {
    fd_funk_txn_t * txn = fd_funk_txn_map_iter_ele( map, iter );
    fd_funk_rec_t const * rec = fd_funk_rec_query_const(funk, txn, &key);
    if (NULL != rec) {
      if (first) {
        fprintf(outf, "\n");
        first = 0;
      } else
        fprintf(outf, ",\n");
      fprintf(outf, "  { \"key\":\"%32J.%32J:%32J\", \"len\":%lu }",
              rec->pair.key->uc, rec->pair.key->uc + 32U, rec->pair.xid->uc, fd_funk_val_sz(rec));
    }
  }
  fd_funk_rec_t const * rec = fd_funk_rec_query_const(funk, NULL, &key);
  if (NULL != rec) {
    if (first) {
      fprintf(outf, "\n");
      first = 0;
    } else
      fprintf(outf, ",\n");
    fprintf(outf, "  { \"key\":\"%32J.%32J:%32J\", \"len\":%lu }",
            rec->pair.key->uc, rec->pair.key->uc + 32U, rec->pair.xid->uc, fd_funk_val_sz(rec));
  }
  fprintf(outf, "\n]\n");
}

int
main( int     argc,
      char ** argv ) {

  if( FD_UNLIKELY( argc==1 ) ) {
    usage( argv[0] );
    return 1;
  }

  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

# define SMAX 4 << 20
  static uchar smem[SMAX] __attribute((aligned(FD_SCRATCH_SMEM_ALIGN)));
# define SCRATCH_DEPTH (4UL)
  static ulong fmem[ SCRATCH_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));
  fd_scratch_attach( smem, fmem, SMAX, SCRATCH_DEPTH );

  char const * outfname = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out", NULL, NULL );
  if (NULL == outfname)
    outf = stdout;
  else {
    outf = fopen(outfname, "w");
    if (outf == NULL)
      FD_LOG_ERR(("open %s failed: %s", outfname, strerror(errno)));
  }

  char const * wkspname = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp", NULL, NULL );
  if (wkspname == NULL) {
    FD_LOG_ERR(( "--wksp is mandatory" ));
    return 1;
  }
  fd_wksp_t* wksp = fd_wksp_attach(wkspname);
  if (wksp == NULL)
    FD_LOG_ERR(( "failed to attach to workspace %s", wkspname ));

  while(1) {
    char const * cmd = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cmd", NULL, NULL );
    if (cmd == NULL)
      break;

    if (strcmp(cmd, "load") == 0) {
      char const * file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--file", NULL, NULL );
      if (file == NULL) {
        FD_LOG_ERR(( "load requires --file flag" ));
        return 1;
      }
      load_cmd(wksp, file);
      continue;
    }

    if (strcmp(cmd, "backup") == 0) {
      char const * file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--file", NULL, NULL );
      if (file == NULL) {
        FD_LOG_ERR(( "backup requires --file flag" ));
        return 1;
      }
      backup_cmd(wksp, file);
      continue;
    }

    fd_wksp_tag_query_info_t info;
    ulong tag = FD_FUNK_MAGIC;
    if (fd_wksp_tag_query(wksp, &tag, 1, &info, 1) <= 0) {
      FD_LOG_ERR(( "failed to find a funky in the workspace" ));
      return 1;
    }
    void * shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
    fd_funk_t * funk = fd_funk_join(shmem);
    if (funk == NULL) {
      FD_LOG_ERR(( "failed to join a funky" ));
      return 1;
    }

    if (strcmp(cmd, "verify") == 0) {
      FD_TEST(fd_funk_verify(funk) == FD_FUNK_SUCCESS);

    } else if (strcmp(cmd, "print-txns") == 0) {
      print_txns_cmd(funk, FD_FUNK_TXN_IDX_NULL, 0, 1);

    } else if (strcmp(cmd, "publish-txn") == 0) {
      char const * xid = fd_env_strip_cmdline_cstr ( &argc, &argv, "--xid", NULL, NULL );
      if (xid == NULL) {
        FD_LOG_ERR(( "publish-txn requires --xid flag" ));
        return 1;
      }
      publish_txn_cmd(funk, xid);

    } else if (strcmp(cmd, "cancel-txn") == 0) {
      char const * xid = fd_env_strip_cmdline_cstr ( &argc, &argv, "--xid", NULL, NULL );
      if (xid == NULL) {
        FD_LOG_ERR(( "cancel-txn requires --xid flag" ));
        return 1;
      }
      cancel_txn_cmd(funk, xid);

    } else if (strcmp(cmd, "merge-txn") == 0) {
      char const * xid = fd_env_strip_cmdline_cstr ( &argc, &argv, "--xid", NULL, NULL );
      if (xid == NULL) {
        FD_LOG_ERR(( "merge-txn requires --xid flag" ));
        return 1;
      }
      merge_txn_cmd(funk, xid);

    } else if (strcmp(cmd, "inspect-txn") == 0) {
      char const * xid = fd_env_strip_cmdline_cstr ( &argc, &argv, "--xid", NULL, NULL );
      if (xid == NULL) {
        FD_LOG_ERR(( "inspect-txn requires --xid flag" ));
        return 1;
      }
      inspect_txn_cmd(funk, xid);

    } else if (strcmp(cmd, "publish-all-txns") == 0) {
      publish_all_cmd(funk);

    } else if (strcmp(cmd, "cancel-all-txns") == 0) {
      cancel_all_cmd(funk);

    } else if (strcmp(cmd, "inspect-raw") == 0) {
      char const * key = fd_env_strip_cmdline_cstr ( &argc, &argv, "--key", NULL, NULL );
      if (key == NULL) {
        FD_LOG_ERR(( "inspect-raw requires --key flag" ));
        return 1;
      }
      inspect_raw_cmd(funk, key);

    } else if (strcmp(cmd, "inspect-acct") == 0) {
      char const * key = fd_env_strip_cmdline_cstr ( &argc, &argv, "--key", NULL, NULL );
      if (key == NULL) {
        FD_LOG_ERR(( "inspect-acct requires --key flag" ));
        return 1;
      }
      char const * type = fd_env_strip_cmdline_cstr ( &argc, &argv, "--type", NULL, NULL );
      inspect_acct_cmd(funk, key, type);

    } else if (strcmp(cmd, "find-acct") == 0) {
      char const * pubkey = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pubkey", NULL, NULL );
      if (pubkey == NULL) {
        FD_LOG_ERR(( "find-acct requires --pubkey flag" ));
        return 1;
      }
      find_acct_cmd(funk, pubkey);

    } else
      FD_LOG_WARNING(("command %s is unknown", cmd));

    fd_funk_leave( funk );
  }

  if (outf != stdout)
    fclose(outf);

  fd_log_flush();
  fd_flamenco_halt();
  fd_halt();
  return 0;
}
