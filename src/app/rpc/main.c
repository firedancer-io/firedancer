/****
     build/linux/gcc/x86_64/bin/fd_rpc --wksp giant_wksp --gaddr 0xc7ce180
****/

#include "../../util/fd_util.h"
#include <signal.h>
#include <stdio.h>
#include <microhttpd.h>
#include "../../tango/webserver/fd_methods.h"
#include "../../tango/webserver/fd_webserver.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "keywords.h"

#define CRLF "\r\n"

static fd_funk_t* funk = NULL;
static fd_firedancer_banks_t bank;

// Implementation of the "getBalance" method
int method_getBalance(struct fd_web_replier* replier, struct json_values* values, long call_id) {
  // Path to argument
  static const uint PATH[3] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_PARAMS,
    (JSON_TOKEN_LBRACKET<<16) | 0,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 3, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "getBalance requires a string as first parameter");
    return 0;
  }
  fd_pubkey_t acct;
  fd_base58_decode_32((const char *)arg, acct.uc);
  fd_funk_rec_key_t recid = fd_acc_mgr_key(&acct);
  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &recid);
  if (rec == NULL) {
    fd_web_replier_error(replier, "account not found");
    return 0;
  }
  int err;
  void * val = fd_funk_val_cache(funk, rec, &err);
  if (val == NULL ) {
    fd_web_replier_error(replier, "failed to load account data");
    return 0;
  }
  fd_account_meta_t * metadata = (fd_account_meta_t *)val;
  char buf[1000];
  long buflen = snprintf(buf, sizeof(buf), "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"apiVersion\":\"1.14.19\",\"slot\":%lu},\"value\":%lu},\"id\":%lu}" CRLF, bank.slot, metadata->info.lamports, call_id);
  fd_web_replier_reply(replier, buf, (uint)buflen);
  return 0;
}

// Top level method dispatch function
int fd_webserver_method_generic(struct fd_web_replier* replier, struct json_values* values) {
  static const uint PATH[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_JSONRPC,
    (JSON_TOKEN_STRING<<16)
  };
  ulong arg_sz = 0;
  const void* arg = json_get_value(values, PATH, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "missing jsonrpc member");
    return 0;
  }
  if (strcmp((const char*)arg, "2.0") != 0) {
    fd_web_replier_error(replier, "jsonrpc value must be 2.0");
    return 0;
  }

  static const uint PATH3[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_ID,
    (JSON_TOKEN_INTEGER<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH3, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "missing id member");
    return 0;
  }
  long call_id = *(long*)arg;

  static const uint PATH2[2] = {
    (JSON_TOKEN_LBRACE<<16) | KEYW_JSON_METHOD,
    (JSON_TOKEN_STRING<<16)
  };
  arg_sz = 0;
  arg = json_get_value(values, PATH2, 2, &arg_sz);
  if (arg == NULL) {
    fd_web_replier_error(replier, "missing method member");
    return 0;
  }
  long meth_id = fd_webserver_json_keyword((const char*)arg, arg_sz);

  switch (meth_id) {
  case KEYW_RPCMETHOD_GETBALANCE:
    if (!method_getBalance(replier, values, call_id))
      return 0;
    break;
  default: {
    char msg[100];
    snprintf(msg, sizeof(msg), "unknown or unimplemented method: %s", (const char*)arg);
    fd_web_replier_error(replier, msg);
    return 0;
  }
  }

  fd_webserver_reply_ok(replier);
  return 1;
}

// SIGINT signal handler
volatile int stopflag = 0;
void stop(int sig) { (void)sig; stopflag = 1; }

int main(int argc, char** argv)
{
  fd_boot(&argc, &argv);

  const char* wkspname = fd_env_strip_cmdline_cstr(&argc, &argv, "--wksp", NULL, NULL);
  if (wkspname == NULL)
    FD_LOG_ERR(( "--wksp not specified" ));
  fd_wksp_t* wksp = fd_wksp_attach(wkspname);
  if (wksp == NULL)
    FD_LOG_ERR(( "failed to attach to workspace %s", wkspname ));
  
  const char* gaddr = fd_env_strip_cmdline_cstr(&argc, &argv, "--gaddr", NULL, NULL);
  if (gaddr == NULL)
    FD_LOG_ERR(( "--gaddr not specified" ));
  void* shmem;
  if (gaddr[0] == '0' && gaddr[1] == 'x')
    shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(gaddr+2, NULL, 16) );
  else
    shmem = fd_wksp_laddr_fast( wksp, (ulong)strtol(gaddr, NULL, 10) );
  funk = fd_funk_join(shmem);
  if (funk == NULL)
    FD_LOG_ERR(( "failed to join a funky" ));

  {
    fd_firedancer_banks_new(&bank);
    fd_funk_rec_key_t id = fd_runtime_banks_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, NULL, &id);
    if ( rec == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    int err;
    void * val = fd_funk_val_cache( funk, rec, &err );
    if (val == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    fd_bincode_decode_ctx_t ctx;
    ctx.data = val;
    ctx.dataend = (uchar*)val + fd_funk_val_sz( rec );
    ctx.valloc = fd_libc_alloc_virtual();
    if ( fd_firedancer_banks_decode(&bank, &ctx ) )
      FD_LOG_ERR(("failed to read banks record"));
  }
  
  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  // Get the gateway service port number 
  uint portno = fd_env_strip_cmdline_uint(&argc, &argv, "--port", "FD_FCGI_PORT", 8899U);
  fd_webserver_t ws;
  if (fd_webserver_start(portno, &ws))
    FD_LOG_ERR(("fd_webserver_start failed"));
  
  while (!stopflag) {
    sleep(1);
  }

  if (fd_webserver_stop(&ws))
    FD_LOG_ERR(("fd_webserver_stop failed"));

  {
    fd_bincode_destroy_ctx_t ctx;
    ctx.valloc = fd_libc_alloc_virtual();
    fd_firedancer_banks_destroy(&bank, &ctx);
  }

  fd_funk_leave( funk );

  fd_log_flush();
  fd_halt();
  return 0;
}
