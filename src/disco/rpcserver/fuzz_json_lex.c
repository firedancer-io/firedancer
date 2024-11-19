#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../util/fd_util.h"
#include "json_lex.h"

# define SMAX (1L<<20UL)
# define FMAX (1UL)
uchar scratch_mem [ SMAX ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));
ulong scratch_fmem[ FMAX ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

struct json_lex_state *lex_state = NULL;

void free_lex_state( void ) { free(lex_state); }

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  /* Set up shell without signal handlers */
  putenv("FD_LOG_BACKTRACE=0");
  fd_boot(argc, argv);
  atexit(fd_halt);

  lex_state = malloc(sizeof(struct json_lex_state));
  atexit(free_lex_state);

  /* Disable parsing error logging */
  fd_log_level_stderr_set(4);
  return 0;
}

int
LLVMFuzzerTestOneInput(uchar const *data, ulong size) {
  fd_scratch_attach( scratch_mem, scratch_fmem, SMAX, FMAX );
  json_lex_state_new(lex_state, (const char *)data, size);
  for (;;) {
    long token_type = json_lex_next_token(lex_state);

    if (token_type == JSON_TOKEN_END || token_type == JSON_TOKEN_ERROR) {
      break;
    }

    ulong sz_out;
    const char *out = json_lex_get_text(lex_state, &sz_out);

    if (sz_out) {
      // Access the first and last byte of the state
      const char a __attribute__((unused)) = out[0];

      // An ASAN hit here would mean that json_lex_get_text claims that we can
      // read further than we can.
      const char b __attribute__((unused)) = out[sz_out - 1];
    }
  }

  json_lex_state_delete(lex_state);
  fd_scratch_detach( NULL );
  return 0;
}
