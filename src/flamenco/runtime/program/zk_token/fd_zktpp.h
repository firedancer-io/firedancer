static int
process_close_proof_context( fd_exec_instr_ctx_t ctx );

/* process_verify_proof
   executes the common logic among all the zktpp instructions:
   parse data (context + proof), verify proof, store context. */
static int
process_verify_proof( fd_exec_instr_ctx_t ctx,
                      uchar               instr_id );
