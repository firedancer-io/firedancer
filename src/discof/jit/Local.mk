ifdef FD_HAS_HOSTED
ifdef FD_HAS_TRANSPILE_EXEC
$(call add-hdrs,fd_jit_client.h)
$(call add-objs,fd_jit_client,fd_discof)

# The compiler tiles need fd_transpiler, which only firedancer-dev links
$(call make-lib,fd_jit)
$(call add-objs,fd_jit_tile fd_jitmap_tile,fd_jit)
endif
endif
