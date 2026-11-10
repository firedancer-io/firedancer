# FD_HAS_TRANSPILE_EXEC: the host can run the code this build's
# backend emits (x86 code needs BMI2, which FD_HAS_AVX implies)
ifdef FD_HAS_ARM
FD_HAS_TRANSPILE_EXEC:=1
endif
ifdef FD_HAS_AVX
FD_HAS_TRANSPILE_EXEC:=1
endif

# transpiler core (portable): one machine code backend per target
$(call make-lib,fd_transpiler)
$(call add-hdrs,fd_transpile.h fd_transpile_bb.h fd_transpile_target.h)
$(call add-objs,fd_transpile_bb,fd_transpiler)
ifdef FD_HAS_ARM
$(call add-objs,fd_transpile_arm64,fd_transpiler)
else
$(call add-objs,fd_transpile_x86,fd_transpiler)
endif
$(call make-unit-test,test_transpile,test_transpile,fd_transpiler fd_util)
$(call run-unit-test,test_transpile)

# transpiler runtime support
$(call add-hdrs,fd_transpile_runtime.h)
$(call add-objs,fd_transpile_runtime,fd_flamenco)

# binds program cache records to linked-in transpiled programs
$(call add-hdrs,fd_transpile_bind.h fd_jit_proto.h fd_jit_arena.h)
$(call add-objs,fd_transpile_bind fd_transpile_ext fd_jit_arena,fd_flamenco)

# transpiler frontend
$(call add-hdrs,fd_transpile_obj.h)
$(call add-objs,fd_transpile_obj,fd_transpiler)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_transpile_obj,test_transpile_obj,fd_transpiler fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_transpile_obj)
$(call make-bin,fd_transpile,fd_transpile_main,fd_transpiler fd_flamenco fd_ballet fd_util)
ifdef FD_HAS_TRANSPILE_EXEC
$(call add-test-scripts,test_transpile_link.sh)
endif
endif

# test-only live transpiler
ifdef FD_HAS_TRANSPILE_EXEC
ifdef FD_HAS_HOSTED
$(call make-lib,fd_transpiler_live)
$(call add-hdrs,fd_transpile_live.h)
$(call add-objs,fd_transpile_live,fd_transpiler_live)
$(call make-unit-test,test_transpile_live,test_transpile_live,fd_transpiler_live fd_transpiler fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_transpile_live)
$(call make-fuzz-test,fuzz_transpile_diff,fuzz_transpile_diff,fd_transpiler fd_flamenco fd_ballet fd_util)
endif # FD_HAS_HOSTED
endif # FD_HAS_TRANSPILE_EXEC
