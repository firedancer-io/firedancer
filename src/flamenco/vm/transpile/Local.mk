# transpiler core (portable)
$(call make-lib,fd_transpiler)
$(call add-hdrs,fd_transpile.h)
$(call add-objs,fd_transpile_x86,fd_transpiler)
$(call make-unit-test,test_transpile,test_transpile,fd_transpiler fd_util)
$(call run-unit-test,test_transpile)

# transpiler runtime support
$(call add-hdrs,fd_transpile_runtime.h)
$(call add-objs,fd_transpile_runtime,fd_vm)

# binds program cache records to linked-in transpiled programs
$(call add-hdrs,fd_transpile_bind.h)
$(call add-objs,fd_transpile_bind,fd_flamenco)

# transpiler frontend
$(call add-hdrs,fd_transpile_obj.h)
$(call add-objs,fd_transpile_obj,fd_transpiler)
ifdef FD_HAS_HOSTED
$(call make-unit-test,test_transpile_obj,test_transpile_obj,fd_transpiler fd_flamenco fd_vm fd_ballet fd_util)
$(call run-unit-test,test_transpile_obj)
$(call make-bin,fd_transpile,fd_transpile_main,fd_transpiler fd_flamenco fd_vm fd_ballet fd_util)
ifdef FD_HAS_AVX
$(call add-test-scripts,test_transpile_link.sh)
endif
endif

# test-only live transpiler
ifdef FD_HAS_AVX # transpiled code requires X86 and BMI2
ifdef FD_HAS_HOSTED
$(call make-lib,fd_transpiler_live)
$(call add-hdrs,fd_transpile_live.h)
$(call add-objs,fd_transpile_live,fd_transpiler_live)
$(call make-unit-test,test_transpile_live,test_transpile_live,fd_transpiler_live fd_transpiler fd_flamenco fd_vm fd_ballet fd_util)
$(call run-unit-test,test_transpile_live)
$(call make-fuzz-test,fuzz_transpile_diff,fuzz_transpile_diff,fd_transpiler fd_flamenco fd_vm fd_ballet fd_util)
endif # FD_HAS_HOSTED
endif # FD_HAS_AVX
