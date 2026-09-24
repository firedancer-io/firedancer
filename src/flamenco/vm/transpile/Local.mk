ifdef FD_HAS_X86
$(call add-hdrs,fd_transpile.h)
# the transpiler itself
$(call make-lib,fd_transpiler)
$(call add-hdrs,fd_transpile_obj.h)
$(call add-objs,fd_transpile fd_transpile_x86 fd_transpile_obj,fd_transpiler)
# transpiler runtime support
$(call add-hdrs,fd_transpile_runtime.h)
$(call add-objs,fd_transpile_runtime,fd_vm)
ifdef FD_HAS_HOSTED
$(call make-bin,fd_transpile,fd_transpile_main,fd_transpiler fd_flamenco fd_vm fd_ballet fd_util)
endif
endif # FD_HAS_X86
