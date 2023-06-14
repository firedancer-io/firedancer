$(call make-lib,fd_ballet)
$(call add-hdrs,fd_ballet_base.h fd_ballet.h)
$(call maybe-add-env-obj,BALLET_STATIC_EXTERN_OBJECT,fd_ballet)
