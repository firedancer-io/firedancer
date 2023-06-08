$(call make-lib,fd_disco)
$(call add-hdrs,fd_disco_base.h fd_disco.h)
$(call maybe-add-env-obj,DISCO_STATIC_EXTERN_OBJECT,fd_disco)
$(call make-unit-test,test_disco_base,test_disco_base,fd_disco fd_tango fd_util)
$(call run-unit-test,test_disco_base,)

