$(call make-lib,fd_disco)
$(call add-hdrs,fd_disco_base.h fd_disco.h)
$(call make-unit-test,test_disco_base,test_disco_base,fd_disco fd_tango fd_util)
$(call run-unit-test,test_disco_base,)
