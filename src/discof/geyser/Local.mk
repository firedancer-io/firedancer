ifdef FD_HAS_INT128
ifdef FD_HAS_SSE
$(call add-hdrs,fd_geyser.h)
$(call add-objs,fd_geyser,fd_discof)
$(call make-unit-test,test_geyser,test_geyser,fd_reedsol fd_discof fd_disco fd_flamenco fd_ballet fd_funk fd_tango fd_choreo fd_waltz fd_util)
endif
endif
