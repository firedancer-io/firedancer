ifdef FD_HAS_INT128
$(call make-lib,fd_choreo)
$(call add-hdrs,fd_choreo_base.h fd_choreo.h)
$(call make-unit-test,test_choreo_base,test_choreo_base,fd_choreo fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_choreo,test_choreo,fd_choreo fd_flamenco fd_ballet fd_funk fd_util fd_tango)
endif
