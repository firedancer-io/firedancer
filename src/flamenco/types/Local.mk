$(call add-hdrs,fd_cast.h)
ifdef FD_HAS_DOUBLE
$(call make-unit-test,test_cast,test_cast,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_cast)
$(call make-unit-test,test_rust_float,test_rust_float,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_rust_float)
endif
