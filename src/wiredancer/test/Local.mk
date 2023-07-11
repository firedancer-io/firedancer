ifdef FD_HAS_WIREDANCER
$(call make-lib,fd_wiredancer_test)
$(call add-hdrs,wd_f1_mon.h fd_replay_loop.h)
$(call add-objs,fd_replay_loop wd_f1_mon,fd_wiredancer_test)
$(call make-unit-test,test_wiredancer_demo,test_wiredancer_demo wd_f1_mon fd_replay_loop,fd_wiredancer fd_ballet fd_disco fd_tango fd_util)
endif
