$(call add-hdrs,fd_exec_test.pb.h)
$(call add-objs,fd_exec_test.pb,fd_flamenco)

ifdef FD_HAS_INT128
$(call add-hdrs,fd_exec_instr_test.h)
$(call add-objs,fd_exec_instr_test,fd_flamenco)

$(call make-unit-test,test_exec_instr,test_exec_instr,fd_flamenco fd_funk fd_ballet fd_util)
endif
