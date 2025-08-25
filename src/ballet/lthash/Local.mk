$(call add-hdrs,fd_lthash.h)
$(call add-hdrs,fd_lthash_adder.h)
$(call add-objs,fd_lthash_adder,fd_ballet)
$(call make-unit-test,test_lthash,test_lthash,fd_ballet fd_util)
