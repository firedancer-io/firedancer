$(call add-hdrs,fd_keccak256.h)
$(call add-objs,fd_keccak256,fd_ballet)

$(call make-unit-test,test_keccak256,test_keccak256,fd_ballet fd_util)
$(call fuzz-test,fuzz_keccak256,fuzz_keccak256,fd_ballet fd_util)
$(call run-unit-test,test_keccak256)
