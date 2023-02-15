ifeq ($(FD_HAS_ZSTD),1)
$(call make-bin,fd_frank_ledger,main tar,fd_util fd_ballet)
$(call make-bin,banks_test,banks_test,fd_util fd_ballet)
$(call make-bin,test_funk,test_funk fd_funk,fd_util)
$(call make-bin,test_map_giant,test_map_giant,fd_util)
endif
