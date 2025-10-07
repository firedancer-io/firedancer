ifdef FD_HAS_INT128
ifdef FD_HAS_ROCKSDB
$(call add-objs,fd_eqvoctest_tile,fd_discof)
else
$(warning "rocksdb not installed, skipping eqvoctest")
endif
endif
