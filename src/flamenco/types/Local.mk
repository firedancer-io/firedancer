$(call add-hdrs,fd_bincode.h fd_types.h fd_types_custom.h fd_cast.h)
$(call add-objs,fd_types,fd_flamenco)
ifdef FD_HAS_DOUBLE
$(call make-unit-test,test_cast,test_cast,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_cast)
endif

# "ConfirmedBlock" Protobuf definitions
$(call add-objs,fd_solana_block.pb,fd_flamenco)
