ifdef FD_HAS_INT128
$(call add-hdrs,fd_bincode.h fd_types.h fd_types_custom.h)
$(call add-objs,fd_types fd_types_yaml fd_types_meta,fd_flamenco)
ifdef FD_HAS_X86
$(call make-unit-test,test_pubkey_match,test_pubkey_match,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_pubkey_match)
endif
$(call make-unit-test,test_types_yaml,test_types_yaml,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_types_yaml)
$(call make-unit-test,test_types_walk,test_types_walk,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_types_walk)
$(call make-unit-test,test_types_fixtures,test_types_fixtures,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_types_fixtures)
endif
$(call fuzz-test,fuzz_types_decode,fuzz_types_decode,fd_flamenco fd_ballet fd_util)
$(call gen-protobuf,fd_solana_block)
$(call add-objs,fd_solana_block.pb,fd_flamenco)
