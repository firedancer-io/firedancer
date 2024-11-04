ifdef FD_HAS_INT128
$(call add-hdrs,fd_bincode.h fd_types.h fd_types_custom.h fd_types_meta.h fd_types_yaml.h fd_cast.h)
$(call add-objs,fd_types fd_types_yaml,fd_flamenco)
$(call make-unit-test,test_types_meta,test_types_meta,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_types_yaml,test_types_yaml,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_types_fixtures,test_types_fixtures,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_cast,test_cast,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_types_archive,test_types_archive,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_types_meta)
$(call run-unit-test,test_types_yaml)
$(call run-unit-test,test_types_fixtures)
$(call run-unit-test,test_cast)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_types_decode,fuzz_types_decode,fd_flamenco fd_ballet fd_util)
endif
endif

# "ConfirmedBlock" Protobuf definitions
$(call add-objs,fd_solana_block.pb,fd_flamenco)
