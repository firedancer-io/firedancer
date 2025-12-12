$(call add-hdrs,fd_bincode.h fd_types.h fd_types_custom.h fd_types_meta.h fd_types_yaml.h fd_cast.h)
$(call add-objs,fd_types fd_types_yaml,fd_flamenco)
$(call make-unit-test,test_types_meta,test_types_meta,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_types_walk,test_types_walk,fd_flamenco fd_ballet fd_util)
$(call make-unit-test,test_types_yaml,test_types_yaml,fd_flamenco fd_ballet fd_util)
$(OBJDIR)/obj/flamenco/types/test_types_fixtures.o: $(wildcard src/flamenco/types/fixtures/*.bin) $(wildcard src/flamenco/types/fixtures/*.yml)
$(call make-unit-test,test_types_fixtures,test_types_fixtures,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_types_meta)
$(call run-unit-test,test_types_walk)
$(call run-unit-test,test_types_yaml)
$(call run-unit-test,test_types_fixtures)
ifdef FD_HAS_DOUBLE
$(call make-unit-test,test_cast,test_cast,fd_flamenco fd_ballet fd_util)
$(call run-unit-test,test_cast)
endif

$(call make-lib fd_flamenco_test)
$(call add-objs,fd_types_reflect fd_types_reflect_generated,fd_flamenco_test)

ifdef FD_HAS_HOSTED
$(call make-bin,fd_bincode2yaml,fd_bincode2yaml,fd_flamenco_test fd_flamenco fd_ballet fd_util)
$(call make-fuzz-test,fuzz_types_decode,fuzz_types_decode,fd_flamenco_test fd_flamenco fd_ballet fd_util)
endif

# "ConfirmedBlock" Protobuf definitions
$(call add-objs,fd_solana_block.pb,fd_flamenco)
