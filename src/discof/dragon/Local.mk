ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_dragon_cuckoo.h fd_dragon_limits.h fd_dragon_buf.h fd_dragon_ingest.h fd_dragon_rpc.h fd_dragon_session.h fd_dragon_tile.h fd_geyser_api.h fd_geyser_core.h)
$(call add-objs,fd_dragon_cuckoo fd_dragon_buf fd_dragon_ingest fd_dragon_rpc fd_dragon_session fd_dragon_tile fd_geyser_core,fd_discof)

$(call make-unit-test,test_dragon_cuckoo,test_dragon_cuckoo,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_dragon_cuckoo)

$(call make-unit-test,test_dragon_rpc,test_dragon_rpc,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_dragon_rpc)

$(call make-unit-test,test_geyser_core,test_geyser_core,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_geyser_core)

$(call make-unit-test,test_dragon_records,test_dragon_records,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call run-unit-test,test_dragon_records,--page-sz normal --page-cnt 32768)

$(call make-unit-test,test_dragon_tile,test_dragon_tile,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)

$(call make-fuzz-test,fuzz_dragon_rpc,fuzz_dragon_rpc,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call make-fuzz-test,fuzz_dragon_filter,fuzz_dragon_filter,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call make-fuzz-test,fuzz_dragon_ingest,fuzz_dragon_ingest,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
$(call make-fuzz-test,fuzz_geyser_core,fuzz_geyser_core,fd_discof fd_disco fd_flamenco fd_waltz fd_tango fd_ballet fd_util)
endif
