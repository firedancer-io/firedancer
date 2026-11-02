ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX

$(call make-lib,fd_app_dev)

# firedancer-dev boot
$(call add-objs,boot/fd_dev_boot,fd_app_dev)

# firedancer-dev actions
$(call add-objs,commands/bench/bench,fd_app_dev)
$(call add-objs,commands/bundle_client,fd_app_dev)
$(call add-objs,commands/dev,fd_app_dev)
$(call add-objs,commands/dump,fd_app_dev)
$(call add-objs,commands/flame,fd_app_dev)
$(OBJDIR)/obj/app/shared_dev/commands/flame.o: src/app/shared_dev/commands/flamegraph_template.html src/app/shared_dev/commands/flamegraph.py
$(call add-objs,commands/load,fd_app_dev)
$(call add-objs,commands/metrics_record,fd_app_dev)
$(call add-objs,commands/pktgen/pktgen,fd_app_dev)
$(call add-objs,commands/txn,fd_app_dev)
$(call add-objs,commands/udpecho/udpecho,fd_app_dev)
$(call add-objs,commands/wksp,fd_app_dev)

# firedancer-dev tiles
$(call add-objs,commands/bench/fd_bencho,fd_app_dev)
$(call add-objs,commands/bench/fd_benchg,fd_app_dev)
$(call add-objs,commands/bench/fd_benchs,fd_app_dev)
$(call add-objs,commands/pktgen/fd_pktgen_tile,fd_app_dev)
$(call add-objs,commands/udpecho/fd_udpecho_tile,fd_app_dev)

# firedancer-dev configure stages
$(call add-objs,commands/configure/keys,fd_app_dev)
$(call add-objs,commands/configure/kill,fd_app_dev)
$(call add-objs,commands/configure/genesis,fd_app_dev)

endif
endif
