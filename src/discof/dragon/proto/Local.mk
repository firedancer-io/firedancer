# timestamp.pb is byte identical to the bundle's copy in fd_disco, which
# every target that links fd_discof also links; compiling it here too
# would duplicate google_protobuf_Timestamp_*
$(call add-objs,geyser.pb solana_storage.pb health.pb,fd_discof)
