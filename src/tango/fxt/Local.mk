# FTF protocol definition
$(call add-hdrs,fd_fxt_proto.h)

# Firedancer-specific shared memory transport for FTF events
$(call add-hdrs,fd_fxt_pub.h)
$(call add-objs,fd_fxt_pub,fd_tango)
