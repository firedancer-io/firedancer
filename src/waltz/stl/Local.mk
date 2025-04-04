$(call make-lib,fd_stl)

$(call add-hdrs,fd_stl.h fd_stl_proto.h fd_stl_base.h)
$(call add-objs,fd_stl,fd_stl)

$(call add-hdrs,fd_stl_private.h)
$(call add-objs,fd_stl_common,fd_stl)

$(call add-hdrs,fd_stl_s0_client.h fd_stl_s0_server.h)
$(call add-objs,fd_stl_s0,fd_stl)
