# HPACK
$(call add-hdrs,fd_hpack.h,fd_waltz)
$(call add-objs,fd_hpack,fd_waltz)
$(call add-objs,nghttp2_hd_huffman nghttp2_hd_huffman_data,fd_waltz)
ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_hpack_rd,fuzz_hpack_rd,fd_waltz fd_util)
endif

# HTTP/2
$(call add-hdrs,fd_h2_base.h fd_h2_proto.h)
$(call add-objs,fd_h2_proto,fd_waltz)

$(call add-hdrs,fd_h2_rbuf.h fd_h2_rbuf_sock.h)

$(call add-hdrs,fd_h2_callback.h)
$(call add-objs,fd_h2_callback,fd_waltz)

$(call add-hdrs,fd_h2_conn.h)
$(call add-objs,fd_h2_conn,fd_waltz)

$(call add-hdrs,fd_h2_hdr_match.h)
$(call add-objs,fd_h2_hdr_match,fd_waltz)

$(call add-hdrs,fd_h2_tx.h)
$(call add-objs,fd_h2_tx,fd_waltz)

# Tests
$(call make-unit-test,test_h2,test_h2,fd_waltz fd_ballet fd_util)
$(call run-unit-test,test_h2)

ifdef FD_HAS_HOSTED
$(call make-fuzz-test,fuzz_h2,fuzz_h2,fd_waltz fd_util)
$(call make-unit-test,test_h2_server,test_h2_server,fd_waltz fd_util)
endif
