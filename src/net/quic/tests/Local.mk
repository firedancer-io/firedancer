$(call make-bin,test_quic,test_quic ../fd_quic ../../util/fd_net_util ../fd_quic_conn ../fd_quic_conn_id \
       ../fd_quic_conn_map ../fd_quic_proto ../templ/fd_quic_transport_params \
       ../templ/fd_quic_parse_util ../fd_quic_stream ../../aio/fd_aio \
       ../tls/fd_quic_tls ../crypto/fd_quic_crypto_suites,fd_util)

$(call make-bin,test_quic_hs,test_quic_hs ../fd_quic ../../util/fd_net_util ../fd_quic_conn ../fd_quic_conn_id \
       ../fd_quic_conn_map ../fd_quic_proto ../templ/fd_quic_transport_params \
       ../templ/fd_quic_parse_util ../fd_quic_stream ../../aio/fd_aio \
       ../tls/fd_quic_tls ../crypto/fd_quic_crypto_suites,fd_util)

$(call make-bin,test_handshake,test_handshake ../tls/fd_quic_tls ../fd_quic_proto \
       ../templ/fd_quic_transport_params ../templ/fd_quic_parse_util ../fd_quic_stream \
       ../../aio/fd_aio ../../util/fd_net_util,fd_util)

$(call make-bin,test_crypto,test_crypto ../fd_quic ../fd_quic_conn ../fd_quic_conn_id \
       ../fd_quic_conn_map ../fd_quic_proto ../templ/fd_quic_transport_params \
       ../templ/fd_quic_parse_util ../fd_quic_stream ../../aio/fd_aio \
       ../tls/fd_quic_tls ../crypto/fd_quic_crypto_suites ../../util/fd_net_util,fd_util)

$(call make-bin,test_frames,test_frames ../templ/fd_quic_parse_util ../fd_quic_proto,fd_util)

$(call make-bin,test_checksum,test_checksum ../../util/fd_net_util,)
