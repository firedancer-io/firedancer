def fmt_ip4_addr(num):
    return "%d.%d.%d.%d" % (
        num & 0xFF,
        (num >> 8) & 0xFF,
        (num >> 16) & 0xFF,
        (num >> 24) & 0xFF,
    )


def trace_conn_error(frame, bp_loc, internal_dict):
    conn = frame.FindVariable("conn")
    peer = conn.GetChildMemberWithName("peer").GetChildAtIndex(0)
    print(
        "  fd_quic_conn_error: conn_id=%016x reason=0x%x endpoint=%s:%d"
        % (
            int(conn.GetChildMemberWithName("our_conn_id").value),
            int(frame.FindVariable("reason").value),
            fmt_ip4_addr(int(peer.GetChildMemberWithName("ip_addr").value)),
            int(peer.GetChildMemberWithName("udp_port").value),
        )
    )
