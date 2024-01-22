
/*

    Transactions belonging to each stream (identified by metadata.src)
    must be published to the host in the same order as they were invoked
    by the host.  Scrambling occurs inside SHA as message length determines
    the number of cycles to perform SHA.

    A 64-bit timestamp (cycle count) is used for time keeping.  At 250MHz
    a 64-bit timestamp will wrap around after ~137 years.

    Transactions are placed into a ram according to the LSBs of the
    transaction ID, along with the current timestamp.

    For every ram location, a last-seen timestamp is also kept in a 
    separate ram, which is only updated when a transaction is deemed
    new.
    
    Output pointer advances only if a transaction has a timestamp newer
    than its corresponding last-seen timestamp.

    The size of the ram is proportional to the span of the reordering
    that occurs.

*/

`default_nettype none

module tid_inorder #(
    W                           = 32,
    D                           = 16,
    D_L                         = $clog2(D),
    W_L                         = $clog2(W)
) (
    input wire [1-1:0]          i_v,
    input wire [D_L-1:0]        i_a,
    input wire [W-1:0]          i_d,
    output logic [1-1:0]        i_f,
    output logic [D_L+1-1:0]    i_c,

    input wire [1-1:0]          o_r,
    output logic [1-1:0]        o_v,
    output logic [W-1:0]        o_d,

    input wire [1-1:0]          clk,
    input wire [1-1:0]          rst
);

logic [64-1:0]                  timestamp;
bit   [64-1:0]                  last_ts;
bit   [64-1:0]                  oo_t;
logic [1-1:0]                   oo_r;
logic [1-1:0]                   oo_v;
logic [W-1:0]                   oo_d;
logic [D_L-1:0]                 oo_a;
logic [D_L-1:0]                 oo_a_n;

assign oo_r                     = o_r | ~o_v;
assign oo_a_n                   = (oo_v & oo_r) ? oo_a + 1 : oo_a;

assign i_f                      = i_c >= D-1;
assign oo_v                     = (oo_t > last_ts);

simple_dual_port_ram #(
    .WRITE_MODE                                     ("read_first"),
    .CLOCKING_MODE                                  ("common_clock"),
    .ADDRESS_WIDTH                                  (D_L),
    .DATA_WIDTH                                     ($bits({timestamp, i_d}))
) ram_inst (
    .wr_clock                                       (clk),
    .wr_address                                     (i_a),
    .wr_en                                          (i_v),
    .wr_byteenable                                  ('1),
    .data                                           ({timestamp, i_d}),

    .rd_clock                                       (clk),
    .rd_address                                     (oo_a_n),
    .q                                              ({oo_t, oo_d}),
    .rd_en                                          (1'b1)
);

simple_dual_port_ram #(
    .WRITE_MODE                                     ("read_first"),
    .CLOCKING_MODE                                  ("common_clock"),
    .ADDRESS_WIDTH                                  (D_L),
    .DATA_WIDTH                                     ($bits({timestamp}))
) ts_ram_inst (
    .wr_clock                                       (clk),
    .wr_address                                     (oo_a),
    .wr_en                                          (oo_v & oo_r),
    .wr_byteenable                                  ('1),
    .data                                           (timestamp),

    .rd_clock                                       (clk),
    .rd_address                                     (oo_a_n),
    .q                                              (last_ts),
    .rd_en                                          (1'b1)
);

always_ff@(posedge clk) begin
    timestamp                   <= timestamp + 1;
    oo_a                        <= oo_a_n;

    if (oo_r) begin
        o_v                     <= oo_v;
        o_d                     <= oo_d;
    end

    case({
        i_v,
        o_v & o_r
    })
        2'b10: i_c              <= i_c + 1;
        2'b01: i_c              <= i_c - 1;
    endcase

    if (rst) begin
        i_c                     <= 0;
        o_v                     <= 0;
        oo_a                    <= 0;
        timestamp               <= 0;
    end
end

always_ff@(posedge clk) if (i_v | o_v) $display("%t: %x %x %b %b %x - %x %x %x", $time
    , i_v
    , i_a
    , i_c
    , i_f
    , i_d

    , o_v
    , o_r
    , o_d
);

endmodule

`default_nettype wire
