`default_nettype none

module pcie_inorder #(
    ADDR_MASK = 64'hffff_ffff_ffff_ffff,
    ADDR_VAL = 64'h0000_0000_0000_0000,
    W = 512,
    D = 512,
    REG_O = 0,
    W2 = W/2,
    W_L = $clog2(W),
    D_L = $clog2(D)
) (
    input wire [2-1:0]                      pcie_v,
    input wire [64-1:0]                     pcie_a,
    input wire [2-1:0][W2-1:0]              pcie_d,

    output logic [1-1:0]                    out_v,
    output logic [1-1:0]                    out_s,
    input wire [1-1:0]                      out_p,
    output logic [64-1:0]                   out_a,
    output logic [W-1:0]                    out_d,

    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

logic [64-1:0]          timestamp;

logic [1-1:0]           addr_match;

bit   [64-1:0]          last_ts;

logic [1-1:0]           out_iv;
logic [64-1:0]          out_ia;
bit   [2-1:0][64-1:0]   out_a_p;
logic [2-1:0][W2-1:0]   out_d_p;
logic [2-1:0][64-1:0]   out_t_p;

logic [D_L-1:0]         rd_addr;
logic [D_L-1:0]         rd_addr_n;

assign addr_match = (pcie_a & ADDR_MASK) == ADDR_VAL;

assign out_iv           = (out_ia == out_a_p[0]) & (out_ia == out_a_p[1]) & (out_t_p[0] > last_ts) & (out_t_p[1] > last_ts);
assign rd_addr_n        = (out_iv & out_p) ? rd_addr + 1 : rd_addr;

generate

    if (REG_O == 0) begin

        assign out_v = out_iv;
        assign out_a = out_ia;
        assign out_d = out_d_p;
        assign out_s = out_a == ADDR_VAL;

    end else begin

        // assuming out_p==1
        always_ff@(posedge clk) out_v <= out_iv;
        always_ff@(posedge clk) out_a <= out_ia;
        always_ff@(posedge clk) out_d <= out_d_p;
        always_ff@(posedge clk) out_s <= out_ia == ADDR_VAL;

    end

    for (genvar g_i = 0; g_i < 2; g_i ++) begin
        simple_dual_port_ram #(
            .WRITE_MODE                                     ("read_first"),
            .CLOCKING_MODE                                  ("common_clock"),
            .ADDRESS_WIDTH                                  (D_L),
            .DATA_WIDTH                                     ($bits({timestamp, pcie_d[g_i], pcie_a}))
        ) ram_inst (
            .wr_clock                                       (clk),
            .wr_address                                     (pcie_a[W_L-3 +: D_L]),
            .wr_en                                          (pcie_v[g_i] & addr_match),
            .wr_byteenable                                  ('1),
            .data                                           ({timestamp, pcie_d[g_i], pcie_a}),

            .rd_clock                                       (clk),
            .rd_address                                     (rd_addr_n),
            .q                                              ({out_t_p[g_i], out_d_p[g_i], out_a_p[g_i]}),
            .rd_en                                          (1'b1)
        );
    end
endgenerate

simple_dual_port_ram #(
    .WRITE_MODE                                     ("read_first"),
    .CLOCKING_MODE                                  ("common_clock"),
    .ADDRESS_WIDTH                                  (D_L),
    .DATA_WIDTH                                     ($bits({timestamp}))
) ts_ram_inst (
    .wr_clock                                       (clk),
    .wr_address                                     (rd_addr),
    .wr_en                                          (out_iv & out_p),
    .wr_byteenable                                  ('1),
    .data                                           (timestamp),

    .rd_clock                                       (clk),
    .rd_address                                     (rd_addr_n),
    .q                                              (last_ts),
    .rd_en                                          (1'b1)
);

always_ff@(posedge clk) begin
    timestamp <= timestamp + 1;

    if (pcie_v & (pcie_a == ADDR_VAL)) begin
        rd_addr                                             <= 0;
        out_ia                                              <= ADDR_VAL;
    end else begin
        rd_addr                                             <= rd_addr_n;

        if (out_iv & out_p)
            out_ia                                          <= out_ia + (1 << (W_L-3));
    end

    if (rst) begin
        out_ia <= ADDR_VAL;
        timestamp <= 0;
    end
end

// always_ff@(posedge clk)
// if (addr_match & |pcie_v)
// $display("%t: %m.in: %x %x %x - %b %x %x",$time, ADDR_MASK, ADDR_VAL, addr_match, pcie_v, pcie_a, pcie_d);

// always_ff@(posedge clk)
// if (out_iv & out_p)
// $display("%t: %m.out: %x - %x %x - %x %x %x %x - %x %x",$time, rd_addr_n, out_iv, out_p, out_d, out_d_p[0], out_d_p[1], out_a_p, out_t_p, last_ts);

endmodule


`default_nettype wire
