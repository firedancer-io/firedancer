`default_nettype none

module key_store #(
    D                                       = 512,
    D_L                                     = $clog2(D),
    W                                       = 1
) (
    output logic [1-1:0]                    i_r, // has empty space
    input wire [1-1:0]                      i_v, // push
    output logic [D_L-1:0]                  i_k, // key provided to pusher
    input wire [W-1:0]                      i_d, // data to be stored

    input wire    [1-1:0]                   o_r, // pop
    input wire    [D_L-1:0]                 o_k, // key to pop
    output logic  [W-1:0]                   o_d, // popped data, next cycle

    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

logic [2-1:0]                               idx_st;

logic [2-1:0]                               idx_we;
logic [16-1:0]                              idx_wd [2-1:0];

logic [1-1:0]                               idx_rr;
logic [1-1:0]                               idx_rv;
logic [D_L-1:0]                             idx_rd;

assign i_r                                  = idx_rv;
assign i_k                                  = idx_rd;

assign idx_we[1]                            = o_r;
assign idx_wd[1]                            = o_k;
assign idx_rr                               = i_v & idx_rv;

always_ff@(posedge clk) begin
    case (idx_st)
        // XPM fifo reset wait
        0: begin
            idx_wd[0]                       <= idx_wd[0] + 1;
            if (idx_wd[0] == 1024) begin
                idx_we[0]                   <= 1'b1;
                idx_wd[0]                   <= '0;
                idx_st                      <= 1;
            end
        end
        // fill idx fifo
        1: begin
            idx_wd[0]                       <= idx_wd[0] + 1;
            if (idx_wd[0] == D-1) begin
                idx_we[0]                   <= 1'b0;
                idx_wd[0]                   <= '0;
                idx_st                      <= 2;
            end
        end
        2: begin
        end
    endcase
    if (rst) begin
        idx_st                              <= 0;
        idx_we[0]                           <= 1'b0;
        idx_wd[0]                           <= 0;
    end
end

showahead_fifo #(
    .WIDTH                                  (D_L),
    .DEPTH                                  (D)
) idx_fifo_inst (
    .aclr                                   (rst),

    .wr_clk                                 (clk),
    .wr_req                                 (|idx_we),
    .wr_full                                (),
    .wr_data                                (idx_we[0] ? idx_wd[0] : idx_wd[1]),

    .rd_clk                                 (clk),
    .rd_req                                 (idx_rr),
    .rd_empty                               (),
    .rd_not_empty                           (idx_rv),
    .rd_count                               (),
    .rd_data                                (idx_rd)
);

simple_dual_port_ram #(
    .ADDRESS_WIDTH                          (D_L),
    .DATA_WIDTH                             (W),
    .REGISTER_OUTPUT                        (0),
    .CLOCKING_MODE                          ("common_clock")
) meta_ram_inst(

    .wr_clock                               (clk),
    .wr_address                             (idx_rd),
    .data                                   (i_d),
    .wr_en                                  (idx_rr),

    .rd_clock                               (clk),
    .rd_address                             (o_k),
    .q                                      (o_d),
    .rd_en                                  (1'b1)
);

endmodule

`default_nettype wire

