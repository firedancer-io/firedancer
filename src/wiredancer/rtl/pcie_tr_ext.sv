`default_nettype none

import wd_sigverify::*;

module pcie_tr_ext #(
    BUFF_SZ                                             = 1024,
    BUFF_SZ_L                                           = $clog2(BUFF_SZ)
) (
    input wire [1-1:0]                                  pcie_v,
    input wire [512-1:0]                                pcie_d,
    output logic [1-1:0]                                pcie_f, // full
    output logic [BUFF_SZ_L+1-1:0]                      pcie_l, // fill

    output logic [1-1:0]                                o_v,
    input wire   [1-1:0]                                o_r,
    output logic [1-1:0]                                o_e,
    output logic [$bits(sv_meta2_t)-1:0]                o_m0,
    output logic [$bits(pcie_meta_t)-1:0]               o_m1,

    input wire clk,
    input wire rst
);

logic [1-1:0]                                           st_blk;

pcie_meta_t                                             pcie_m;
sv_meta2_t                                              blk_m0;
pcie_meta_t                                             blk_m1;

logic [1-1:0]                                           blk_v;
logic [1-1:0]                                           blk_eop;
logic [5-1:0]                                           blk_c;
logic [5-1:0]                                           blk_tc;

logic [64-1:0]                                          tid;

assign pcie_m                                          = pcie_d;

always_ff@(posedge clk) begin
    case (st_blk)
        0: begin

            blk_v                                   <= 0;
            blk_eop                                 <= 0;
            blk_c                                   <= 1;
            blk_tc                                  <= (pcie_m.size >> 6) + |pcie_m.size[0+:6];

            blk_m1                                  <= pcie_m;

            blk_m0.m.m.tid                          <= tid;
            blk_m0.m.m.src                          <= pcie_m.src;
            blk_m0.m.sig_l                          <= pcie_m.sig_l;
            blk_m0.size                             <= pcie_m.size;
            blk_m0.emp                              <= (512/8) - pcie_m.size;

            if (pcie_v & (pcie_m.magic == PCIE_MAGIC)) begin
                tid                                 <= tid + 1;
                st_blk                              <= 1;
            end
        end
        1: begin
            blk_v                                   <= pcie_v;
            if (blk_c == 1)
                blk_m0.data                         <= {pcie_d[256+:256], blk_m0.m.sig_l};
            else
                blk_m0.data                         <= {pcie_d[256+:256], pcie_d[0+:256]};
            if (pcie_v) begin

                if (blk_c == 1) begin
                    blk_m0.m.sig_h                  <= pcie_d[  0+:256];
                    blk_m0.m.pub                    <= pcie_d[256+:256];
                end

                blk_c                               <= blk_c + 1;
                blk_m0.sop                          <= blk_c == 1;
                blk_eop                             <= blk_c == blk_tc;

                if (blk_c == blk_tc) begin
                    st_blk                          <= 0;
                end
            end
        end
    endcase

    if (rst) begin
        st_blk                                      <= 0;
        blk_v                                       <= 0;
        tid                                         <= 32'hABCD_0000;
    end
end

showahead_fifo #(
    .WIDTH                              ($bits({blk_m1, blk_m0, blk_eop})),
    .DEPTH                              (BUFF_SZ)
) o_fifo_inst (
    .aclr                               (rst),

    .wr_clk                             (clk),
    .wr_req                             (blk_v),
    .wr_full                            (pcie_f),
    .wr_full_b                          (),
    .wr_data                            ({blk_m1, blk_m0, blk_eop}),
    .wr_count                           (pcie_l),

    .rd_clk                             (clk),
    .rd_req                             (o_v & o_r),
    .rd_empty                           (),
    .rd_not_empty                       (o_v),
    .rd_count                           (),
    .rd_data                            ({o_m1, o_m0, o_e})
);

endmodule

`default_nettype wire