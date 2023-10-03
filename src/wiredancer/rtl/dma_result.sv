`default_nettype none

import wd_sigverify::*;

module dma_result #(
    N_PCIE                                              = 2
) (
    input wire [1-1:0]                                  dma_r,
    output logic [1-1:0]                                dma_v,
    output logic [64-1:0]                               dma_a,
    output logic [64-1:0]                               dma_b,
    input wire [1-1:0]                                  dma_f,
    output logic [256-1:0]                              dma_d,

    input wire [N_PCIE-1:0][1-1:0]                      ext_v,
    input wire [N_PCIE-1:0][1-1:0]                      ext_r,
    input wire [N_PCIE-1:0][1-1:0]                      ext_e,
    input wire [N_PCIE-1:0][$bits(pcie_meta_t)-1:0]     ext_m,

    input wire [N_PCIE-1:0][1-1:0]                      res_v,
    input wire [N_PCIE-1:0][64-1:0]                     res_t,
    input wire [N_PCIE-1:0][1-1:0]                      res_d,
    output logic [N_PCIE-1:0][16-1:0]                   res_c,
    output logic [N_PCIE-1:0][1-1:0]                    res_f,
    output logic [N_PCIE-1:0][1-1:0]                    res_p,

    input wire [64-1:0]                                 priv_base,
    input wire [64-1:0]                                 priv_mask,

    input wire [1-1:0]                                  send_fails,

    input wire clk,
    input wire rst
);

logic [N_PCIE-1:0][1-1:0]               dma_p_r;
logic [N_PCIE-1:0][1-1:0]               dma_p_v;
mcache_pcim_t [N_PCIE-1:0]              dma_p_dab;

logic [64-1:0]                          dma_aa;

assign dma_a                            = {dma_aa[64-1:6], 6'h0};

generate

    for (genvar g_i = 0; g_i < N_PCIE; g_i ++) begin: P_IN

        logic [1-1:0]                       ext_p_v, ext_pp_v;
        pcie_meta_t                         ext_p_m, ext_pp_m;

        logic [1-1:0]                       dma_m_v;
        logic [16-1:0]                      dma_m_ctrl;
        logic [1-1:0]                       res_o_v;
        logic [1-1:0]                       res_o_d;

        assign dma_p_v[g_i]                 = res_o_v & dma_m_v & (|dma_p_dab[g_i].pcim_addr) & (send_fails | res_o_d);
        assign dma_p_dab[g_i].pcim_strb     = dma_p_dab[g_i].pcim_addr[5] ? 64'hFFFF_FFFF_0000_0000 : 64'h0000_0000_FFFF_FFFF;
        assign dma_p_dab[g_i].ctrl[1:0]     = dma_m_ctrl[1:0];
        assign dma_p_dab[g_i].ctrl[2]       = ~res_o_d;
        assign dma_p_dab[g_i].ctrl[15:3]    = dma_m_ctrl[15:3];
        assign dma_p_dab[g_i].tsorig        = '0;
        assign dma_p_dab[g_i].tspub         = '0;

        always_ff@(posedge clk) res_p [g_i] <= dma_p_r[g_i] & dma_p_v[g_i];

        (* dont_touch = "yes" *) piped_wire #(
            .WIDTH                      ($bits({ext_m[g_i], ext_v[g_i] & ext_r[g_i] & ext_e[g_i]})),
            .DEPTH                      (2)
        ) ext_pipe_inst (
            .in                         ({ext_m[g_i], ext_v[g_i] & ext_r[g_i] & ext_e[g_i]}),
            .out                        ({ext_p_m, ext_p_v}),

            .clk                        (clk),
            .reset                      (rst)
        );

        always_ff@(posedge clk) begin
            ext_pp_v                    <= ext_p_v;
            ext_pp_m                    <= ext_p_m;
            ext_pp_m.dma_addr           <= (ext_p_m.dma_addr & priv_mask) + priv_base;
        end

        showahead_fifo #(
            .WIDTH                      ($bits({ext_pp_m.sig_l[0+:64], ext_pp_m.dma_chunk, ext_pp_m.dma_seq, ext_pp_m.dma_addr, ext_pp_m.dma_ctrl, ext_pp_m.dma_size})),
            .DEPTH                      (512)
        ) dma_m_fifo_inst (
            .aclr                       (rst),

            .wr_clk                     (clk),
            .wr_req                     (ext_pp_v),
            .wr_full                    (),
            .wr_full_b                  (),
            .wr_count                   (),
            .wr_data                    ({ext_pp_m.sig_l[0+:64], ext_pp_m.dma_chunk, ext_pp_m.dma_seq, ext_pp_m.dma_addr, ext_pp_m.dma_ctrl, ext_pp_m.dma_size}),

            .rd_clk                     (clk),
            .rd_req                     (dma_m_v & res_o_v & dma_p_r[g_i]),
            .rd_empty                   (),
            .rd_not_empty               (dma_m_v),
            .rd_count                   (),
            .rd_data                    ({dma_p_dab[g_i].sig, dma_p_dab[g_i].chunk, dma_p_dab[g_i].seq, dma_p_dab[g_i].pcim_addr, dma_m_ctrl, dma_p_dab[g_i].sz})
        );

        tid_inorder #(
            .W                          ($bits({res_d[g_i]})),
            .D                          (2048)
        ) tid_inorder_inst (
            .i_v                        (res_v      [g_i]),
            .i_a                        (res_t      [g_i][0+:11]),
            .i_f                        (res_f      [g_i]),
            .i_c                        (res_c      [g_i]),
            .i_d                        (res_d      [g_i]),

            .o_r                        (dma_m_v & res_o_v & dma_p_r[g_i]),
            .o_v                        (res_o_v),
            .o_d                        (res_o_d),

            .clk                        (clk),
            .rst                        (rst)
        );

    end
endgenerate

rrb_merge #(
    .W                                  ($bits({dma_p_dab[0]})),
    .N                                  (N_PCIE)
) dma_merge_inst (
    .i_r                                (dma_p_r),
    .i_v                                (dma_p_v),
    .i_e                                ({N_PCIE{1'b1}}),
    .i_m                                (dma_p_dab),

    .o_r                                (dma_r),
    .o_v                                (dma_v),
    .o_e                                (),
    .o_m                                ({dma_d, dma_b, dma_aa}),

    .clk                                (clk),
    .rst                                (rst)
);

always_ff@(posedge clk)
if (|dma_p_v)
$display("%t: %m: %b %b - %b %b", $time
, dma_p_r
, dma_p_v
, dma_r
, dma_v
);
endmodule


`default_nettype wire
