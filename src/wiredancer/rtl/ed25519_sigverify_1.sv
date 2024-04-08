/*

              +-----------------------------------------------------------+
              |                            SLR                            |
              |                                                           |
              |         +----------+  +-------------------------+         |         +----------+
  ------|R|-------|R|---> CDC-FIFO |-->          DSDP           |---|R|-------|R|---> CDC-FIFO |------->
    |         |         +----------+  +-------------------------+         |         +----------+   ^
    |         |                                                           |                        |
    |         +-----------------------------------------------------------+                        |
    |                                                                                              |
    |                                                                                              |
    |                                          +------+                                            |
    +------------------------------------------> Meta +--------------------------------------------+
                                               +------+

    DSDP runs at a marginally higher clock rate to keep up with the previous 
    stage throughput.

    DSDP is placed in a separate SLR to assist with placement and routing.
    To further assist with timing closure, two sets of registers are used
    before and after SLR corssings.

    Metadata is stored in a key-storage to avoid sending wide metadata
    into DSDP pipeline.

*/


`default_nettype none

import wd_sigverify::*;

module ed25519_sigverify_1 #(
    // parameter logic [32-1:0] MUL_T              = 32'h0000_00802, // 8-cycle mock mul_wide
    parameter logic [32-1:0] MUL_T              = 32'h007F_CCC2,
    parameter integer MUL_D                     = 15,
    parameter integer DSDP_WS                   = 2,
    parameter integer KEY_D                     = 512,
    parameter integer KEY_D_L                   = $clog2(KEY_D)
) (
    output logic [1-1:0]                        i_r,
    input wire [1-1:0]                          i_w,
    input wire [1-1:0]                          i_v,
    input wire [$bits(sv_meta5_t)-1:0]          i_m,

    output logic [1-1:0]                        o_v,
    output logic [$bits(sv_meta6_t)-1:0]        o_m,

    input wire clk,
    input wire rst
);

logic [KEY_D_L-1:0]                             i_k;
logic [2-1:0]                                   i_rr;
sv_meta5_t                                      i_mm;
sv_meta6_t                                      o_mm;

logic [1-1:0]                                   dsdp_o_v;
logic [KEY_D_L-1:0]                             dsdp_o_k;
logic [255-1:0]                                 dsdp_o_Zx;
logic [255-1:0]                                 dsdp_o_Zy;
logic [255-1:0]                                 dsdp_o_Zz;

assign i_r                                      = i_rr[0] & i_rr[1] & (~i_w);
assign i_mm                                     = i_m;
assign o_m                                      = o_mm;

always_ff@(posedge clk) begin
    o_v                                         <= dsdp_o_v;
    o_mm.Zx                                     <= dsdp_o_Zx;
    o_mm.Zy                                     <= dsdp_o_Zy;
    o_mm.Zz                                     <= dsdp_o_Zz;
    if (rst)
        o_v <= 0;
end

key_store #(
    .D                                          (KEY_D),
    .W                                          ($bits({i_mm.os[SCH_O_RES][0], i_mm.os[SCH_O_RX], i_mm.m.m.sig_l, i_mm.m.m.m}))
) keystore_inst (
    .i_r                                        (i_rr[0]),
    .i_v                                        (i_v & i_r),
    .i_k                                        (i_k),
    .i_d                                        ({i_mm.os[SCH_O_RES][0], i_mm.os[SCH_O_RX], i_mm.m.m.sig_l, i_mm.m.m.m}),

    .o_r                                        (dsdp_o_v),
    .o_k                                        (dsdp_o_k),
    .o_d                                        ({o_mm.res, o_mm.Rx, o_mm.sig_l, o_mm.m}),

    .clk                                        (clk),
    .rst                                        (rst)
);

ed25519_sigverify_dsdp_mul #(
    .MUL_T                                      (MUL_T),
    .MUL_D                                      (MUL_D),
    .W_S                                        (DSDP_WS),
    .W_M                                        (KEY_D_L)
) ed25519_sigverify_dsdp_mul_inst (
    .i_r                                        (i_rr[1]),
    .i_v                                        (i_v & i_rr[0] & (~i_w)),
    .i_m                                        (i_k),

    .i_Ax                                       (i_mm.os[SCH_O_AX]),
    .i_Ay                                       (i_mm.m.m.pub[0+:255]),
    .i_Az                                       (255'h1),
    .i_At                                       (i_mm.os[SCH_O_AT]),

    .i_ApGx                                     (i_mm.os[SCH_O_TX]), // A+G
    .i_ApGy                                     (i_mm.os[SCH_O_TY]),
    .i_ApGz                                     (i_mm.os[SCH_O_TZ]),
    .i_ApGt                                     (i_mm.os[SCH_O_TT]),

    .i_As                                       (i_mm.m.h),
    .i_Gs                                       (i_mm.m.m.sig_h),

    .o_v                                        (dsdp_o_v),
    .o_m                                        (dsdp_o_k),

    .o_Cx                                       (dsdp_o_Zx),
    .o_Cy                                       (dsdp_o_Zy),
    .o_Cz                                       (dsdp_o_Zz),
    .o_Ct                                       (),

    .clk                                        (clk),
    .rst                                        (rst)
);

// always_ff@(posedge clk) if (i_v | oo_v[3])
// $display("%t: %m: %x - %x", $time
// , i_t

// , o_t
// );

endmodule

`default_nettype wire
