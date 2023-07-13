`default_nettype none

import wd_sigverify::*;

module ed25519_add_modp #(
    W = 255,
    M=128
)(
    input wire                                                      clk,
    input wire                                                      rst,

    input wire [W-1:0]                                              in0,
    input wire [W-1:0]                                              in1,
    input wire [M-1:0]                                              m_i,
    output logic [M-1:0]                                            m_o,
    output logic [W-1:0]                                            out0
);

logic [M-1:0] m_o_p;
logic [W+1-1:0] c_2_AB;
logic [1-1:0] c_2_AB_ge_p;
logic [1-1:0] out0_;

assign c_2_AB_ge_p = c_2_AB >= ED25519_P;

piped_adder #(
    .W(W+1),
    .R(0),
    .C(1),
    .M(M)
) c0_addmodp_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0({1'b0, in0}),
    .in1({1'b0, in1}),
    .out0(c_2_AB),
    .cout0(),
    .m_i(m_i),
    .m_o(m_o_p)
);
piped_adder #(
    .W(W+1),
    .R(0),
    .C(1),
    .M(M)
) c2_addmodp_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0(c_2_AB),
    .in1(c_2_AB_ge_p ? ED25519_P_N : {(W+1){1'b0}}),
    .out0({out0_, out0}),
    .cout0(),
    .m_i(m_o_p),
    .m_o(m_o)
);

endmodule

`default_nettype wire
