`default_nettype none

import wd_sigverify::*;

module ed25519_sub_modp #(
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

assign c_2_AB_ge_p = c_2_AB >= ED25519_P;

logic [1-1:0] c_0_a_lt_b;

assign c_0_a_lt_b = in0 < in1;

shift_adder_3 #(
    .W          (W),
    .S0         (0),
    .S1         (0),
    .S2         (0),
    .C          (1),
    .M          (M),
    .R          (0),
    .R0         (0)
) a3_inst (
    .clk(clk),
    .rst(rst),
    .cin0(1'b1),
    .in0(in0),
    .in1(~in1),
    .in2(c_0_a_lt_b ? ED25519_P : {(W){1'b0}}),
    .out0(out0),
    .cout0(),
    .m_i(m_i),
    .m_o(m_o)
);

// always_ff@(posedge clk) $display("%t: %m: %x - %x = %x", $time, in0, in1, out0);

endmodule

`default_nettype wire
