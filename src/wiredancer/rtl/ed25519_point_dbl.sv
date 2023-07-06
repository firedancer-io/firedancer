`default_nettype none

import wd_sigverify::*;

`define ADD(___, _, __)     ed25519_add_modp #(.W(255))          add_modp_``___`` (.clk(clk),  .rst(rst),.in0(_),.in1(__),.out0(___),.m_i('0),.m_o());
`define SUB(___, _, __)     ed25519_sub_modp #(.W(255))          sub_modp_``___`` (.clk(clk),  .rst(rst),.in0(_),.in1(__),.out0(___),.m_i('0),.m_o());
`define MUL(___, _, __)     ed25519_mul_modp #(.T(T))            mul_modp_``___`` (.clk(clk),  .rst(rst),.in0(_),.in1(__),.out0(___),.m_i('0),.m_o());
`define PIP(___, _, __, _W) piped_wire #(.WIDTH(_W),.DEPTH(__))  wide_pip_``___`` (.clk(clk),.reset(rst), .in(_),          .out(___)                );

(* keep_hierarchy = "yes" *) module ed25519_point_dbl #(
    T=32'h007F_CCC2,
    D_M = 15,
    D_A = 4,
    D_S = 2,
    CT = T[0 +: 4],
    ST = T >> 4,
    R_I=0,
    M=128
)(
    input wire                                                      clk,
    input wire                                                      rst,

    input wire [255-1:0]                                            in0_x,
    input wire [255-1:0]                                            in0_y,
    input wire [255-1:0]                                            in0_z,
    input wire [255-1:0]                                            in0_t,
    output logic [255-1:0]                                          out0_x,
    output logic [255-1:0]                                          out0_y,
    output logic [255-1:0]                                          out0_z,
    output logic [255-1:0]                                          out0_t,
    input wire [M-1:0]                                              m_i,
    output logic [M-1:0]                                            m_o
);

logic [255-1:0] R1_s;
logic [255-1:0] R2_s;
logic [255-1:0] R3_a;
logic [255-1:0] R4_a;
logic [255-1:0] R5_sm;
logic [255-1:0] R6_am;
logic [255-1:0] R7_m;
logic [255-1:0] R8_m;
logic [255-1:0] R9_mm;
logic [255-1:0] R5_am;
logic [255-1:0] R10_ma;
logic [255-1:0] R11_ams;
logic [255-1:0] R12_mms;
logic [255-1:0] R13_mma;
logic [255-1:0] R14_ama;
logic [255-1:0] R10_mm;
logic [255-1:0] R11_mma;
logic [255-1:0] R12_mma;
logic [255-1:0] R14_mma;

`SUB(R1_s, in0_y, in0_x)
`ADD(R3_a, in0_y, in0_x)

`MUL(R5_sm, R1_s, R1_s)
`MUL(R6_am, R3_a, R3_a)
`MUL(R7_m, in0_t, in0_t)
`MUL(R8_m, in0_z, in0_z)
`MUL(R9_mm, ED25519_2D, R7_m)

`PIP(R5_am, R5_sm, (D_A+D_M)-(D_S+D_M), 255)

`ADD(R10_ma, R8_m, R8_m)
`SUB(R11_ams, R6_am, R5_am)
`SUB(R12_mms, R10_mm, R9_mm)
`ADD(R13_mma, R10_mm, R9_mm)
`ADD(R14_ama, R6_am, R5_am)

`PIP(R10_mm, R10_ma, D_M-D_A, 255)
`PIP(R11_mma, R11_ams, (D_M+D_M+D_A) - (D_A+D_M+D_S), 255)
`PIP(R12_mma, R12_mms, (D_M+D_M+D_A) - (D_M+D_M+D_S), 255)
`PIP(R14_mma, R14_ama, D_M-D_A, 255)

`MUL(out0_x, R11_mma, R12_mma)
`MUL(out0_y, R13_mma, R14_mma)
`MUL(out0_t, R11_mma, R14_mma)
`MUL(out0_z, R12_mma, R13_mma)

`PIP(m_o, m_i, D_M+D_M+D_A+D_M, M);

endmodule

`undef ADD
`undef SUB
`undef MUL
`undef PIP

`default_nettype wire
