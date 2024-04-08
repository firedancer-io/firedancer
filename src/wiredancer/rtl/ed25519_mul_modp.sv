`default_nettype none

import wd_sigverify::*;

module ed25519_mul_modp #(
    T=32'h007F_CCC2,
    CT = T[0 +: 4],
    ST = T >> 4,
    R_I=0,
    M=128
)(
    input wire                                                      clk,
    input wire                                                      rst,

    input wire [255-1:0]                                            in0,
    input wire [255-1:0]                                            in1,
    input wire [M-1:0]                                              m_i,
    output logic [M-1:0]                                            m_o,
    output logic [255-1:0]                                          out0
);

logic [255-1:0] in0_r;
logic [255-1:0] in1_r;
logic [M-1:0] m_i_r;

generate;
    if (R_I) begin
        always_ff@(posedge clk) in0_r <= in0;
        always_ff@(posedge clk) in1_r <= in1;
        always_ff@(posedge clk) m_i_r <= m_i;
    end else begin
        assign in0_r = in0;
        assign in1_r = in1;
        assign m_i_r = m_i;
    end

    if (CT == 2) begin

localparam A0_R0    = 0;
localparam A0_R1    = 0;
localparam A0_R     = 1;
localparam A0_C     = 0;

localparam A1_R0    = 0;
localparam A1_R1    = 0;
localparam A1_R     = 1;
localparam A1_C     = 0;

localparam A2_R0    = 0;
localparam A2_R1    = 0;
localparam A2_R     = 1;
localparam A2_C     = 1;

localparam A3_R0    = 0;
localparam A3_R1    = 0;
localparam A3_R     = 1;
localparam A3_C     = 1;

localparam A4_R0    = 0;
localparam A4_R1    = 0;
localparam A4_R     = 1;
localparam A4_C     = 1;

logic [128-1:0] c_0_x0, c_0_y0;
logic [127-1:0] c_0_x1, c_0_y1;

logic [129-1:0] c_a_A;
logic [129-1:0] c_a_B;

logic [256-1:0] c_m_C;
logic [254-1:0] c_m_D;

logic [256-1:0] c_ma_C;
logic [254-1:0] c_ma_D;
logic [258-1:0] c_am_M;
logic [260-1:0] c_ma_N;

logic [255+132-1:0] c_maa_E;
logic [255-1:0] c_maa_El;
logic [132-1:0] c_maa_Eh;
logic [256-1:0] c_maab_F;
logic [256-1:0] c_maabc_G;

logic [5-1:0][M-1:0] m_o_p;

piped_adder #(
    .W(128),
    .R(A0_R),
    .C(A0_C),
    .M(1)
) aK_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0(c_0_x0),
    .in1({1'b0, c_0_x1}),
    .out0(c_a_A[0+:128]),
    .cout0(c_a_A[128]),
    .m_i(),
    .m_o()
);
piped_adder #(
    .W(128),
    .R(A0_R),
    .C(A0_C),
    .M(1)
) aL_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0(c_0_y0),
    .in1({1'b0, c_0_y1}),
    .out0(c_a_B[0+:128]),
    .cout0(c_a_B[128]),
    .m_i(),
    .m_o()
);

mul_wide #(.W(128), .T(ST), .M(M))  m0_inst (.clk(clk), .rst(rst), .in0(c_0_x0), .in1(c_0_y0), .out0(c_m_C ), .m_i(m_i), .m_o(m_o_p[0]));
mul_wide #(.W(127), .T(ST))         m1_inst (.clk(clk), .rst(rst), .in0(c_0_x1), .in1(c_0_y1), .out0(c_m_D ), .m_i( '0), .m_o()        );
mul_wide #(.W(129), .T(ST))         m2_inst (.clk(clk), .rst(rst), .in0( c_a_A), .in1( c_a_B), .out0(c_am_M), .m_i( '0), .m_o()        );

shift_adder_3 #(
    .W          (260),
    .S0         (1),
    .S1         (2),
    .S2         (5),
    .M          ($bits({c_m_D, c_m_C, m_o_p[0]})),
    .R0         (A1_R0),
    .R          (A1_R),
    .C          (A1_C)
) a_N_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0({6'h0, c_m_D}),
    .in1({6'h0, c_m_D}),
    .in2({6'h0, c_m_D}),
    .out0(c_ma_N),
    .cout0(),
    .m_i({c_m_D, c_m_C, m_o_p[0]}),
    .m_o({c_ma_D, c_ma_C, m_o_p[1]})
);

shift_adder_6 #(
    .W          (255+132),
    .S0         (0),
    .S1         (0),
    .S2         (128),
    .S3         (128),
    .S4         (128),
    .S5         (128),
    .M          (M),
    .R0         (A2_R0),
    .R1         (A2_R1),
    .R          (A2_R),
    .C          (A2_C)
) a0_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0({140'h0, c_ma_C}),
    .in1({140'h0, c_ma_N}),
    .in2({140'h0, c_am_M}),
    .in3({{400{1'b1}}, ~c_ma_C}),
    .in4({{400{1'b1}}, ~c_ma_D}),
    .in5({400'h2}),
    .out0(c_maa_E),
    .cout0(),
    .m_i(m_o_p[1]),
    .m_o(m_o_p[2])
);

shift_adder_6 #(
    .W          (256),
    .S0         (0),
    .S1         (0),
    .S2         (1),
    .S3         (4),
    .S4         (0),
    .S5         (0),
    .M          (M),
    .R0         (A3_R0),
    .R1         (A3_R1),
    .R          (A3_R),
    .C          (A3_C)
) a1_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0({  1'h0, c_maa_El}),
    .in1({124'h0, c_maa_Eh}),
    .in2({124'h0, c_maa_Eh}),
    .in3({124'h0, c_maa_Eh}),
    .in4({256'h0}),
    .in5({256'h0}),
    .out0(c_maab_F),
    .cout0(),
    .m_i(m_o_p[2]),
    .m_o(m_o_p[3])
);

piped_adder #(
    .W(256),
    .M(M),
    .R(A4_R),
    .C(A4_C)
) a3_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0(c_maab_F),
    .in1(c_maab_F >= ED25519_P ? ED25519_P_N : 256'h0),
    .out0(c_maabc_G),
    .cout0(),
    .m_i(m_o_p[3]),
    .m_o(m_o_p[4])
);

always_comb begin
    c_0_x0 = in0_r[  0+:128];
    c_0_x1 = in0_r[128+:127];
    c_0_y0 = in1_r[  0+:128];
    c_0_y1 = in1_r[128+:127];

    c_maa_El = c_maa_E[  0+:255];
    c_maa_Eh = c_maa_E[255+:132];
end

assign out0 = c_maabc_G;
assign m_o  = m_o_p[4];

// always_ff@(posedge clk) $display("%t: c_a_A: %x", $time, c_a_A);
// always_ff@(posedge clk) $display("%t: c_a_B: %x", $time, c_a_B);

// always_ff@(posedge clk) $display("%t: c_m_C: %x", $time, c_m_C);
// always_ff@(posedge clk) $display("%t: c_m_D: %x", $time, c_m_D);

// always_ff@(posedge clk) $display("%t: c_ma_C: %x", $time, c_ma_C);
// always_ff@(posedge clk) $display("%t: c_ma_D: %x", $time, c_ma_D);
// always_ff@(posedge clk) $display("%t: c_am_M: %x", $time, c_am_M);
// always_ff@(posedge clk) $display("%t: c_ma_N: %x", $time, c_ma_N);
// always_ff@(posedge clk) $display("%t: c_maa_E: %x", $time, c_maa_E);

    end // T2

endgenerate

// always_ff@(posedge clk) $display("%t: %m: %x x %x = %x", $time, in0, in1, out0);


endmodule


`default_nettype wire
