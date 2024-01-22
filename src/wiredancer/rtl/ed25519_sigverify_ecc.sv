`default_nettype none

/*

    Multiple sub-pipelines combined into a single-input single-output 
    pipeline.  Different operations have different depths.  Sub-results
    are combined into a single output at various stages (1, 3, 5, M).





*/

module ed25519_sigverify_ecc #(
    // MUL_T                       = 32'h07F2_BBB0,
    MUL_T                       = 32'h007F_CCC2,
    MUL_D                       = 15,
    W_M                         = 128,
    W_D                         = 256
)(
    input wire [5-1:0]          i_o,
    input wire [W_D-1:0]        i_a,
    input wire [W_D-1:0]        i_b,
    input wire [1-1:0]          i_c,
    input wire [W_M-1:0]        i_m,

    output logic [W_D-1:0]      o_d,
    output logic [W_M-1:0]      o_m,

    input wire                  clk,
    input wire                  rst
);

localparam OP_AND               = 0;
localparam OP_EQ                = 1;
localparam OP_NE                = 2;
localparam OP_GE                = 3;
localparam OP_SHL               = 4;
localparam OP_SHR               = 5;
localparam OP_ADD               = 6;
localparam OP_SUB               = 7;
localparam OP_ADD_MODP          = 8;
localparam OP_SUB_MODP          = 9;
localparam OP_MUL_MODP          = 10;
localparam OP_TERNARY           = 5'h1B;

logic [255-1:0] ED25519_P = 255'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
logic [256-1:0] ED25519_P_N = 256'h1 + ~256'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;

logic [5-1:0]                   c_1_o;
logic [5-1:0]                   c_2_o;
logic [5-1:0]                   c_3_o;
logic [5-1:0]                   c_4_o;

logic [256-1:0]                 c_1_d;
logic [4-1:0][256-1:0]          c_2_d;
logic [256-1:0]                 c_3_d;
logic [2-1:0][256-1:0]          c_4_d;
logic [256-1:0]                 c_5_d;

logic [5-1:0]                   c_m_o;
logic [W_M-1:0]                 c_m_m;

logic [MUL_D-1:0][256-1:0]      c_x_d;
logic [2-1:0][256-1:0]          c_m_d;

always_ff@(posedge clk) begin
    integer i;

    c_1_o                   <= i_o;
    c_2_o                   <= c_1_o;
    c_3_o                   <= c_2_o;
    c_4_o                   <= c_3_o;

    c_2_d[0]                <= c_1_d;
    c_4_d[0]                <= c_3_d;

    c_x_d[6]                <= c_5_d;
    for (i = 7; i < MUL_D; i ++)
        c_x_d[i]            <= c_x_d[i-1];
    c_m_d[0]                <= c_x_d[MUL_D-1];

    case(i_o)
        OP_AND:     c_1_d   <= i_a & i_b;
        OP_EQ:      c_1_d   <= i_a == i_b;
        OP_NE:      c_1_d   <= i_a != i_b;
        OP_GE:      c_1_d   <= i_a >= i_b;
        OP_SHL:     c_1_d   <= {i_a[0+:255], 1'b0};
        OP_SHR:     c_1_d   <= {255'h0, i_a[255]};
        OP_TERNARY: c_1_d   <= i_c ? i_a : i_b;
    endcase

    case (c_2_o)
        OP_ADD:     c_3_d   <= c_2_d[1];
        OP_SUB:     c_3_d   <= c_2_d[2];
        OP_SUB_MODP:c_3_d   <= c_2_d[3];
        default:    c_3_d   <= c_2_d[0];
    endcase

    case (c_4_o)
        OP_ADD_MODP:c_5_d   <= c_4_d[1];
        default:    c_5_d   <= c_4_d[0];
    endcase

    case (c_m_o)
        OP_MUL_MODP:o_d     <= c_m_d[1];
        default:    o_d     <= c_m_d[0];
    endcase

    o_m                     <= c_m_m;

end

// add
piped_adder #(
    .W(W_D),
    .R(0),
    .C(1),
    .M(1)
) c0_add_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0(i_a),
    .in1(i_b),
    .out0(c_2_d[1]),
    .cout0(),
    .m_i('0),
    .m_o()
);

// sub
piped_adder #(
    .W(W_D),
    .R(0),
    .C(1),
    .M(1)
) c0_sub_inst (
    .clk(clk),
    .rst(rst),
    .cin0(1'b1),
    .in0(i_a),
    .in1(~i_b),
    .out0(c_2_d[2]),
    .cout0(),
    .m_i('0),
    .m_o()
);

// sub_modp
logic [1-1:0] c_0_a_lt_b;

assign c_0_a_lt_b = i_a < i_b;

shift_adder_3 #(
    .W          (W_D),
    .S0         (0),
    .S1         (0),
    .S2         (0),
    .C          (1),
    .M          (1),
    .R          (0),
    .R0         (0)
) sub_modp_inst (
    .clk(clk),
    .rst(rst),
    .cin0(1'b1),
    .in0(i_a),
    .in1(~i_b),
    .in2(c_0_a_lt_b ? ED25519_P : {(W_D){1'b0}}),
    .out0(c_2_d[3]),
    .m_i('0),
    .m_o()
);


// add_modp
logic [W_D+1-1:0] c_2_AB;
logic [1-1:0] c_2_AB_ge_p;

assign c_2_AB_ge_p = c_2_AB >= ED25519_P;

piped_adder #(
    .W(W_D+1),
    .R(0),
    .C(1),
    .M(1)
) c0_addmodp_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0({1'b0, i_a}),
    .in1({1'b0, i_b}),
    .out0(c_2_AB),
    .cout0(),
    .m_i('0),
    .m_o()
);
piped_adder #(
    .W(W_D+1),
    .R(0),
    .C(1),
    .M(1)
) c2_addmodp_inst (
    .clk(clk),
    .rst(rst),
    .cin0('0),
    .in0(c_2_AB),
    .in1(c_2_AB_ge_p ? ED25519_P_N : {(W_D+1){1'b0}}),
    .out0(c_4_d[1]),
    .cout0(),
    .m_i('0),
    .m_o()
);

// mul_modp
ed25519_mul_modp #(
    .T(MUL_T),
    .R_I(0),
    .M($bits({i_o, i_m}))
) c0_mul_inst (
    .clk(clk),
    .rst(rst),
    .in0(i_a),
    .in1(i_b),
    .out0(c_m_d[1]),
    .m_i({i_o, i_m}),
    .m_o({c_m_o, c_m_m})
);

endmodule


`default_nettype wire
