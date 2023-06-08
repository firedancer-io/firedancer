`default_nettype none

module sha512_modq #(
    META_W                                  = 64
) (
    input wire [1-1:0]                      i_v, // valid
    input wire [1-1:0]                      i_f, // first blk
    input wire [4-1:0]                      i_c, // number of blocks
    input wire [1024-1:0]                   i_d, // data
    input wire [META_W-1:0]                 i_t, // transaction id
    output logic [1-1:0]                    i_p, // backpressure is only applied for the first block

    output logic                            o_v,
    output logic  [META_W-1:0]              o_t,
    output logic  [256-1:0]                 o_d,

    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

localparam logic [253-1:0] ED25519_Q = 253'h1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
localparam logic [125-1:0] ED25519_L0 = 125'h14def9dea2f79cd65812631a5cf5d3ed;

logic [1-1:0]                           sha_i_v;
logic [1024-1:0]                        sha_i_d;
logic [META_W-1:0]                      sha_i_t;
logic [1-1:0]                           sha_i_f;
logic [1-1:0]                           sha_i_m;
logic [1-1:0]                           sha_i_l;

logic [1-1:0]                           sha_o_v;
logic [META_W-1:0]                      sha_o_t;
logic [64-1:0][8-1:0]                   sha_o_d;
logic [64-1:0][8-1:0]                   sha_o_dl;

logic [META_W+1-1:0]                    c_s_t;
logic [META_W+1-1:0]                    c_sm0_t;
logic [META_W+1-1:0]                    c_sm0m1_t;
logic [META_W+1-1:0]                    c_sm0m1m2_t;
logic [META_W+1-1:0]                    c_sm0m1m2a_t;
logic [META_W+1-1:0]                    c_sm0m1m2aa_t;
logic [META_W+1-1:0]                    c_sm0m1m2aaa_t;

logic [512-1:0]                         c_s_x;
logic [252-1:0]                         c_s_x0;
logic [252-1:0]                         c_sm0_x0;
logic [252-1:0]                         c_sm0m1_x0;
logic [252-1:0]                         c_sm0m1m2_x0;
logic [260-1:0]                         c_s_x1;

logic [385-1:0]                         c_sm0_y;
logic [252-1:0]                         c_sm0_y0;
logic [252-1:0]                         c_sm0m1_y0;
logic [252-1:0]                         c_sm0m1m2_y0;
logic [133-1:0]                         c_sm0_y1;

logic [258-1:0]                         c_sm0m1_z;
logic [252-1:0]                         c_sm0m1_z0;
logic [252-1:0]                         c_sm0m1m2_z0;
logic [  6-1:0]                         c_sm0m1_z1;

logic [131-1:0]                         c_sm0m1m2_r;

logic [253-1:0]                         c_sm0m1m2a_x0z0;
logic [253-1:0]                         c_sm0m1m2a_y0r;

logic [253-1:0]                         c_sm0m1m2aa_m;
logic [253-1:0]                         c_sm0m1m2aaa_m;

logic [252+1-1:0]                       x0z0;
logic [252+1-1:0]                       y0r;

logic [252+1-1:0]                       m0;
logic [252+1-1:0]                       m1;

sha512_sch #(
    .W_BLK                          (1024),
    .W_M                            (META_W),
    .BLKS_PER_TR                    (11),
    .RAM_D                          (512),
    .N_CYCLES                       (84)//sha512_block_inst.CYCLES_BLOCK)
) sha512_sch_inst (
    .iblk_v                         (i_v),
    .iblk_f                         (i_f),
    .iblk_c                         (i_c),
    .iblk_d                         (i_d),
    .iblk_t                         (i_t),
    .iblk_p                         (i_p),

    .oblk_v                         (sha_i_v),
    .oblk_d                         (sha_i_d),
    .oblk_t                         (sha_i_t),
    .oblk_f                         (sha_i_f),
    .oblk_m                         (sha_i_m),
    .oblk_l                         (sha_i_l),

    .clk                            (clk),
    .rst                            (rst)
);

sha512_block #(
    .DATA_W                         (1024),
    .CTRL_W                         (3),
    .MSGI_W                         (META_W),
    .HASH_W                         (512),
    .WORD_W                         (64)
) sha512_block_inst (
    .i_valid                        (sha_i_v),
    .i_data                         (sha_i_d),
    .i_ctrl                         ({sha_i_f, sha_i_m, sha_i_l}),
    .i_msgi                         (sha_i_t),

    .o_valid                        (sha_o_v),
    .o_msgi                         (sha_o_t),
    .o_hash                         (sha_o_d),

    .clk                            (clk),
    .rst                            (rst)
);

mul_wide #(.W0(260), .W1(125), .T(8'h1F), .M($bits(                                    {c_sm0_x0, c_sm0_t}))) m0_inst (.clk(clk), .rst(rst), .in0(    {c_s_x1}), .in1(), .out0(    c_sm0_y), .m_i(                                {c_s_x0, c_s_t}), .m_o(                                    {c_sm0_x0, c_sm0_t}));
mul_wide #(.W0(133), .W1(125), .T(8'h2F), .M($bits(                    {c_sm0m1_y0, c_sm0m1_x0, c_sm0m1_t}))) m1_inst (.clk(clk), .rst(rst), .in0(  {c_sm0_y1}), .in1(), .out0(  c_sm0m1_z), .m_i(                  {c_sm0_y0, c_sm0_x0, c_sm0_t}), .m_o(                    {c_sm0m1_y0, c_sm0m1_x0, c_sm0m1_t}));
mul_wide #(.W0(  6), .W1(125), .T(8'h3F), .M($bits({c_sm0m1m2_z0, c_sm0m1m2_y0, c_sm0m1m2_x0, c_sm0m1m2_t}))) m2_inst (.clk(clk), .rst(rst), .in0({c_sm0m1_z1}), .in1(), .out0(c_sm0m1m2_r), .m_i({c_sm0m1_z0, c_sm0m1_y0, c_sm0m1_x0, c_sm0m1_t}), .m_o({c_sm0m1m2_z0, c_sm0m1m2_y0, c_sm0m1m2_x0, c_sm0m1m2_t}));

always_ff@(posedge clk) begin

    c_sm0m1m2a_x0z0 <= c_sm0m1m2_x0 + c_sm0m1m2_z0;
    c_sm0m1m2a_y0r <= c_sm0m1m2_y0 + c_sm0m1m2_r;
    c_sm0m1m2a_t <= c_sm0m1m2_t;

    c_sm0m1m2aa_m <= c_sm0m1m2a_x0z0 + (c_sm0m1m2a_x0z0 < c_sm0m1m2a_y0r ? ED25519_Q : '0) - c_sm0m1m2a_y0r;
    c_sm0m1m2aa_t <= c_sm0m1m2a_t;

    c_sm0m1m2aaa_m <= c_sm0m1m2aa_m - (c_sm0m1m2aa_m >= ED25519_Q ? ED25519_Q : '0);
    c_sm0m1m2aaa_t <= c_sm0m1m2aa_t;
end

always_comb begin
    integer i;
    for (i = 0; i < 64; i ++)
        sha_o_dl[i]                 = sha_o_d[64-i-1];
end

always_comb begin
    c_s_x = sha_o_dl;
    c_s_t = {sha_o_t, sha_o_v};

    c_s_x0 = c_s_x[0+:252];
    c_s_x1 = c_s_x[252+:260];

    c_sm0_y0 = c_sm0_y[0+:252];
    c_sm0_y1 = c_sm0_y[252+:133];

    c_sm0m1_z0 = c_sm0m1_z[0+:252];
    c_sm0m1_z1 = c_sm0m1_z[252+:6];

    o_d = c_sm0m1m2aaa_m;
    {o_t, o_v} = c_sm0m1m2aaa_t;
end

// always_ff@(posedge clk) $display("%t: %x %x %x - %x %x %x", $time
//     ,i_v // valid
//     ,i_f // first blk
//     ,i_c // number of blocks
//     ,i_d // data
//     ,i_t // transaction id
//     ,i_p // pop blk
// );
// always_ff@(posedge clk) if (sha_o_v) $display("%t: %m.sha_o: %x %x", $time, sha_o_t, sha_o_d);
// always_ff@(posedge clk) if (o_v) $display("%t: %m.o: %x %x", $time, o_t, o_d);

endmodule

`default_nettype wire
