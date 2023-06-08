`default_nettype none

module sha512_modq_meta #(
    parameter integer KEY_D                 = 512,
    parameter integer KEY_D_L               = $clog2(KEY_D)
) (
    output logic [1-1:0]                    i_r, // backpressure is only applied for the first block (i_m.f)
    input wire [1-1:0]                      i_w, // wait
    input wire [1-1:0]                      i_v, // valid
    input wire [1-1:0]                      i_e, // last blk
    input wire [$bits(sv_meta3_t)-1:0]      i_m, // meta data

    output logic  [1-1:0]                   o_v,
    output logic  [1-1:0]                   o_e,
    output logic  [$bits(sv_meta4_t)-1:0]   o_m,

    input wire [1-1:0] clk,
    input wire [1-1:0] rst
);

sv_meta3_t                                  i_mm;
sv_meta4_t                                  o_mm;

logic [1-1:0]                               sha_i_r;
logic [1-1:0]                               sha_i_v;
logic [KEY_D_L-1:0]                         sha_i_k;

logic [1-1:0]                               key_i_r;
logic [1-1:0]                               key_i_v;

logic [1-1:0]                               sha_o_v;
logic [KEY_D_L-1:0]                         sha_o_k;
logic [256-1:0]                             sha_o_d;

assign i_r                                  = (i_mm.f & sha_i_r & key_i_r & ~i_w) | (sha_i_r & ~i_mm.f);
assign i_mm                                 = i_m;

assign key_i_v                              = i_mm.f & sha_i_r & i_v & ~i_w;
assign sha_i_v                              = (i_mm.f & key_i_r & i_v & ~i_w) | (i_v & ~i_mm.f);

assign o_e                                  = 1;
assign o_m                                  = o_mm;

always_ff@(posedge clk) begin
    o_v                                     <= sha_o_v;
    o_mm.h                                  <= sha_o_d;
    if (rst)
        o_v <= 0;
end

key_store #(
    .D                                      (KEY_D),
    .W                                      ($bits({i_m}))
) keystore_inst (
    .i_r                                    (key_i_r),
    .i_v                                    (key_i_v),
    .i_k                                    (sha_i_k),
    .i_d                                    ({i_m}),

    .o_r                                    (sha_o_v),
    .o_k                                    (sha_o_k),
    .o_d                                    ({o_mm.m}),

    .clk                                    (clk),
    .rst                                    (rst)
);

sha512_modq #(
    .META_W                                 (KEY_D_L)
) sha512_modq_inst (
    .i_p                                    (sha_i_r), // backpressure is only applied for the first block (i_m.f)
    .i_v                                    (sha_i_v),
    .i_t                                    (sha_i_k), // key
    .i_f                                    (i_mm.f), // first blk
    .i_c                                    (i_mm.c), // number of blocks
    .i_d                                    (i_mm.d), // data

    .o_v                                    (sha_o_v),
    .o_t                                    (sha_o_k),
    .o_d                                    (sha_o_d),

    .clk                                    (clk),
    .rst                                    (rst)
);

endmodule

`default_nettype wire

