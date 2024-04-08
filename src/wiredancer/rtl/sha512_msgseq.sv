`default_nettype none


module aux_round_msgseq #(
    DATA_W = 1024,
    WORD_W =   64,
    INST_I =   -1
) (
    input wire    [DATA_W-1:0]  i_data,
    output logic  [DATA_W-1:0]  o_data,
    output logic  [WORD_W-1:0]  o_word,

    input wire      clk,
    input wire      rst
);

assert property (@(posedge clk) (INST_I >=  0)) else begin $display("%m usupported INST_I: %d",INST_I);  $error("INST_I!!");  $fatal; end
assert property (@(posedge clk) (INST_I <  80)) else begin $display("%m usupported INST_I: %d",INST_I);  $error("INST_I!!");  $fatal; end
assert property (@(posedge clk) (DATA_W==1024)) else begin $display("%m usupported DATA_W: %d",DATA_W);  $error("DATA_W!!");  $fatal; end
assert property (@(posedge clk) (WORD_W==  64)) else begin $display("%m usupported WORD_W: %d",WORD_W);  $error("WORD_W!!");  $fatal; end

logic          [WORD_W-1:0]  word;
logic  [16-1:0][WORD_W-1:0]  data;

logic  [WORD_W-1:0]  w2;
logic  [WORD_W-1:0]  w7;
logic  [WORD_W-1:0]  w15;
logic  [WORD_W-1:0]  w16;

logic  [WORD_W-1:0]  a;
logic  [WORD_W-1:0]  b;
logic  [WORD_W-1:0]  c;
logic  [WORD_W-1:0]  d;

assign data = i_data;

generate
    if ( INST_I < 16 ) begin
        assign word = data[INST_I];
    end else begin
        always_comb begin
            w2   = data[14];
            w7   = data[ 9];
            w15  = data[ 1];
            w16  = data[ 0];

            a = { w2[19-1:0], w2[WORD_W-1:19]} ^
                { w2[61-1:0], w2[WORD_W-1:61]} ^
                {       6'd0, w2[WORD_W-1: 6]};
            b = w7;
            c = {w15[ 1-1:0],w15[WORD_W-1: 1]} ^
                {w15[ 8-1:0],w15[WORD_W-1: 8]} ^
                {       7'd0,w15[WORD_W-1: 7]};
            d = w16;
        end
        shift_adder_6 #(
            .W      ( WORD_W ),
            .S0     (   0    ),
            .S1     (   0    ),
            .S2     (   0    ),
            .S3     (   0    ),
            .S4     (   0    ),
            .S5     (   0    ),
            .C      (   0    ),
            .M      (   0    ),
            .R0     (   0    ), /* output of reduction 6-3 (first layer of reduction) */
            .R1     (   0    ), /* output of reduction 3-2 (second layer of reduction)*/
                                /* reduction 2-1 just an adder */
            .R      (   0    )  /* output */
        ) shift_adder_6_inst (
            .clk    (  clk   ),
            .rst    (  rst   ),

            .cin0   (   '0   ),
            .in0    (    a   ),
            .in1    (    b   ),
            .in2    (    c   ),
            .in3    (    d   ),
            .in4    (   '0   ),
            .in5    (   '0   ),
            .out0   (  word  ),

            .m_i    ('0),
            .m_o    (),
            .cout0  ()
        );
    end
endgenerate


always_ff@(posedge clk) begin
    o_word <= word;
    /* INST_I is guaranteed to be in range [0,80) 
        (see the asserts above) */
    if ( INST_I < 16 ) begin
        o_data <= data;
    end else begin
        o_data <= {word, data[16-1:1]};
end end    

endmodule // _round_msgseq






module sha512_msgseq #(
    DATA_W = 1024,
    WORD_W =   64,
    ROUNDS =   80
) (
    input wire    [DATA_W-1:0]  i_data,
    output logic  [WORD_W-1:0]  o_word [ROUNDS-1:0],

    input wire      clk,
    input wire      rst
);

assert property (@(posedge clk) (DATA_W==1024)) else begin $display("%m usupported DATA_W: %d",DATA_W);  $error("DATA_W!!");  $fatal; end
assert property (@(posedge clk) (WORD_W==  64)) else begin $display("%m usupported WORD_W: %d",WORD_W);  $error("WORD_W!!");  $fatal; end
assert property (@(posedge clk) (ROUNDS==  80)) else begin $display("%m usupported ROUNDS: %d",ROUNDS);  $error("ROUNDS!!");  $fatal; end
localparam D_WD_N = DATA_W / WORD_W;
assert property (@(posedge clk) (D_WD_N==  16)) else begin $display("%m usupported D_WD_N: %d",D_WD_N);  $error("D_WD_N!!");  $fatal; end


localparam CYCLES_MSGSEQ = 1;

logic  [DATA_W-1:0] t_data [(ROUNDS+1)-1:0];

/* big-endian convention - from RFC6234:

  "Throughout this document, the "big-endian" convention is used when
  expressing both 32-bit and 64-bit words, so that within each word
  the most significant bit is shown in the leftmost bit position."

  "Again, the "big-endian" convention is used and the most
  significant word is in the leftmost word position for values
  represented by multiple-words."

  "... The
  message or data file should be considered to be a bit string."

  "The words of the message schedule are labeled W0, W1, ..., W79."

  "The input message is padded as described in Section 4.2 above, then
  parsed into 1024-bit blocks that are considered to be composed of
  sixteen 64-bit words M(i)0, M(i)1, ..., M(i)15."

  ------------------------------------
  Example from Section 4.2 of RFC6234:

    Suppose the original message is the bit string:
      01100001 01100010 01100011 01100100 01100101
      (sz = 40bits)
    after padding and size addition, the message (1 block here) becomes:

    61626364 65800000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000028

    This means:
      M(i)0  = 64'h6162636465800000
      M(i)2  = 64'h0000000000000000
      M(i)3  = 64'h0000000000000000
      M(i)4  = 64'h0000000000000000
      M(i)5  = 64'h0000000000000000
      M(i)6  = 64'h0000000000000000
      M(i)7  = 64'h0000000000000000
      M(i)8  = 64'h0000000000000000
      M(i)9  = 64'h0000000000000000
      M(i)10 = 64'h0000000000000000
      M(i)11 = 64'h0000000000000000
      M(i)12 = 64'h0000000000000000
      M(i)13 = 64'h0000000000000000
      M(i)14 = 64'h0000000000000000
      M(i)15 = 64'h0000000000000028

    Then, as a reference, round 0 receives:
      W_0 = M(i)0 = 64'h6162636465800000
      K_0         = 64'h428a2f98d728ae22
  ------------------------------------
*/

integer k;
always_comb begin
    /* big-endian convention (see RFC6234) */
    for (k=0; k<D_WD_N; k++) begin
        t_data[0][WORD_W*k +: WORD_W] = i_data[WORD_W*(D_WD_N-1-k) +: WORD_W];
    end
end

genvar g_w;

generate
    for (g_w = 0; g_w < ROUNDS; g_w ++) begin: G_W

        aux_round_msgseq #(
            .DATA_W     ( DATA_W ),
            .WORD_W     ( WORD_W ),
            .INST_I     ( g_w    )
        ) aux_round_msgseq_inst (
            .i_data     ( t_data [g_w  ] ),
            .o_data     ( t_data [g_w+1] ),
            .o_word     ( o_word [g_w  ] ),

            .clk        ( clk ),
            .rst        ( rst )
        );
    end 
endgenerate


endmodule // sha512_msgseq

`default_nettype wire
