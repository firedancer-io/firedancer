`default_nettype none


module sha512_block #(
    DATA_W  = 1024,
    CTRL_W  =    3,
    MSGI_W  =   64,
    HASH_W  =  512,
    WORD_W  =   64
)(
    input wire                  i_valid,
    input wire    [DATA_W-1:0]  i_data,
    input wire    [CTRL_W-1:0]  i_ctrl,
    input wire    [MSGI_W-1:0]  i_msgi,
   
    output logic                o_valid,
    output logic  [MSGI_W-1:0]  o_msgi,
    output logic  [HASH_W-1:0]  o_hash,

    input wire      clk,
    input wire      rst
);

assert property (@(posedge clk) (DATA_W==1024)) else begin $display("%m usupported DATA_W: %d",DATA_W);  $error("DATA_W!!");  $fatal; end
assert property (@(posedge clk) (CTRL_W==   3)) else begin $display("%m usupported CTRL_W: %d",CTRL_W);  $error("CTRL_W!!");  $fatal; end
assert property (@(posedge clk) (HASH_W== 512)) else begin $display("%m usupported HASH_W: %d",HASH_W);  $error("HASH_W!!");  $fatal; end
assert property (@(posedge clk) (WORD_W==  64)) else begin $display("%m usupported WORD_W: %d",WORD_W);  $error("WORD_W!!");  $fatal; end
localparam H_WD_N       = HASH_W / WORD_W;
assert property (@(posedge clk) (H_WD_N==   8)) else begin $display("%m usupported H_WD_N: %d",H_WD_N);  $error("H_WD_N!!");  $fatal; end

localparam N_ROUNDS       = 80;
localparam CYCLES_OHEAD   = 3;
localparam CYCLES_ROUND   = 1; /* Vivado does not support e.g. G_R[0].sha512_round_inst.CYCLES_ROUND; if not instantiated before this statement */
localparam CYCLES_ADDER   = 1;
localparam CYCLES_BLOCK   = CYCLES_OHEAD + N_ROUNDS * CYCLES_ROUND + CYCLES_ADDER;

localparam M_FIFO_DEPTH   = 1<<$clog2(CYCLES_BLOCK + 2);   /* safety margin: +2 (fifos need not be too much larger than the pipeline) */
localparam M_FIFO_WIDTH   = MSGI_W;

localparam CTRL_BIT_FIRST = 2;
localparam CTRL_BIT_MIDD  = 1;
localparam CTRL_BIT_LAST  = 0;

localparam logic [7-1:0] RCOUNT_N = CYCLES_OHEAD + N_ROUNDS * CYCLES_ROUND;
localparam logic [7-1:0] RCOUNT_D = 6;
localparam               RCOUNT_W = $clog2(RCOUNT_N + RCOUNT_D);   /* safety margin: (partial count addition may overflow) */
assert property (@(posedge clk) ($bits(RCOUNT_N)==RCOUNT_W)) else begin $display("%m usupported $bits(RCOUNT_N): %d",$bits(RCOUNT_N));  $error("$bits(RCOUNT_N)!!");  $fatal; end
assert property (@(posedge clk) ($bits(RCOUNT_D)==RCOUNT_W)) else begin $display("%m usupported $bits(RCOUNT_D): %d",$bits(RCOUNT_D));  $error("$bits(RCOUNT_D)!!");  $fatal; end

localparam H_RAM_ADDR_W           = $clog2(RCOUNT_N);
localparam H_RAM_DATA_W           = HASH_W;

/* big-endian convention - from RFC6234:

  "Throughout this document, the "big-endian" convention is used when
  expressing both 32-bit and 64-bit words, so that within each word
  the most significant bit is shown in the leftmost bit position."

  "Again, the "big-endian" convention is used and the most
  significant word is in the leftmost word position for values
  represented by multiple-words."

  "... The
  message or data file should be considered to be a bit string."

  "The words of the message schedule are labeled W0, W1, ..., W79. The
  eight working variables are labeled a, b, c, d, e, f, g, and h. The
  words of the hash value are labeled H(i)0, H(i)1, ..., H(i)7, which
  will hold the initial hash value, H(0), replaced by each successive
  intermediate hash value (after each message block is processed),
  H(i), and ending with the final hash value, H(N) after all N blocks
  are processed.
  The input message is padded as described in Section 4.2 above, then
  parsed into 1024-bit blocks that are considered to be composed of
  sixteen 64-bit words M(i)0, M(i)1, ..., M(i)15. The following
  computations are then performed for each of the N message block."

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

/* big-endian convention (see RFC6234):
    { H(0)7, H(0)6, ... , H(0)0 }
    InitVector[7] = 64'h6a09e667f3bcc908
    InitVector[6] = 64'hbb67ae8584caa73b
    InitVector[5] = 64'h3c6ef372fe94f82b
    InitVector[4] = 64'ha54ff53a5f1d36f1
    InitVector[3] = 64'h510e527fade682d1
    InitVector[2] = 64'h9b05688c2b3e6c1f
    InitVector[1] = 64'h1f83d9abfb41bd6b
    InitVector[0] = 64'h5be0cd19137e2179
*/
logic [H_WD_N-1:0][WORD_W-1:0] InitVector = '{
    64'h6a09e667f3bcc908, /* H(0)0 */
    64'hbb67ae8584caa73b, /* H(0)1 */
    64'h3c6ef372fe94f82b, /* H(0)2 */
    64'ha54ff53a5f1d36f1, /* H(0)3 */
    64'h510e527fade682d1, /* H(0)4 */
    64'h9b05688c2b3e6c1f, /* H(0)5 */
    64'h1f83d9abfb41bd6b, /* H(0)6 */
    64'h5be0cd19137e2179  /* H(0)7 */
};

/* big-endian convention (see RFC6234):
    Constants[ 0] = 64'h428a2f98d728ae22
    Constants[ 1] = 64'h7137449123ef65cd
    ...
    Constants[78] = 64'h5fcb6fab3ad6faec
    Constants[79] = 64'h6c44198c4a475817
*/
logic [WORD_W-1:0] Constants [N_ROUNDS] = '{ 
  64'h428a2f98d728ae22, 64'h7137449123ef65cd, /*  K0,  K1 */
  64'hb5c0fbcfec4d3b2f, 64'he9b5dba58189dbbc, /*  K2,  K3 */
  64'h3956c25bf348b538, 64'h59f111f1b605d019, /*  K4,  K5 */
  64'h923f82a4af194f9b, 64'hab1c5ed5da6d8118, /*  K6,  K7 */
  64'hd807aa98a3030242, 64'h12835b0145706fbe, /*  K8,  K9 */
  64'h243185be4ee4b28c, 64'h550c7dc3d5ffb4e2, /* K10, K11 */
  64'h72be5d74f27b896f, 64'h80deb1fe3b1696b1, /* K12, K13 */
  64'h9bdc06a725c71235, 64'hc19bf174cf692694, /* K14, K15 */
  64'he49b69c19ef14ad2, 64'hefbe4786384f25e3, /* K16, K17 */
  64'h0fc19dc68b8cd5b5, 64'h240ca1cc77ac9c65, /* K18, K19 */
  64'h2de92c6f592b0275, 64'h4a7484aa6ea6e483, /* K20, K21 */
  64'h5cb0a9dcbd41fbd4, 64'h76f988da831153b5, /* K22, K23 */
  64'h983e5152ee66dfab, 64'ha831c66d2db43210, /* K24, K25 */
  64'hb00327c898fb213f, 64'hbf597fc7beef0ee4, /* K26, K27 */
  64'hc6e00bf33da88fc2, 64'hd5a79147930aa725, /* K28, K29 */
  64'h06ca6351e003826f, 64'h142929670a0e6e70, /* K30, K31 */
  64'h27b70a8546d22ffc, 64'h2e1b21385c26c926, /* K32, K33 */
  64'h4d2c6dfc5ac42aed, 64'h53380d139d95b3df, /* K34, K35 */
  64'h650a73548baf63de, 64'h766a0abb3c77b2a8, /* K36, K37 */
  64'h81c2c92e47edaee6, 64'h92722c851482353b, /* K38, K39 */
  64'ha2bfe8a14cf10364, 64'ha81a664bbc423001, /* K40, K41 */
  64'hc24b8b70d0f89791, 64'hc76c51a30654be30, /* K42, K43 */
  64'hd192e819d6ef5218, 64'hd69906245565a910, /* K44, K45 */
  64'hf40e35855771202a, 64'h106aa07032bbd1b8, /* K46, K47 */
  64'h19a4c116b8d2d0c8, 64'h1e376c085141ab53, /* K48, K49 */
  64'h2748774cdf8eeb99, 64'h34b0bcb5e19b48a8, /* K50, K51 */
  64'h391c0cb3c5c95a63, 64'h4ed8aa4ae3418acb, /* K52, K53 */
  64'h5b9cca4f7763e373, 64'h682e6ff3d6b2b8a3, /* K54, K55 */
  64'h748f82ee5defb2fc, 64'h78a5636f43172f60, /* K56, K57 */
  64'h84c87814a1f0ab72, 64'h8cc702081a6439ec, /* K58, K59 */
  64'h90befffa23631e28, 64'ha4506cebde82bde9, /* K60, K61 */
  64'hbef9a3f7b2c67915, 64'hc67178f2e372532b, /* K62, K63 */
  64'hca273eceea26619c, 64'hd186b8c721c0c207, /* K64, K65 */
  64'heada7dd6cde0eb1e, 64'hf57d4f7fee6ed178, /* K66, K67 */
  64'h06f067aa72176fba, 64'h0a637dc5a2c898a6, /* K68, K69 */
  64'h113f9804bef90dae, 64'h1b710b35131c471b, /* K70, K71 */
  64'h28db77f523047d84, 64'h32caab7b40c72493, /* K72, K73 */
  64'h3c9ebe0a15c9bebc, 64'h431d67c49c100d4c, /* K74, K75 */
  64'h4cc5d4becb3e42b6, 64'h597f299cfc657e2a, /* K76, K77 */
  64'h5fcb6fab3ad6faec, 64'h6c44198c4a475817  /* K78, K79 */
};


logic [HASH_W-1:0]            initvec;

logic [1-1:0]                 c00_i_valid;
logic [DATA_W-1:0]            c00_i_data;
logic [CTRL_W-1:0]            c00_i_ctrl;
logic [MSGI_W-1:0]            c00_i_msgi;
logic [HASH_W-1:0]            c00_p_hash;

logic [1-1:0]                 c01_i_valid;
logic [DATA_W-1:0]            c01_i_data;
logic [CTRL_W-1:0]            c01_i_ctrl;
logic [MSGI_W-1:0]            c01_i_msgi;
logic [HASH_W-1:0]            c01_p_hash;

logic [DATA_W-1:0]            c02_i_data;
logic [MSGI_W-1:0]            c02_i_msgi;
logic [M_FIFO_WIDTH-1:0]      c02_m_fifo_data;
logic [1-1:0]                 c02_m_fifo_push;
logic [HASH_W-1:0]            c02_p_hash;

logic [HASH_W-1:0]            c03_p_hash;

logic [RCOUNT_W-1:0]          c93_rcount_p;
logic [RCOUNT_W-1:0]          c93_rcount_m;

logic [H_RAM_ADDR_W-1:0]      c94_h_ram_rd_addr;
logic [1-1:0]                 c94_a_fifo_pop;

logic [H_RAM_DATA_W-1:0]      c96_h_ram_rd_data;

logic [HASH_W-1:0]            c97_p_hash;

logic [HASH_W-1:0]            c98_mux;

logic [M_FIFO_WIDTH-1:0]      c98_m_fifo_data;
logic [1-1:0]                 c98_m_fifo_pop ;

logic [1-1:0]                 c99_o_valid;
logic [MSGI_W-1:0]            c99_o_msgi;
logic [HASH_W-1:0]            c99_o_hash;
logic [H_RAM_ADDR_W-1:0]      c99_h_ram_wr_addr;
logic [H_RAM_DATA_W-1:0]      c99_h_ram_wr_data;
logic [1-1:0]                 c99_h_ram_wr_en  ;


logic [CYCLES_BLOCK-1:0]      piped_isfirst;
logic [CYCLES_BLOCK-1:0]      piped_ismidd ;
logic [CYCLES_BLOCK-1:0]      piped_islast ;

logic [RCOUNT_W-1:0]          rcount;

genvar g_r;
integer i,j,k;

logic [WORD_W-1:0]  t_word [N_ROUNDS-1:0];
logic [HASH_W-1:0]  p_hash [N_ROUNDS-1:0];
logic [HASH_W-1:0]  t_hash [N_ROUNDS-1:0];


// used for simulation only
logic [64-1:0] tstamp;
always_ff@(posedge clk) begin
    if ( rst ) begin
        tstamp          <= '0;
    end else begin
        tstamp          <= tstamp + 1'b1;
end end


always_comb begin
  /* big-endian convention (see RFC6234)*/
  initvec = InitVector;
end

always_comb begin
    c00_i_valid          = i_valid;
    c00_i_data           = i_data; /* big-endian convention (see RFC6234)*/
    c00_i_ctrl           = i_ctrl;
    c00_i_msgi           = i_msgi;
    c00_p_hash           = c99_o_hash;
end

always_ff@(posedge clk) begin
    c01_i_valid         <= c00_i_valid;
    c01_i_data          <= c00_i_data;
    c01_i_ctrl          <= c00_i_ctrl;
    c01_i_msgi          <= c00_i_msgi;
    c01_p_hash          <= c00_p_hash;

    c02_i_data          <= c01_i_data;
    c02_i_msgi          <= c01_i_msgi;
    c02_m_fifo_data     <= c01_i_msgi;
    c02_p_hash          <= c01_p_hash;

    c03_p_hash          <= piped_isfirst[1] ? initvec : c02_p_hash;

    c93_rcount_p        <= rcount +  RCOUNT_D; /* at c92, we are 6 cycles from c98_mux */
    c93_rcount_m        <= rcount - (RCOUNT_N - RCOUNT_D);

    c94_h_ram_rd_addr   <= (c93_rcount_p<RCOUNT_N) ? c93_rcount_p[H_RAM_ADDR_W-1:0] : c93_rcount_m[H_RAM_ADDR_W-1:0];

    c97_p_hash          <= c96_h_ram_rd_data;
    
    c98_mux             <= piped_isfirst[CYCLES_BLOCK-1-2] ? initvec : c97_p_hash;

    c99_o_valid         <= piped_islast[CYCLES_BLOCK-1-1];
    c99_o_msgi          <= c98_m_fifo_data;
    for(j=0; j<H_WD_N; j++) begin
    /* there are H_WD_N independent additions modulo 2^64 */
    c99_o_hash[WORD_W*j +: WORD_W] <= t_hash[N_ROUNDS-1][WORD_W*j +: WORD_W]  + c98_mux[WORD_W*j +: WORD_W];
    end
end

always_comb begin
    c02_m_fifo_push      = piped_isfirst[1] | piped_ismidd[1] | piped_islast[1];

    c94_a_fifo_pop       = piped_isfirst[CYCLES_BLOCK-1-5] | piped_ismidd[CYCLES_BLOCK-1-5] | piped_islast[CYCLES_BLOCK-1-5];

    c98_m_fifo_pop       = piped_isfirst[CYCLES_BLOCK-1-1] | piped_ismidd[CYCLES_BLOCK-1-1] | piped_islast[CYCLES_BLOCK-1-1];

    c99_h_ram_wr_addr    = rcount;
    c99_h_ram_wr_data    = c99_o_hash;
    c99_h_ram_wr_en      = piped_isfirst[CYCLES_BLOCK-1] | piped_ismidd[CYCLES_BLOCK-1];

    o_valid              = c99_o_valid;
    o_msgi               = c99_o_msgi;
    o_hash               = c99_o_hash;
end



always_ff@(posedge clk) begin
    if ( rst ) begin
        piped_isfirst   <= '0;
        piped_ismidd    <= '0;
        piped_islast    <= '0;
    end else begin
        // It is preferred to use the registered version of:
        // c01_i_ctrl and c01_i_valid, assumming that none 
        // of the pipes is ever queried for bit [0]. Otherwise
        // {p[CYCLES_BLOCK-1:0], c00_i_ctrl[...] & c00_i_valid}
        piped_isfirst   <= { piped_isfirst[CYCLES_BLOCK-1:1], c01_i_ctrl[CTRL_BIT_FIRST] & c01_i_valid, 1'b0 };
        piped_ismidd    <= { piped_ismidd [CYCLES_BLOCK-1:1], c01_i_ctrl[CTRL_BIT_MIDD ] & c01_i_valid, 1'b0 };
        piped_islast    <= { piped_islast [CYCLES_BLOCK-1:1], c01_i_ctrl[CTRL_BIT_LAST ] & c01_i_valid, 1'b0 };
end end


always_ff@(posedge clk) begin
    if ( rst ) begin
        rcount          <= '0;
    end else begin
        rcount          <= (rcount < (RCOUNT_N-1))? rcount + 1'b1 : '0;
    end
end



always_comb begin
    p_hash[0] = c03_p_hash;   
    for (i = 1; i < N_ROUNDS; i ++) begin
        p_hash[i] = t_hash[i-1];
    end
end 


sha512_msgseq #(
    .DATA_W     ( DATA_W    ),
    .WORD_W     ( WORD_W    ),
    .ROUNDS     ( N_ROUNDS  )
) sha512_msgseq_inst (
    /* FIXME: CYCLES_MSGSEQ must match CYCLES_ROUND
              c02_i_data is for CYCLES_MSGSEQ=1 
              c01_i_data is for CYCLES_MSGSEQ=2
              if  CYCLES_MSGSEQ > 2, then add register
                stages before feeding the first round !!
                (alternative solutions may exist though) */
    .i_data     ( c02_i_data ), 
    .o_word     ( t_word     ),

    .clk        ( clk ),
    .rst        ( rst )
);


generate
    for (g_r = 0; g_r < N_ROUNDS; g_r ++) begin: G_R
      sha512_round #(
          .HASH_W     ( HASH_W ),
          .WORD_W     ( WORD_W )
      ) sha512_round_inst (
          .i_hash     ( p_hash    [g_r] ),
          .i_word     ( t_word    [g_r] ),
          .i_cval     ( Constants [g_r] ),

          .o_hash     ( t_hash    [g_r] ),

          .clk        ( clk ),
          .rst        ( rst )
      );
    end 
endgenerate


simple_dual_port_ram #(
    .ADDRESS_WIDTH      (H_RAM_ADDR_W),
    .DATA_WIDTH         (H_RAM_DATA_W),
    .REGISTER_OUTPUT    (1),
    .CLOCKING_MODE      ("common_clock")
) p_hash_ram_inst (

    .wr_clock           ( clk ),
    .wr_address         ( c99_h_ram_wr_addr ),
    .wr_en              ( c99_h_ram_wr_en   ),
    .wr_byteenable      (                '1 ),
    .data               ( c99_h_ram_wr_data ),

    .rd_clock           ( clk ),
    .rd_address         ( c94_h_ram_rd_addr ),
    .q                  ( c96_h_ram_rd_data ),
    .rd_en              ( 1'b1 )
);


showahead_fifo #(
    .WIDTH              ( M_FIFO_WIDTH ),
    .DEPTH              ( M_FIFO_DEPTH )
) meta_fifo_inst (
    .aclr               ( rst ),

    .wr_clk             ( clk ),
    .wr_req             ( c02_m_fifo_push ),
    .wr_full            ( ),
    .wr_data            ( c02_m_fifo_data ),

    .rd_clk             ( clk ),
    .rd_req             ( c98_m_fifo_pop  ),
    .rd_empty           ( ), /* FIXME needed? */
    .rd_not_empty       ( ), /* FIXME needed? */
    .rd_count           ( ), /* FIXME needed? */
    .rd_data            ( c98_m_fifo_data )
);


endmodule // sha512_block

`default_nettype wire
