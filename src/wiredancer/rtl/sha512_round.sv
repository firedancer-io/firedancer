`default_nettype none


module sha512_round #(
    HASH_W  = 512,
    WORD_W  =  64
)(
    input wire    [HASH_W-1:0]  i_hash,
    input wire    [WORD_W-1:0]  i_word,
    input wire    [WORD_W-1:0]  i_cval,

    output logic  [HASH_W-1:0]  o_hash,

    input wire      clk,
    input wire      rst
);

assert property (@(posedge clk) (HASH_W==512)) else begin $display("%m usupported HASH_W: %d",HASH_W);  $error("HASH_W!!");  $fatal; end
assert property (@(posedge clk) (WORD_W== 64)) else begin $display("%m usupported WORD_W: %d",WORD_W);  $error("WORD_W!!");  $fatal; end


localparam CYCLES_ROUND = 1;

logic [WORD_W-1:0] a;
logic [WORD_W-1:0] b;
logic [WORD_W-1:0] c;
logic [WORD_W-1:0] d;
logic [WORD_W-1:0] e;
logic [WORD_W-1:0] f;
logic [WORD_W-1:0] g;
logic [WORD_W-1:0] h;

logic [WORD_W-1:0] w;
logic [WORD_W-1:0] k;

logic [WORD_W-1:0] ma;
logic [WORD_W-1:0] ea;
logic [WORD_W-1:0] ee;
logic [WORD_W-1:0] ch;

logic [WORD_W-1:0] s0;
logic [WORD_W-1:0] s1;
logic [WORD_W-1:0] s2;
logic [WORD_W-1:0] s6;

always_comb begin

    w = i_word;
    k = i_cval;

    {a,b,c,d,e,f,g,h} = i_hash;

    ma = (a&b) ^ (a&c) ^ (b&c);
    ch = (e&f) ^ ((~e)&g);

    ea = {a[28-1:0],a[WORD_W-1:28]} ^ 
         {a[34-1:0],a[WORD_W-1:34]} ^
         {a[39-1:0],a[WORD_W-1:39]};

    ee = {e[14-1:0],e[WORD_W-1:14]} ^ 
         {e[18-1:0],e[WORD_W-1:18]} ^
         {e[41-1:0],e[WORD_W-1:41]};

    s0 = ea + ma;

    /* keep as a reference
        s3 = ch +  h;
        s4 = s3 + ee;
        s5 = s4 +  w;
        s6 = s5 +  k;
        s1 = s0 + s6;
        s2 =  d + s6;     */
    s1 = s0 + s6;
    s2 =  d + s6;
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
) shift_adder_6_s1_inst (
    .clk    (  clk   ),
    .rst    (  rst   ),

    .cin0   (   '0   ),
    .in0    (   ch   ),
    .in1    (    h   ),
    .in2    (   ee   ),
    .in3    (    w   ),
    .in4    (    k   ),
    .in5    (   '0   ),
    .out0   (   s6   ),
    .cout0  (        ),
    .m_i    (        ),
    .m_o    (        )
);

always_ff@(posedge clk) begin
    o_hash <= {s1,a,b,c,s2,e,f,g};
end

endmodule // sha512_round

`default_nettype wire
