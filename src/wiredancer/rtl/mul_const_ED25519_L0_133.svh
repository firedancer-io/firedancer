logic [258-1:0] out_p;
logic [258-1:0] out_n;
logic [M-1:0] p_m_o;
logic [M-1:0] n_m_o;
logic [2-1:0][M-1:0] p_m_o_p;
logic [288-1:0] p_s_1_00;
logic [167-1:0] p_s_0_00;
logic [160-1:0] p_s_0_06;
logic [138-1:0] p_s_0_18;
logic [167-1:0] p_s_0_12;
`SHADD_6_1C(167, p_s_0_00,   0,  10,  12,  24,  31,  33, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]});
`SHADD_6_1C(160, p_s_0_06,   0,   5,  10,  12,  15,  26, {160'b0, in0[0+:133]}, {160'b0, in0[0+:133]}, {160'b0, in0[0+:133]}, {160'b0, in0[0+:133]}, {160'b0, in0[0+:133]}, {160'b0, in0[0+:133]});
`SHADD_6_1C(167, p_s_0_12,   0,   5,  18,  21,  23,  33, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]}, {167'b0, in0[0+:133]});
`SHADD_6_1C(138, p_s_0_18,   0,   2,   4,   0,   0,   0, {138'b0, in0[0+:133]}, {138'b0, in0[0+:133]}, {138'b0, in0[0+:133]}, {138'b0, '0}, {138'b0, '0}, {138'b0, '0});
`SHADD_6_1C(288, p_s_1_00,   0,  37,  72, 120,   0,   0, {288'b0, p_s_0_00}, {288'b0, p_s_0_06}, {288'b0, p_s_0_12}, {288'b0, p_s_0_18}, {288'b0, '0}, {288'b0, '0});
assign out_p = p_s_1_00 << 0;
assign p_m_o = p_m_o_p[2-1];
always_ff@(posedge clk) p_m_o_p[0] <= m_i;
always_ff@(posedge clk) p_m_o_p[1] <= p_m_o_p[1-1];
logic [2-1:0][M-1:0] n_m_o_p;
logic [166-1:0] n_s_0_06;
logic [253-1:0] n_s_1_00;
logic [158-1:0] n_s_0_00;
logic [152-1:0] n_s_0_12;
logic [163-1:0] n_s_0_18;
`SHADD_6_1C(158, n_s_0_00,   0,   2,  12,  15,  17,  24, {158'b0, in0[0+:133]}, {158'b0, in0[0+:133]}, {158'b0, in0[0+:133]}, {158'b0, in0[0+:133]}, {158'b0, in0[0+:133]}, {158'b0, in0[0+:133]});
`SHADD_6_1C(166, n_s_0_06,   0,   6,  11,  16,  30,  32, {166'b0, in0[0+:133]}, {166'b0, in0[0+:133]}, {166'b0, in0[0+:133]}, {166'b0, in0[0+:133]}, {166'b0, in0[0+:133]}, {166'b0, in0[0+:133]});
`SHADD_6_1C(152, n_s_0_12,   0,   2,   4,   9,  14,  18, {152'b0, in0[0+:133]}, {152'b0, in0[0+:133]}, {152'b0, in0[0+:133]}, {152'b0, in0[0+:133]}, {152'b0, in0[0+:133]}, {152'b0, in0[0+:133]});
`SHADD_6_1C(163, n_s_0_18,   0,   9,  13,  19,  24,  29, {163'b0, in0[0+:133]}, {163'b0, in0[0+:133]}, {163'b0, in0[0+:133]}, {163'b0, in0[0+:133]}, {163'b0, in0[0+:133]}, {163'b0, in0[0+:133]});
`SHADD_6_1C(253, n_s_1_00,   0,  27,  63,  86,   0,   0, {253'b0, n_s_0_00}, {253'b0, n_s_0_06}, {253'b0, n_s_0_12}, {253'b0, n_s_0_18}, {253'b0, '0}, {253'b0, '0});
assign out_n = n_s_1_00 << 2;
assign n_m_o = n_m_o_p[2-1];
always_ff@(posedge clk) n_m_o_p[0] <= m_i;
always_ff@(posedge clk) n_m_o_p[1] <= n_m_o_p[1-1];
always_ff@(posedge clk) out0 <= out_p - out_n;
always_ff@(posedge clk) m_o <= p_m_o;
