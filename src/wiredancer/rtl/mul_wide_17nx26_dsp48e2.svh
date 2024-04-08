
localparam NO_CASCADE = (W1+16)/17;

logic [NO_CASCADE-1:0][W0+17-1:0] Ps;
logic [NO_CASCADE-1:0][48-1:0] Pcouts;

for (genvar g_i = 0; g_i < NO_CASCADE; g_i ++) begin: G_I

logic [30-1:0] ACOUT;
logic [18-1:0] BCOUT;
logic [1-1:0] CARRYCASCOUT;
logic [1-1:0] MULTSIGNOUT;
logic [48-1:0] PCOUT;
      // Control outputs: Control Inputs/Status Bits
logic [1-1:0] OVERFLOW;
logic [1-1:0] PATTERNBDETECT;
logic [1-1:0] PATTERNDETECT;
logic [1-1:0] UNDERFLOW;
      // Data outputs: Data Ports
logic [4-1:0] CARRYOUT;
logic [48-1:0] P;
logic [8-1:0] XOROUT;
      // Cascade inputs: Cascade Ports
logic [30-1:0] ACIN = 0;
logic [18-1:0] BCIN = 0;
logic [1-1:0] CARRYCASCIN = 0;
logic [1-1:0] MULTSIGNIN = 0;
logic [48-1:0] PCIN;
      // Control inputs: Control Inputs/Status Bits
logic [4-1:0] ALUMODE;
logic [3-1:0] CARRYINSEL = 0;
logic [1-1:0] CLK;
logic [5-1:0] INMODE = 0;
logic [9-1:0] OPMODE;
      // Data inputs: Data Ports
logic [30-1:0] A;
logic [18-1:0] B;
logic [48-1:0] C = 0;
logic [1-1:0] CARRYIN = 0;
logic [27-1:0] D = 0;
      // Reset/Clock Enable inputs: Reset/Clock Enable Inputs
logic [1-1:0] CEA1 = 1;
logic [1-1:0] CEA2 = 1;
logic [1-1:0] CEAD = 1;
logic [1-1:0] CEALUMODE = 1;
logic [1-1:0] CEB1 = 1;
logic [1-1:0] CEB2 = 1;
logic [1-1:0] CEC = 1;
logic [1-1:0] CECARRYIN = 1;
logic [1-1:0] CECTRL = 1;
logic [1-1:0] CED = 1;
logic [1-1:0] CEINMODE = 1;
logic [1-1:0] CEM = 1;
logic [1-1:0] CEP = 1;
logic [1-1:0] RSTA;
logic [1-1:0] RSTALLCARRYIN;
logic [1-1:0] RSTALUMODE;
logic [1-1:0] RSTB;
logic [1-1:0] RSTC;
logic [1-1:0] RSTCTRL;
logic [1-1:0] RSTD;
logic [1-1:0] RSTINMODE;
logic [1-1:0] RSTM;
logic [1-1:0] RSTP;

//   DSP48E2   : In order to incorporate this function into the design,
//   Verilog   : the following instance declaration needs to be placed
//  instance   : in the body of the design code.  The instance name
// declaration : (DSP48E2_inst) and/or the port declarations within the
//    code     : parenthesis may be changed to properly reference and
//             : connect this function to the design.  All inputs
//             : and outputs must be connected.

//  <-----Cut code below this line---->

   // DSP48E2: 48-bit Multi-Functional Arithmetic Block
   //          Virtex UltraScale+
   // Xilinx HDL Language Template, version 2020.1

   DSP48E2 #(
      // Feature Control Attributes: Data Path Selection
      .AMULTSEL("A"),                    // Selects A input to multiplier (A, AD)
      .A_INPUT("DIRECT"),                // Selects A input source, "DIRECT" (A port) or "CASCADE" (ACIN port)
      .BMULTSEL("B"),                    // Selects B input to multiplier (AD, B)
      .B_INPUT("DIRECT"),                // Selects B input source, "DIRECT" (B port) or "CASCADE" (BCIN port)
      .PREADDINSEL("A"),                 // Selects input to pre-adder (A, B)
      .RND(48'h000000000000),            // Rounding Constant
      .USE_MULT("MULTIPLY"),             // Select multiplier usage (DYNAMIC, MULTIPLY, NONE)
      .USE_SIMD("ONE48"),                // SIMD selection (FOUR12, ONE48, TWO24)
      .USE_WIDEXOR("FALSE"),             // Use the Wide XOR function (FALSE, TRUE)
      .XORSIMD("XOR24_48_96"),           // Mode of operation for the Wide XOR (XOR12, XOR24_48_96)
      // Pattern Detector Attributes: Pattern Detection Configuration
      .AUTORESET_PATDET("NO_RESET"),     // NO_RESET, RESET_MATCH, RESET_NOT_MATCH
      .AUTORESET_PRIORITY("RESET"),      // Priority of AUTORESET vs. CEP (CEP, RESET).
      .MASK(48'h3fffffffffff),           // 48-bit mask value for pattern detect (1=ignore)
      .PATTERN(48'h000000000000),        // 48-bit pattern match for pattern detect
      .SEL_MASK("MASK"),                 // C, MASK, ROUNDING_MODE1, ROUNDING_MODE2
      .SEL_PATTERN("PATTERN"),           // Select pattern value (C, PATTERN)
      .USE_PATTERN_DETECT("NO_PATDET"),  // Enable pattern detect (NO_PATDET, PATDET)
      // Programmable Inversion Attributes: Specifies built-in programmable inversion on specific pins
      .IS_ALUMODE_INVERTED(4'b0000),     // Optional inversion for ALUMODE
      .IS_CARRYIN_INVERTED(1'b0),        // Optional inversion for CARRYIN
      .IS_CLK_INVERTED(1'b0),            // Optional inversion for CLK
      .IS_INMODE_INVERTED(5'b00000),     // Optional inversion for INMODE
      .IS_OPMODE_INVERTED(9'b000000000), // Optional inversion for OPMODE
      .IS_RSTALLCARRYIN_INVERTED(1'b0),  // Optional inversion for RSTALLCARRYIN
      .IS_RSTALUMODE_INVERTED(1'b0),     // Optional inversion for RSTALUMODE
      .IS_RSTA_INVERTED(1'b0),           // Optional inversion for RSTA
      .IS_RSTB_INVERTED(1'b0),           // Optional inversion for RSTB
      .IS_RSTCTRL_INVERTED(1'b0),        // Optional inversion for RSTCTRL
      .IS_RSTC_INVERTED(1'b0),           // Optional inversion for RSTC
      .IS_RSTD_INVERTED(1'b0),           // Optional inversion for RSTD
      .IS_RSTINMODE_INVERTED(1'b0),      // Optional inversion for RSTINMODE
      .IS_RSTM_INVERTED(1'b0),           // Optional inversion for RSTM
      .IS_RSTP_INVERTED(1'b0),           // Optional inversion for RSTP
      // Register Control Attributes: Pipeline Register Configuration
      .ACASCREG(0),                      // Number of pipeline stages between A/ACIN and ACOUT (0-2)
      .ADREG(0),                         // Pipeline stages for pre-adder (0-1)
      .ALUMODEREG(0),                    // Pipeline stages for ALUMODE (0-1)
      .AREG(0),                          // Pipeline stages for A (0-2)
      .BCASCREG(0),                      // Number of pipeline stages between B/BCIN and BCOUT (0-2)
      .BREG(0),                          // Pipeline stages for B (0-2)
      .CARRYINREG(0),                    // Pipeline stages for CARRYIN (0-1)
      .CARRYINSELREG(0),                 // Pipeline stages for CARRYINSEL (0-1)
      .CREG(0),                          // Pipeline stages for C (0-1)
      .DREG(0),                          // Pipeline stages for D (0-1)
      .INMODEREG(0),                     // Pipeline stages for INMODE (0-1)
      .MREG(1),                          // Multiplier pipeline stages (0-1)
      .OPMODEREG(0),                     // Pipeline stages for OPMODE (0-1)
      .PREG(0)                           // Number of pipeline stages for P (0-1)
   )
   DSP48E2_inst (
      // Cascade outputs: Cascade Ports
      .ACOUT(ACOUT),                   // 30-bit output: A port cascade
      .BCOUT(BCOUT),                   // 18-bit output: B cascade
      .CARRYCASCOUT(CARRYCASCOUT),     // 1-bit output: Cascade carry
      .MULTSIGNOUT(MULTSIGNOUT),       // 1-bit output: Multiplier sign cascade
      .PCOUT(PCOUT),                   // 48-bit output: Cascade output
      // Control outputs: Control Inputs/Status Bits
      .OVERFLOW(OVERFLOW),             // 1-bit output: Overflow in add/acc
      .PATTERNBDETECT(PATTERNBDETECT), // 1-bit output: Pattern bar detect
      .PATTERNDETECT(PATTERNDETECT),   // 1-bit output: Pattern detect
      .UNDERFLOW(UNDERFLOW),           // 1-bit output: Underflow in add/acc
      // Data outputs: Data Ports
      .CARRYOUT(CARRYOUT),             // 4-bit output: Carry
      .P(P),                           // 48-bit output: Primary data
      .XOROUT(XOROUT),                 // 8-bit output: XOR data
      // Cascade inputs: Cascade Ports
      .ACIN(ACIN),                     // 30-bit input: A cascade data
      .BCIN(BCIN),                     // 18-bit input: B cascade
      .CARRYCASCIN(CARRYCASCIN),       // 1-bit input: Cascade carry
      .MULTSIGNIN(MULTSIGNIN),         // 1-bit input: Multiplier sign cascade
      .PCIN(PCIN),                     // 48-bit input: P cascade
      // Control inputs: Control Inputs/Status Bits
      .ALUMODE(ALUMODE),               // 4-bit input: ALU control
      .CARRYINSEL(CARRYINSEL),         // 3-bit input: Carry select
      .CLK(CLK),                       // 1-bit input: Clock
      .INMODE(INMODE),                 // 5-bit input: INMODE control
      .OPMODE(OPMODE),                 // 9-bit input: Operation mode
      // Data inputs: Data Ports
      .A(A),                           // 30-bit input: A data
      .B(B),                           // 18-bit input: B data
      .C(C),                           // 48-bit input: C data
      .CARRYIN(CARRYIN),               // 1-bit input: Carry-in
      .D(D),                           // 27-bit input: D data
      // Reset/Clock Enable inputs: Reset/Clock Enable Inputs
      .CEA1(CEA1),                     // 1-bit input: Clock enable for 1st stage AREG
      .CEA2(CEA2),                     // 1-bit input: Clock enable for 2nd stage AREG
      .CEAD(CEAD),                     // 1-bit input: Clock enable for ADREG
      .CEALUMODE(CEALUMODE),           // 1-bit input: Clock enable for ALUMODE
      .CEB1(CEB1),                     // 1-bit input: Clock enable for 1st stage BREG
      .CEB2(CEB2),                     // 1-bit input: Clock enable for 2nd stage BREG
      .CEC(CEC),                       // 1-bit input: Clock enable for CREG
      .CECARRYIN(CECARRYIN),           // 1-bit input: Clock enable for CARRYINREG
      .CECTRL(CECTRL),                 // 1-bit input: Clock enable for OPMODEREG and CARRYINSELREG
      .CED(CED),                       // 1-bit input: Clock enable for DREG
      .CEINMODE(CEINMODE),             // 1-bit input: Clock enable for INMODEREG
      .CEM(CEM),                       // 1-bit input: Clock enable for MREG
      .CEP(CEP),                       // 1-bit input: Clock enable for PREG
      .RSTA(RSTA),                     // 1-bit input: Reset for AREG
      .RSTALLCARRYIN(RSTALLCARRYIN),   // 1-bit input: Reset for CARRYINREG
      .RSTALUMODE(RSTALUMODE),         // 1-bit input: Reset for ALUMODEREG
      .RSTB(RSTB),                     // 1-bit input: Reset for BREG
      .RSTC(RSTC),                     // 1-bit input: Reset for CREG
      .RSTCTRL(RSTCTRL),               // 1-bit input: Reset for OPMODEREG and CARRYINSELREG
      .RSTD(RSTD),                     // 1-bit input: Reset for DREG and ADREG
      .RSTINMODE(RSTINMODE),           // 1-bit input: Reset for INMODEREG
      .RSTM(RSTM),                     // 1-bit input: Reset for MREG
      .RSTP(RSTP)                      // 1-bit input: Reset for PREG
   );

   // End of DSP48E2_inst instantiation

// always_ff@(posedge clk)
// $display("%t: %m.DSP: %x %x %x %x %x",$time
//    , A
//    , B
//    , P
//    , PCOUT
//    , PCIN);

localparam _W1 = (W1 - (g_i*17)) > 17 ? 17 : W1 - (g_i*17);

assign CLK = clk;

assign ALUMODE = 4'b0000;
assign OPMODE = (g_i == 0 ) ? 9'b00_000_01_01 : 9'b00_101_01_01;
assign A = in0;
// assign B = in1[(NO_CASCADE-1-g_i)*17 +: 17];
assign B = in1[g_i*17 +: _W1];
assign Ps[g_i] = P;
assign Pcouts[g_i] = PCOUT;
if (g_i > 0)
    assign PCIN = Pcouts[g_i-1];

assign out0[g_i*17 +: 17] = P[0 +: 17];

end

localparam LEFTOVER = W0+W1-(NO_CASCADE*17);

if (LEFTOVER > 0)
      assign out0[NO_CASCADE*17 +: LEFTOVER] = Ps[NO_CASCADE-1][17 +: LEFTOVER];
