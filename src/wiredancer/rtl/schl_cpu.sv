`default_nettype none

/* -- SigVerify Scheduler --

This is a Xilinx Virtex UltraScale+ (VU9P) targeted implementation for scheduling
the runtime of the Solana SigVerify algorithm as a part of the Firedancer consensus
node implementation developed by Jump Crypto

This has been implemented as a simplified N-thread RISC CPU architecture
built around a fixed 256-bit pipeline ALU that schedules the needed runtime
math operations based on a generated fixed instruction stream. The implementation
being generic allowed for a hardware-software codesign process where, combined
with the Python reference implementation that you will find in sw/py/*, gave us
the oppurtunity to optimize the architecture to balance the hardware footprint, 
mathematical complexity and runtime latency/throughput over the course of our 
development (ending up with a very simple and efficient end result design)

There are a few assumptions that this processor makes (after several iterations of
experiments on the architecture), the most significant being that the ALU operations
are all set to a fixed-duration (21 cycles) and that the instruction stream order is
identical for each handled SigVerify calculation. The architecture ended up
non-traditional, as the main instruction pipeline is handled virtually via a set
of parallel state machines rather than being fixed set of stages (our "logical thread"
is effectively a simple state machine managing transitions around input and output
from the ALU containing the math primitives)

Instructions generated from our scipts use a virtual address scheme to specify
operating runtime and have independent physical scratchpad memory space within the
main memories for storing temporary values as needed by the algorithm. This allows
our reference/instruction generation scripts to logically treat the hardware as a
single-threaded process despite having the ability to configurably scale the number
of threads based on physical hardware limitations of the FPGA

A "tag" (logical thread) consists of a metadata including an instruction counter,
support for 4 input hashes from the input bus, a shared set of constants set
during initialization, and 24-slot scratch pad for storing intermediate values
for runtime.  The tags interact with the main memories through a virtual address
space that abstracts the physical memory space allowing us to treat the runtime
as single-threaded in the scripts that generates the instruction stream

The following is the instruction and virtual address translation scheme:
  Instruction:
    { 1 [tern], 4 [op], 6 [INA], 6 [INB], 6 [TERN], 6 [OUT] }
  Memory Range: ( Physical: 0x000 - 0x3FF | Virtual: 0x00 - 0x3B )
      PHY ADDR  |      NAME      | VIRT ADDR |  ACCESS    |      NOTES
    0x000-0x01F | in0 Input Data | 0x00      | read/write | initial input from bus
    0x020-0x03F | in1 Input Data | 0x01      | read/write | initial input from bus
    0x040-0x05F | in2 Input Data | 0x02      | read/write | initial input from bus
    0x060-0x07F | in3 Input Data | 0x03      | read/write | initial input from bus (unused)
    0x080-0x09F | Constant Data  | 0x04-0x23 | read-only  | set at synthesis      
    0x0A0-0x3A0 | Scratch Memory | 0x24-0x3B | read/write | working memory for tag

As this is a traditional (if highly simplified) RISC CPU pipeline, there is a fetch
stage prior to insertion of data into the ALU, where after the virtual
address translation there is a read from the three parallel, synchronized RAMs:

- Two [256-bit] x 1024 dual-port RAMs for A and B input, constant, and working memory
- One [1-bit]   x 1024 distributed memory for Ternary selector input into the ALU

Selection of port A, B, and T is done via instruction and the synchronized
memories are all mirrored via write, allowing for unique-address reads while
having identical internal state (barring the Ternary memory which only stores the
least-significant bit of every write). In addition, each tag being blocking and
having independent physical address spaces allows for an simplified 3 stage
pipeline consisting of FETCH, EXEC, BLOCK

As we are mainly physically resource-bound within the FPGA by the size of the
math primitives (mainly the mul_modp circuit) we physical restrict a max of one
of each operation per CPU and fix our pipeline duration to 21 cycles for all
instructions.  With a more flexible (or a physically larger FPGA) this design
would cater to further math primitives within our ALU and allow for more active
tags to be used without having stalls

The processor can fully fill the ALU's pipeline so we cap the number of tags
to MAX_INFLIGHT (which is our ALU's fixed pipeline depth). This prevents a tag
from "stalling" and getting blocked for 10's of microseconds waiting for
pipeline gaps to appear vs it's priority.  If we add further randomness to the
tag selection at bottlenecks we can increase MAX_INFLIGHT up to NUM_TAGS, however
this will increase the mean latency as primary bottleneck for the entire processor
is the ALU and tags will still stall waiting for ALU pipeline slots to open

Runtime for the final 1153 generated instructions takes ~101us before output starts
to stream to the DSDP block that follows this.  Supported instructions can
be found in ed25519_sigverify_ecc.sv which contains the ALU logic, except for
the "output" instruction (0xC) which writes result values out to the DSDP

Corresponding (non-exhaustive) cocoTB testbech can be found in sim/schl_cpu  */

package schl_pkg;
  parameter SCHL_SM_STATE_SIZE = 4;
  typedef enum bit [SCHL_SM_STATE_SIZE-1:0] {
    ST_INIT  = 4'd0,
    ST_IDLE  = 4'd1, // Wait for new hash
    ST_FETCH = 4'd2, // Read data from memory
    ST_EXEC0 = 4'd3, // Start send data to primitive
    ST_EXEC1 = 4'd4, // Propegate send data to primitive
    ST_BLOCK = 4'd5, // Wait for result from primitive
    ST_JMP   = 4'd6  // Jump to another instr (unused for now)
  } ssm_state_t; 
endpackage  

module shcl_cpu
#(
  MUL_T    = 32'h007F_CCC2,
  MUL_D    = 15,
  W_HASH   = 256,
  W_IN_MEM = 6,
  W_T      = 16,
  MAX_INFLIGHT = (MUL_D+1)+6
)
(
  input var logic clk,
  input var logic rst,

  input var logic [W_HASH-1:0] in_hash_data,
  input var logic              in_hash_valid,
  input var logic [W_T-1:0]    in_hash_ref,
  output    logic              in_hash_ready, 

  output    logic [W_HASH-1:0]   out_hash_data,
  output    logic [W_T-1:0]      out_ref,
  output    logic [W_IN_MEM-1:0] out_d_addr,
  output    logic                out_hash_valid
);

  localparam NUM_PRIMS  = 11 + 1; // 11 math, 1 tern
  localparam W_PRIMS    = $clog2(NUM_PRIMS);
  localparam NUM_TAGS   = 32; // transaction handles == tag
  localparam W_TAGS     = $clog2(NUM_TAGS);
  localparam NUM_OPS    = 16; //max supported ops
  localparam W_OPS      = $clog2(NUM_OPS);

  localparam SZ_MEM      = 1024;
  localparam W_MEM       = $clog2(SZ_MEM);

  localparam NUM_CONSTS = 12;
  parameter bit [W_HASH-1:0] CONST_MEM [12] = {
     256'h0000000000000000000000000000000000000000000000000000000000000000,
     256'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
     256'h0000000000000000000000000000000000000000000000000000000000000001,
     256'h1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
     256'h52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3,
     256'h67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3,
     256'h6666666666666666666666666666666666666666666666666666666666666658,
     256'h216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a,
     256'h2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0,
     256'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec,
     256'h7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
     256'h00000000000000000000000000000000000000000000000000000000000000ff
  };

  localparam ROM_WIDTH = 1 + W_OPS + W_IN_MEM + W_IN_MEM + W_IN_MEM + W_IN_MEM;
  localparam ROM_DEPTH = 512*4; // upper bound, real is 1153
  localparam W_ROM_DEPTH = $clog2(ROM_DEPTH);

  logic [ROM_WIDTH-1:0]   instr_romA_data;
  logic [W_ROM_DEPTH-1:0] instr_romA_addr;
  logic [W_ROM_DEPTH-1:0] instr_romA_addr_d;
  logic                   instr_romA_en;
  logic                   instr_romA_en_d;

  logic [ROM_WIDTH-1:0]   instr_romB_data;
  logic [W_ROM_DEPTH-1:0] instr_romB_addr;
  logic [W_ROM_DEPTH-1:0] instr_romB_addr_d;
  logic                   instr_romB_en;
  logic                   instr_romB_en_d;

  schl_cpu_instr_rom #(
    .ROM_WIDTH ( ROM_WIDTH ),
    .ROM_DEPTH ( ROM_DEPTH )
  ) schl_cpu_instr_rom_inst (
    .clk      ( clk ),
    .rst      ( rst ),

    .a_addr   ( instr_romA_addr ),
    .a_en     ( instr_romA_en ),
    .a_data   ( instr_romA_data ),

    .b_addr   ( instr_romB_addr ),
    .b_en     ( instr_romB_en ),
    .b_data   ( instr_romB_data )
  );

  // Next instruction fetch
  logic [ROM_WIDTH-1:0] next_instr [NUM_TAGS]; // The next instruction to run
  logic [NUM_TAGS-1:0]  next_instr_ready;      // Active high when instruction set
  logic [NUM_TAGS-1:0]  next_instr_req;        // Request next instruction
  logic [NUM_TAGS-1:0]  next_instrA_check;    
  logic [NUM_TAGS-1:0]  next_instrB_check;
  logic [NUM_TAGS-1:0]  next_instrA_tmp;
  logic [NUM_TAGS-1:0]  next_instrB_tmp;
  logic [NUM_TAGS-1:0]  next_instrA_tmp_next;
  logic [NUM_TAGS-1:0]  next_instrB_tmp_next;
  logic [NUM_TAGS-1:0]  next_instr_tmp_mask;

  // Next instruction fetch lookup (helpers)
  logic [NUM_TAGS-1:0] prev_instrA_req;
  logic [NUM_TAGS-1:0] prev_instrA_req_d;
  logic [NUM_TAGS-1:0] prev_instrB_req;
  logic [NUM_TAGS-1:0] prev_instrB_req_d;
  logic [NUM_TAGS-1:0] upper_instr_req;
  logic [NUM_TAGS-1:0] lower_instr_req;
  logic [NUM_TAGS-1:0] upper_instr_req_next;
  logic [NUM_TAGS-1:0] lower_instr_req_next;

  logic [W_ROM_DEPTH-1:0] last_instr;           // Numerically last instruction to run in the ROM
  logic [W_ROM_DEPTH-1:0] instr_addr[NUM_TAGS]; // Current running instruction address in rom (Instruction Pointer)
  assign last_instr = 1153; 

  logic [W_MEM-1:0] init_addr;   // Initialization address to set up constants
  logic [1:0]       in_hash_cnt; // Sequencer for input setting 

  // Instruction helpers
  logic [W_OPS-1:0]    in_tern           [NUM_TAGS]; // Ternary selector (TODO: this isn't really necessary)
  logic [W_OPS-1:0]    in_op             [NUM_TAGS]; // OPcode from Instruction
  logic [W_MEM-1:0]    in_memA_addr      [NUM_TAGS]; // A physical memory address
  logic [W_MEM-1:0]    in_memB_addr      [NUM_TAGS]; // B physical memory address
  logic [W_MEM-1:0]    in_tern_addr      [NUM_TAGS]; // Ternary bit input memory address
  logic [W_MEM-1:0]    in_done_addr      [NUM_TAGS]; // Instruction completion write location
  logic [W_T-1:0]      in_ref            [NUM_TAGS]; // Reference tag set at calc start

  logic [W_IN_MEM-1:0] in_memA_addr_tmp  [NUM_TAGS]; // Virtual A memory addr read from Instruction (helper)
  logic [W_IN_MEM-1:0] in_memB_addr_tmp  [NUM_TAGS]; // Virtual B memory addr read from Instruction (helper)
  logic [W_IN_MEM-1:0] in_tern_addr_tmp  [NUM_TAGS]; // Virtual T memory addr read from Instruction (helper)
  logic [W_IN_MEM-1:0] in_done_addr_tmp  [NUM_TAGS]; // Virtual Done memory addr read from Instruction (helper)
  logic [W_IN_MEM-1:0] pr_done_addr      [NUM_TAGS]; // Previous done address
  logic                pr_done_set       [NUM_TAGS]; 
  logic                jmp_instr         [NUM_TAGS]; // INFO: this isn't used for now
  localparam OP_JMP = 4'hF;

  // Primitive Input connectivity
  logic [W_MEM-1:0]  prim_done_addr;
  logic [W_HASH-1:0] prim_inA_data;
  logic [W_HASH-1:0] prim_inB_data;
  logic              prim_inC_data;
  logic [W_TAGS-1:0] prim_tag;
  logic [W_OPS:0]    prim_op; // {1-in_tern, 4-in_op}
  logic              prim_valid;

  // Primitive Output connectivity
  logic [W_HASH-1:0] prim_out_data;
  logic [W_TAGS-1:0] prim_out_tag;
  logic [W_MEM-1:0]  prim_out_addr;
  logic              prim_out_valid;

  // Scratch Memory
  localparam MEM_CNT = 2; // 2 identical memories for parallel reads, one 1 bit memory for tern (below)
  logic [W_HASH-1:0] mem_d_wr_data;
  logic [W_MEM-1:0]  mem_d_wr_addr;
  logic              mem_d_wr_en;
  logic              mem_t_wr_data;
  logic [W_MEM-1:0]  mem_t_wr_addr;
  logic              mem_t_wr_en;

  logic [W_HASH-1:0] mem_d_rd_data [MEM_CNT];
  logic [W_MEM-1:0]  mem_d_rd_addr [MEM_CNT];
  logic              mem_d_rd_en   [MEM_CNT];
  logic              mem_t_rd_data;
  logic [W_MEM-1:0]  mem_t_rd_addr;
  logic              mem_t_rd_en;

  // Memory Input connectivity
  logic              wrote_in [NUM_TAGS];
  logic              write_in;
  logic              write_in_d;
  logic [W_TAGS-1:0] write_in_addr;
  logic [W_TAGS-1:0] write_in_addr_d;
  logic [W_MEM-1:0]  write_in_done;
  logic [W_MEM-1:0]  write_in_done_tmp;
  logic [W_MEM-1:0]  write_in_done_tmp_d;
  logic [W_MEM-1:0]  write_in_done_d;
  logic [W_OPS:0]    write_in_op; // {1-in_tern, 4-in_op}
  logic [W_OPS:0]    write_in_op_d;

  logic              out_done [NUM_TAGS];

  logic [NUM_TAGS-1:0] rd_data_check;
  logic [NUM_TAGS-1:0] rd_data_tmp;
  logic [W_TAGS-1:0]   rd_data_addr;
  logic                rd_data_addr_en; 
  logic [NUM_TAGS-1:0] rd_data_ready;
  logic [NUM_TAGS-1:0] rd_data_request;

  // State Management (one per tag/calc) 
  import schl_pkg::*;
  ssm_state_t          curr_state  [NUM_TAGS];
  logic                calc_start  [NUM_TAGS];

  logic [NUM_TAGS-1:0] block_valid;
  logic [NUM_TAGS-1:0] block_valid_d;
  logic [NUM_TAGS-1:0] calc_ready;
  logic [NUM_TAGS-1:0] calc_done;
  logic [W_TAGS-1:0]   calc_next;
  logic                calc_next_ready;

  logic [W_HASH-1:0] mem_man_data; 
  logic [W_MEM-1:0]  mem_man_addr; 
  logic [W_TAGS-1:0] mem_man_tag;
  logic              mem_man_valid;
  logic              mem_man_ready;
  logic              init_done;

  assign in_hash_ready = calc_ready != '0 && !mem_man_valid && calc_next_ready;
  always_comb begin
    for (int i=0; i<NUM_TAGS; i++) begin
      /* While we can support NUM_TAG's transactions in flight at a time,
         we are effectively throughput-bound by the primitive pipeline depth
         (which is 21 cycles).  Don't let hashes "hang" by queuing more than
         this by limiting running tags to MAX_INFLIGHT. */
      calc_ready[i] = curr_state[i] == ST_IDLE && i[W_TAGS-1:0] < MAX_INFLIGHT;  
      calc_start[i] = (i == calc_next) && in_hash_valid && in_hash_ready && in_hash_cnt == 2'h2;      // We've gotten 3 input values, start calc
      calc_done [i] = block_valid[i] && (last_instr+1 == instr_addr[i]) && curr_state[i] == ST_BLOCK; // Calculation is done
    end
  end

  // Save input reference value to output at the end 
  always_ff @ (posedge clk) begin
    if(rst) begin
      for( int i=0; i<NUM_TAGS; i++ ) begin
        in_ref[i] <= '0;
      end
    end
    else begin
      for( int i=0; i<NUM_TAGS; i++ ) begin
        if (calc_start[i]) begin
          in_ref[i] <= in_hash_ref; 
        end
      end
    end
  end

  assign calc_next_ready = curr_state[calc_next] == ST_IDLE;
  always_ff @ (posedge clk) begin
    if ( rst ) begin
      calc_next <= '0;
      for (int i=0; i<NUM_TAGS; i++ ) begin
        curr_state[i] <= ST_INIT;
      end
    end
    else begin

      // Figure out the next tag to start
      if ( !calc_next_ready || (in_hash_valid && in_hash_ready && in_hash_cnt == 2'h2) ) begin // Cycle until we find an idle tag (should generally be linear)
        if ( calc_next == NUM_TAGS || calc_next == MAX_INFLIGHT-1 || (init_done && curr_state[0] == ST_INIT)) begin // ... also limit to MAX_INFLIGHT here
          calc_next <= 0; 
        end
        else begin
          calc_next <= calc_next + 1;
        end
      end

      // Main tag statemachine (`NUM_TAGS` in parallel)
      for( int i=0; i<NUM_TAGS; i++) begin
        case (curr_state[i])
          ST_INIT:  if (init_done)        curr_state[i] <= ST_IDLE;  // mainly writes in constants
          ST_IDLE:  if (calc_start[i])    curr_state[i] <= ST_FETCH; // start process
          ST_FETCH: if (rd_data_ready[i]) curr_state[i] <= ST_EXEC0; // fetch next instruction (can prefetch in block)
          ST_EXEC0:                       curr_state[i] <= ST_EXEC1; // read mem to send to block
          ST_EXEC1: begin // wait until memory written into ALU
            if (wrote_in[i]) begin 
              curr_state[i] <= ST_BLOCK;
            end
          end
          ST_BLOCK: begin             // wait until result comes out of ALU and is written back 
            if (block_valid[i]) begin // ... block_valid is complicated (see below)
              if (calc_done[i]) curr_state [i] <= ST_IDLE; 
              else if (next_instr_ready[i] ) begin // Don't advance unless instr ready!
                curr_state[i] <= ST_FETCH;
                //else stay in BLOCK
              end
            end
          end
          ST_JMP:  curr_state[i] <= ST_FETCH; // unused for now
          default: curr_state[i] <= ST_IDLE; // TODO: fatal
        endcase
      end
    end 
  end

  // Physical offset addresses for each tag's scratch memory
  parameter [W_MEM-1:0] SCRATCH_TAG_OFFSET [32] = {10'h000, 10'h018, 10'h030, 10'h048, 10'h060, 10'h078, 10'h090, 10'h0A8, 
                                                   10'h0C0, 10'h0D8, 10'h0F0, 10'h108, 10'h120, 10'h138, 10'h150, 10'h168,
                                                   10'h180, 10'h198, 10'h1B0, 10'h1C8, 10'h1E0, 10'h1F8, 10'h210, 10'h228, 
                                                   10'h240, 10'h258, 10'h270, 10'h288, 10'h2A0, 10'h2B8, 10'h2D0, 10'h2E8}; 
  logic [W_MEM-1:0] s_memA_offset;
  logic [W_MEM-1:0] s_memB_offset;
  logic [W_MEM-1:0] s_tern_offset;
  logic [W_MEM-1:0] s_done_offset;
  logic             fault_inA_mem  [NUM_TAGS];
  logic             fault_inB_mem  [NUM_TAGS];
  logic             fault_tern_mem [NUM_TAGS];
  logic             fault_done_mem [NUM_TAGS];

  always_comb begin
    for (int i=0; i<NUM_TAGS; i++) begin 
    // Combinatorially break-out parts of instruction into helpers
    //(ternary sel) (opcode)    (virtual addrA)     (virtual addrB)       (virtual addrT)     (virtual addrD)
      {in_tern[i],  in_op[i], in_memA_addr_tmp[i], in_memB_addr_tmp[i], in_tern_addr_tmp[i], in_done_addr_tmp[i] } = next_instr[i];

      s_memA_offset = in_memA_addr_tmp[i] - 6'h24; // A input to ALU
      s_memB_offset = in_memB_addr_tmp[i] - 6'h24; // B input to ALU
      s_tern_offset = in_tern_addr_tmp[i] - 6'h24; // Tern selector bit input to ALU
      s_done_offset = in_done_addr_tmp[i] - 6'h24; // Write back address (where to write result into memory)

      /* VIRTUAL ADDRESS FOR A MEMORY */
      if      ( in_memA_addr_tmp[i] == 6'h00) in_memA_addr[i] = 10'h000 + i[W_IN_MEM-1:0]; // in0
      else if ( in_memA_addr_tmp[i] == 6'h01) in_memA_addr[i] = 10'h020 + i[W_IN_MEM-1:0]; // in1
      else if ( in_memA_addr_tmp[i] == 6'h02) in_memA_addr[i] = 10'h040 + i[W_IN_MEM-1:0]; // in2
      else if ( in_memA_addr_tmp[i] == 6'h03) in_memA_addr[i] = 10'h060 + i[W_IN_MEM-1:0]; // in3
      else if ( in_memA_addr_tmp[i] >= 6'h04 && in_memA_addr_tmp[i] <= 6'h23 ) begin       // constant memory
        in_memA_addr[i] = 10'h080 + (in_memA_addr_tmp[i] - 6'h04);
      end
      else begin                                                                           // scratch memory
        in_memA_addr[i] = 10'h0A0 + SCRATCH_TAG_OFFSET[i] + s_memA_offset;
      end

      /* VIRTUAL ADDRESS FOR B MEMORY */
      if      ( in_memB_addr_tmp[i] == 6'h00) in_memB_addr[i] = 10'h000 + i[W_IN_MEM-1:0]; // in0
      else if ( in_memB_addr_tmp[i] == 6'h01) in_memB_addr[i] = 10'h020 + i[W_IN_MEM-1:0]; // in1
      else if ( in_memB_addr_tmp[i] == 6'h02) in_memB_addr[i] = 10'h040 + i[W_IN_MEM-1:0]; // in2
      else if ( in_memB_addr_tmp[i] == 6'h03) in_memB_addr[i] = 10'h060 + i[W_IN_MEM-1:0]; // in3
      else if ( in_memB_addr_tmp[i] >= 6'h04 && in_memB_addr_tmp[i] <= 6'h23) begin        // constant memory
        in_memB_addr[i] = 10'h080 + (in_memB_addr_tmp[i] - 6'h04);
      end
      else begin                                                                           // scratch memory
        in_memB_addr[i] = 10'h0A0 + SCRATCH_TAG_OFFSET[i] + s_memB_offset;
      end

      /* VIRTUAL ADDRESS FOR TERNARY MEMORY */
      if      ( in_tern_addr_tmp[i] == 6'h00) in_tern_addr[i] = 10'h000 + i[W_IN_MEM-1:0]; // in0
      else if ( in_tern_addr_tmp[i] == 6'h01) in_tern_addr[i] = 10'h020 + i[W_IN_MEM-1:0]; // in1
      else if ( in_tern_addr_tmp[i] == 6'h02) in_tern_addr[i] = 10'h040 + i[W_IN_MEM-1:0]; // in2
      else if ( in_tern_addr_tmp[i] == 6'h03) in_tern_addr[i] = 10'h060 + i[W_IN_MEM-1:0]; // in3
      else if ( in_tern_addr_tmp[i] >= 6'h04 && in_tern_addr_tmp[i] <= 6'h23) begin        // constant memory
        in_tern_addr[i] = 10'h080 + (in_tern_addr_tmp[i] - 6'h04);
      end
      else begin                                                                           // scratch memory
        in_tern_addr[i] = 10'h0A0 + SCRATCH_TAG_OFFSET[i] + s_tern_offset;
      end

      /* VIRTUAL ADDRESS FOR OUTPUT MEMORY */
      // note: we can overwrite input memory locations if we want...
      if      ( in_done_addr_tmp[i] == 6'h00) in_done_addr[i] = 10'h000 + i[W_IN_MEM-1:0]; 
      else if ( in_done_addr_tmp[i] == 6'h01) in_done_addr[i] = 10'h020 + i[W_IN_MEM-1:0]; 
      else if ( in_done_addr_tmp[i] == 6'h02) in_done_addr[i] = 10'h040 + i[W_IN_MEM-1:0]; 
      else if ( in_done_addr_tmp[i] == 6'h03) in_done_addr[i] = 10'h060 + i[W_IN_MEM-1:0]; 
      //... otherwise write to scratch memory
      else                                    in_done_addr[i] = 10'h0A0 + SCRATCH_TAG_OFFSET[i] + s_done_offset; 

      // TODO: plumb faults to some failure state, but these are mainly for sim testing
      fault_inA_mem  [i] = in_memA_addr_tmp[i] > 6'h3B;
      fault_inB_mem  [i] = in_memB_addr_tmp[i] > 6'h3B;
      fault_tern_mem [i] = in_tern_addr_tmp[i] > 6'h3B;
      fault_done_mem [i] = in_done_addr_tmp[i] > 6'h3B || in_done_addr_tmp[i] < 6'h24;
    end
  end

  // Save our previous done_addr for later
  always_ff @ (posedge clk) begin
    if (rst) begin
      for(int i=0; i<NUM_TAGS; i++) begin
        pr_done_addr[i] <= '0;
        pr_done_set [i] <= '0;
      end
    end
    else begin
      for(int i=0; i<NUM_TAGS; i++) begin
        if (curr_state[i] == ST_EXEC0) begin
          pr_done_set [i] <= 1'd1;
          pr_done_addr[i] <= in_done_addr_tmp[i];
        end
      end
    end
  end

  /* One of the trickier implementation details with this processor was balancing requests 
     while using all tag slots in order to have access 'fairness' between the them 
     (i.e. to prevent single tags from blocking for microseconds). Barring random access
     there will be an implicit priority across the tags that will lead lowest-priority 
     tags to block due to lack of pipeline gaps available if:
     
     [MAX_INFLIGHT] > [explicit fixed cycle latency of the ALU] 
     
     In this logic tags are prioritized by lsb by selecting the lowest active bit of our
     one-hot request register (see $next_instrA_tmp below). This effect is compounded when 
     the ALU is not a fixed duration between instructions which was the case with our design 
     initially but was changed to improve timing in other areas of the design
    
     In the "next instruction" logic here we create fairness across tags by having 
     the two read ports in the instruciton ROM split between from upper/lower
     tags and allowing for "lower" reads to select "upper" values to read if they are
     idle (and vice-versa). While still having implicit priority to the the lsb tags 
     within $next_instr_req, this logic provides sufficient access bandwidth to not
     lead to any blocking with our final configuration

     If increasing MAX_INFLIGHT beyond the limits explained before, it is advised to 
     use a psuedo-random Galios LFSR in addition to this logic to "deselect" 
     {upper|lower}_instr_req. Adding randomness in this manner was thoroughly 
     tested in a previous implementation and did well to provide further fairness beyond 
     what was necessary for our end result implementation */

  assign lower_instr_req      = next_instr_req & 32'h0000FFFF & ~prev_instrB_req & ~prev_instrB_req_d;
  assign upper_instr_req      = next_instr_req & 32'hFFFF0000 & ~prev_instrA_req & ~prev_instrA_req_d;
  assign lower_instr_req_next = lower_instr_req & ~next_instrA_tmp; // "second lowest"
  assign upper_instr_req_next = upper_instr_req & ~next_instrB_tmp; // "second lowest"

  assign next_instrA_tmp       = lower_instr_req & ~(lower_instr_req - 1); // only Lowest req bit 
  assign next_instrB_tmp       = upper_instr_req & ~(upper_instr_req - 1); 
  assign next_instrA_tmp_next  = lower_instr_req_next & ~(lower_instr_req_next - 1); // only "second lowest" req bit 
  assign next_instrB_tmp_next  = upper_instr_req_next & ~(upper_instr_req_next - 1); 
  assign next_instrA_check     = (next_instrA_tmp) ? next_instrA_tmp : next_instrB_tmp_next; // either read lowest req from A or second lowest req from B
  assign next_instrB_check     = (next_instrB_tmp) ? next_instrB_tmp : next_instrA_tmp_next; // either read lowest req from B or second lowest req from A

  logic [W_TAGS-1:0] next_instrA_check_sel;
  logic [W_TAGS-1:0] next_instrB_check_sel;
  always_comb begin
    for( int i=0; i<NUM_TAGS; i++ ) begin
      jmp_instr[i] = ( in_op[i] == OP_JMP );

      if(i==0) next_instrA_check_sel  = '0;
      else     next_instrA_check_sel |= (next_instrA_check[i]) ? i[W_TAGS-1:0] : '0; // next_instrA_check can _only_ be one tag
      if(i==0) next_instrB_check_sel  = '0;
      else     next_instrB_check_sel |= (next_instrB_check[i]) ? i[W_TAGS-1:0] : '0; // next_instrB_check can _only_ be one tag
    end
  end

  // Next Instruction (pre-)fetch logic 
  always_ff @(posedge clk) begin
    if (rst) begin
      for (int i=0; i<NUM_TAGS; i++) begin 
        next_instr       [i] <= '0;
        instr_addr       [i] <= '0;
        next_instr_req   [i] <= '0;
        next_instr_ready [i] <= '0;
      end
      instr_romA_addr       <= '0;
      instr_romA_addr_d     <= '0;
      instr_romA_en         <= '0;
      instr_romB_addr       <= '0;
      instr_romB_addr_d     <= '0;
      instr_romB_en         <= '0;
      prev_instrA_req       <= '0;
      prev_instrA_req_d     <= '0;
      prev_instrB_req       <= '0;
      prev_instrB_req_d     <= '0;
    end
    else begin
      instr_romA_addr_d <= instr_romA_addr;
      instr_romA_en_d   <= instr_romA_en;
      instr_romB_addr_d <= instr_romB_addr;
      instr_romB_en_d   <= instr_romB_en;

      instr_romA_en   <= |next_instrA_check;                // If there is anything that needs a new instruction (lower 16)
      instr_romA_addr <= instr_addr[next_instrA_check_sel]; // Get the next one (see above)
      instr_romB_en   <= |next_instrB_check;                // If there is anything that needs a new instruction (upper 16)
      instr_romB_addr <= instr_addr[next_instrB_check_sel]; // Get the next one (see above)

      prev_instrA_req   <= (|next_instrA_check) ? next_instrA_tmp : '0;
      prev_instrA_req_d <= prev_instrA_req;

      prev_instrB_req   <= (|next_instrB_check) ? next_instrB_tmp : '0;
      prev_instrB_req_d <= prev_instrB_req;

      // next_instr_ready[i] -> We've fetched the next instruction for [i] and it's ready in next_instr[i]
      for( int i=0; i<NUM_TAGS; i++) begin
        if (curr_state[i] == ST_EXEC0 || curr_state[i] == ST_IDLE || calc_done[i]) begin
          next_instr_ready[i] <= '0;
        end
        else if( !next_instr_ready[i] && instr_romA_addr_d == instr_addr[i] && instr_romA_en_d) begin
          next_instr[i]       <= (instr_romA_addr_d > last_instr) ? '0 : instr_romA_data;
          next_instr_ready[i] <= 1'd1;
        end
        else if( !next_instr_ready[i] && instr_romB_addr_d == instr_addr[i] && instr_romB_en_d) begin
          next_instr[i]       <= (instr_romB_addr_d > last_instr) ? '0 : instr_romB_data;
          next_instr_ready[i] <= 1'd1;
        end
      end

      // request the next instruction for [i]. can be a prefetch'd in ST_BLOCK
      for (int i=0; i<NUM_TAGS; i++) begin
        if ( ( (curr_state[i] == ST_INIT) || (curr_state[i] == ST_IDLE && calc_start[i])) && !next_instr_ready[i] ) begin 
          next_instr_req[i] <= 1'd1;
        end
        else if ( curr_state[i] == ST_EXEC0 ) begin
          next_instr_req [i] <= 1'd1;
        end
        else if ( next_instr_ready[i] || curr_state[i] == ST_IDLE ) begin
          next_instr_req [i] <= 1'd0;
        end
      end

      // Advance the instruction addr[i] (program counter/instruction counter equivalent)
      for (int i=0; i<NUM_TAGS; i++) begin
        if ( curr_state[i] == ST_IDLE ) begin
          instr_addr[i] <= '0;
        end
        else if ( curr_state[i] == ST_EXEC0 ) begin // if requesting, bump the instr_addr
          instr_addr [i] <= (instr_addr[i] == last_instr+1) ? '0 : instr_addr[i] + 1;
        end
        else if ( curr_state[i] == ST_JMP ) begin // directly jump to addr
          instr_addr[i] <= in_memA_addr_tmp[i];
        end
      end
    end
  end

  // Scratch Memory write logic (assume simple dual port memory with seperate read/write)
  always_ff @(posedge clk) begin
    if (rst) begin
      init_done      <= '0;
      init_addr      <= '0;

      in_hash_cnt    <= '0;
      mem_d_wr_data  <= '0;
      mem_d_wr_addr  <= '0; 
      mem_d_wr_en    <= '0; 
    end
    else begin
      if (curr_state[0] == ST_INIT) begin // Write in constants (intialization only happens at startup)
        init_done <= (init_addr == NUM_CONSTS && next_instr_ready == '1); // Consts written into memory and initial instr read for all tags
      
        if( init_addr < NUM_CONSTS) begin
          init_addr     <= init_addr + 1;
          mem_d_wr_data <= CONST_MEM[init_addr];
          mem_d_wr_addr <= init_addr + 10'h080; // First 32*4 slots for inputs
          mem_d_wr_en   <= 1'd1;

          mem_t_wr_data <= CONST_MEM[init_addr][0];
          mem_t_wr_addr <= init_addr + 10'h080; // First 32*4 slots for inputs
          mem_t_wr_en   <= 1'd1;
        end
        else begin
          mem_d_wr_data <= '0;
          mem_d_wr_addr <= '0;
          mem_d_wr_en   <= '0;

          mem_t_wr_data <= '0;
          mem_t_wr_addr <= '0;
          mem_t_wr_en   <= '0;
        end
      end
      // Prioritize writes from ALU over input as we don't want to backpress the pipline...
      else if (mem_man_valid) begin 
        mem_d_wr_data <= mem_man_data;
        mem_d_wr_addr <= mem_man_addr;
        mem_d_wr_en   <= 1'd1;

        mem_t_wr_data <= mem_man_data[0];
        mem_t_wr_addr <= mem_man_addr;
        mem_t_wr_en   <= 1'd1;
      end
      //...otherwise write values in from input if there's something there
      else if (in_hash_valid && in_hash_ready) begin
        if ( in_hash_cnt == 2'd2 ) begin
          in_hash_cnt <= '0;
        end
        else in_hash_cnt <= in_hash_cnt + 2'd1;

        mem_d_wr_data <= in_hash_data;
        mem_t_wr_data <= in_hash_data[0];
        case(in_hash_cnt)
          2'h0: mem_d_wr_addr <= 10'h000 + calc_next;
          2'h1: mem_d_wr_addr <= 10'h020 + calc_next;
          2'h2: mem_d_wr_addr <= 10'h040 + calc_next;
          2'h3: mem_d_wr_addr <= 10'h060 + calc_next; // unused
        endcase
        case(in_hash_cnt)
          2'h0: mem_t_wr_addr <= 10'h000 + calc_next;
          2'h1: mem_t_wr_addr <= 10'h020 + calc_next;
          2'h2: mem_t_wr_addr <= 10'h040 + calc_next;
          2'h3: mem_t_wr_addr <= 10'h060 + calc_next; // unused
        endcase
        mem_d_wr_en   <= 1'd1;
        mem_t_wr_en   <= 1'd1;
      end
      else begin
        mem_d_wr_data <= '0;
        mem_d_wr_addr <= '0;
        mem_d_wr_en   <= '0;

        mem_t_wr_data <= '0;
        mem_t_wr_addr <= '0;
        mem_t_wr_en   <= '0;
      end
    end
  end
  assign mem_man_ready = 1'd1;

  // Advance tag[i] out of the ST_BLOCK stage
  always_comb begin
    for ( int i=0; i<NUM_TAGS; i++ ) begin
      //                    (if we just got our result from ALU)            || (we wrote to out) || (we did either of those already)
      block_valid[i] = (mem_man_valid && mem_man_tag == i && mem_man_ready) ||    out_done[i]    ||       block_valid_d[i]; 
    end
  end

  // keep block_valid[i] active until we advance out of ST_BLOCK
  always_ff @ (posedge clk) begin
    if(rst) begin
      block_valid_d <= '0;
    end
    else begin
      for (int i=0; i<NUM_TAGS; i++) begin
        // We're out of ST_BLOCK...
        if (curr_state[i] == ST_FETCH || curr_state[i] == ST_EXEC0 || curr_state[i] == ST_IDLE) begin
          block_valid_d[i] <= '0;
        end
        //.. or we just had block_valid[i] 
        else if (!block_valid_d[i] && block_valid[i]) begin 
          block_valid_d[i] <= 1'd1;
        end
      end
    end
  end

  assign rd_data_tmp   = (rd_data_request & next_instr_ready) & ~( (rd_data_request & next_instr_ready) - 1 );
  assign rd_data_check = rd_data_tmp;

  // Read data addr select
  always_comb begin
    for (int i=0; i<NUM_TAGS; i++) begin
      if( i==0 ) begin
        if(rd_data_check[0]) begin
          rd_data_addr    = '0;
          rd_data_addr_en = 1'd1;
        end
        else begin
          rd_data_addr    = '0;
          rd_data_addr_en = '0;          
        end
      end
      else begin
        if (rd_data_check[i]) begin
          rd_data_addr    |= i[W_TAGS-1:0];
          rd_data_addr_en |= 1'd1;
        end
        else begin
          rd_data_addr    |= '0;
          rd_data_addr_en |= '0;
        end
      end
    end
  end

  // Memory read logic
  always_ff @ (posedge clk) begin
    if (rst) begin
      for (int i=0; i<MEM_CNT; i++) begin
        mem_d_rd_addr[i] <= '0;
        mem_d_rd_en  [i] <= '0;
      end
      mem_t_rd_addr   <= '0;
      mem_t_rd_en     <= '0;
      for (int i=0; i<NUM_TAGS; i++) begin
        rd_data_ready   [i] <= '0;
        rd_data_request [i] <= '0;
        wrote_in        [i] <= '0;
      end
      write_in          <= '0;
      write_in_addr     <= '0;
      write_in_done     <= '0;
      write_in_done_tmp <= '0;
      write_in_op       <= '0;
    end
    else begin

      for (int i=0; i<NUM_TAGS; i++ ) begin
        //                           (at the start)     (in the fetch state and haven't gotten it yet) 
        if ( !rd_data_request[i] && (calc_start[i] || (curr_state[i] == ST_FETCH && !rd_data_ready[i]))) begin
          rd_data_request[i] <= 1'd1; 
        end
        else if (rd_data_check[i]) begin // if we get it, set to 0
          rd_data_request[i] <= '0;
        end
      end

      for (int i=0; i<NUM_TAGS; i++) begin
        if (calc_start[i]) begin
          rd_data_ready[i] <= '0;
        end
        else if ( rd_data_addr_en && rd_data_addr == i[W_TAGS-1:0]) begin
          rd_data_ready[i] <= 1'd1; // ON THE NEXT CYCLE mem_d_rd_data WILL BE SET
        end
        else if ( curr_state[i] == ST_EXEC1 ) begin //reset request after send is done
          rd_data_ready[i] <= '0;
        end
      end

      // Did we just write in this logic? sequencing for write_in below
      for (int i=0; i<NUM_TAGS;i++) begin
        if (rd_data_addr_en && rd_data_addr == i[W_TAGS-1:0]) begin
          wrote_in[i] <= 1'd1;
        end
        else if (wrote_in[i] && curr_state[i] == ST_EXEC1) begin
          wrote_in[i] <= '0;
        end
      end

      // Read values from memories to write into ALU 
      if ( rd_data_addr_en ) begin
        mem_d_rd_addr[0]        <= in_memA_addr[rd_data_addr];
        mem_d_rd_addr[1]        <= in_memB_addr[rd_data_addr];
        mem_t_rd_addr           <= in_tern_addr[rd_data_addr];
        mem_d_rd_en  [0]        <= 1'd1;
        mem_d_rd_en  [1]        <= 1'd1;
        mem_t_rd_en             <= 1'd1;
        write_in_d              <= 1'd1;
        write_in_addr_d         <= rd_data_addr;
        wrote_in [rd_data_addr] <= 1'd1;
        write_in_done_d         <= in_done_addr[rd_data_addr];
        write_in_done_tmp_d     <= in_done_addr_tmp[rd_data_addr];
        write_in_op_d           <= {in_tern[rd_data_addr], in_op [rd_data_addr]};
      end
      else begin
        mem_d_rd_addr[0]   <= '0;
        mem_d_rd_addr[1]   <= '0;
        mem_t_rd_addr      <= '0;
        mem_d_rd_en  [0]   <= '0;
        mem_d_rd_en  [1]   <= '0;
        mem_t_rd_en        <= '0;
        write_in_d      <= '0;
        write_in_addr_d <= '0;
        write_in_done_d <= '0;
        write_in_op_d   <= '0;
      end 

      // Memory reads take a cycle
      write_in          <= write_in_d;
      write_in_addr     <= write_in_addr_d;
      write_in_done     <= write_in_done_d;
      write_in_op       <= write_in_op_d;
      write_in_done_tmp <= write_in_done_tmp_d;
    end
  end

  // Primitive input, get values from memory read above
  always_ff @(posedge clk) begin
    if (rst) begin
      prim_inA_data  <= '0;
      prim_inB_data  <= '0;
      prim_inC_data  <= '0;
      prim_tag       <= '0;
      prim_op        <= '0;
      prim_done_addr <= '0;
      prim_valid     <= '0;
    end
    else begin
      // If we're not writing out to out_hash*, write into ALU 
      if ( write_in && write_in_op != 6'hC ) begin
        prim_inA_data  <= mem_d_rd_data[0];
        prim_inB_data  <= mem_d_rd_data[1];
        prim_inC_data  <= mem_t_rd_data;
        prim_tag       <= write_in_addr;
        prim_op        <= write_in_op;
        prim_done_addr <= write_in_done;
        prim_valid     <= 1'd1;
      end
      else begin
        prim_inA_data  <= '0;
        prim_inB_data  <= '0;
        prim_inC_data  <= '0;
        prim_tag       <= '0;
        prim_op        <= '0;
        prim_done_addr <= '0;
        prim_valid     <= '0;
      end
    end

    for(int i=0; i<NUM_TAGS; i++) begin
      if ( write_in && write_in_op == 5'hC && write_in_addr == i[W_TAGS-1:0] ) begin
        out_done[i] <= 1'd1;
      end
      else if ( curr_state[i] == ST_IDLE || (out_done[i] && curr_state[i] == ST_BLOCK && next_instr_ready[i] )) begin
        out_done[i] <= '0;
      end
    end

    if ( write_in && write_in_op == 6'hC ) begin // OUTPUT INSTR (0xC)
      out_hash_data  <= mem_d_rd_data[0];
      out_ref        <= in_ref [write_in_addr];
      out_d_addr     <= write_in_done_tmp;
      out_hash_valid <= 1'd1;
    end
    else begin
      out_hash_data  <= '0;
      out_ref        <= '0;
      out_d_addr     <= '0;
      out_hash_valid <= '0;
    end
  end 

  // ALU instantiation, see ed25519_sigverify_ecc.sv for more details
  ed25519_sigverify_ecc #(
    .MUL_T(MUL_T),
    .MUL_D(MUL_D),
    .W_M(1+W_TAGS+W_MEM),
    .W_D(256)
  ) prims (
    .clk(clk),
    .rst(rst),

    .i_o (prim_op),
    .i_a (prim_inA_data),
    .i_b (prim_inB_data),
    .i_c (prim_inC_data),
    .i_m ({prim_valid, prim_tag, prim_done_addr}),

    .o_d(prim_out_data),
    .o_m({prim_out_valid, prim_out_tag, prim_out_addr}) );

  // Output staging, seem mem_man* above for write-back logic 
  always_ff @(posedge clk) begin
    if (rst) begin
      mem_man_addr  <= '0;
      mem_man_data  <= '0;
      mem_man_valid <= '0;
      mem_man_tag   <= '0;
    end
    else begin
      if (prim_out_valid) begin
        mem_man_addr  <= prim_out_addr;
        mem_man_data  <= prim_out_data;
        mem_man_valid <= 1'd1;
        mem_man_tag   <= prim_out_tag;
      end
      else begin
        mem_man_addr  <= '0;
        mem_man_data  <= '0;
        mem_man_valid <= '0;
        mem_man_tag   <= '0;
      end
    end
  end


// MemA and MemB
genvar x;
generate
  for (x=0; x<2; x++) begin : MEMGEN
      simple_dual_port_ram #(
          .ADDRESS_WIDTH      (W_MEM),
          .DATA_WIDTH         (W_HASH),
          .REGISTER_OUTPUT    (0),
          .CLOCKING_MODE      ("common_clock")
      ) calc_mem (

          .wr_clock           ( clk ),
          .wr_address         ( mem_d_wr_addr ),
          .data               ( mem_d_wr_data ),
          .wr_en              ( mem_d_wr_en   ),

          .rd_clock           ( clk ),
          .rd_address         ( mem_d_rd_addr [x] ),
          .q                  ( mem_d_rd_data [x] ),
          .rd_en              ( mem_d_rd_en   [x] ));
    end

endgenerate

// Ternary bit memory (distributed logic)
logic tern_mem [SZ_MEM];
always_ff @(posedge clk) begin
  if (rst) begin
    for (int i=0; i<SZ_MEM; i++) begin
      tern_mem[i] <= '0;
    end
    mem_t_rd_data   <= '0;
  end
  else begin
    if (mem_t_wr_en) tern_mem[mem_t_wr_addr] <= mem_t_wr_data;
    if (mem_t_rd_en) mem_t_rd_data           <= tern_mem[mem_t_rd_addr];
  end
end

endmodule


// Dummy top level for simulation
module schl #
(
// Input width
  W_HASH = 256
)
(
  input var logic clk,
  input var logic rst,

  // Input from 
  input var logic [W_HASH-1:0] i_hash,
  input var logic              i_valid,
  output    logic              i_ready,

  // Result Ouput 
  output logic [W_HASH-1:0] o_hash,
  output logic              o_valid,
  output logic              o_correct 
);

    logic [W_HASH-1:0] fifo_data_out;
    logic [W_HASH-1:0] input_hash;
    logic              input_valid;
    logic              full;
    logic              in_hash_ready;

    assign i_ready = !full;

    // cocotb can't do same-cycle value toggling wrt input ready so
    // dump a big dumb fifo in the front of the cpu input
    showahead_fifo #(
        .WIDTH              ( W_HASH ),
        .DEPTH              ( 2048 ) 
    ) fake_input_fifo (
        .aclr               ( rst ),

        .wr_clk             ( clk ),
        .wr_req             ( i_valid ),
        .wr_full            ( full ),
        .wr_data            ( i_hash ),
        .wr_count           ( ),

        .rd_clk             ( clk ),
        .rd_req             ( in_hash_ready && input_valid ),
        .rd_empty           ( ),
        .rd_not_empty       ( input_valid ), 
        .rd_count           ( ), 
        .rd_data            ( fifo_data_out )
    );

  assign input_hash = (in_hash_ready && input_valid) ? fifo_data_out : '0;

  // cycle a ref_cnt, actually set internally on last input in_hash_valid
  logic [15:0] ref_cnt;
  always_ff @(posedge clk) begin
    if (rst) begin
      ref_cnt <= '0;
    end
    else begin
      ref_cnt <= ref_cnt + 16'd1;
    end
  end

  shcl_cpu cpu0 (
                  .clk(clk),
                  .rst(rst),

                  .in_hash_data  (input_hash ),
                  .in_hash_valid (input_valid && in_hash_ready ),
                  .in_hash_ref   (ref_cnt),
                  .in_hash_ready (in_hash_ready ),

                  .out_hash_data  (o_hash),
                  .out_ref        (),
                  .out_d_addr     (),
                  .out_hash_valid (o_valid));

  assign o_correct = '0; 

endmodule 
