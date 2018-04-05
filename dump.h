#include <stdint.h>

typedef struct {
  uint64_t aw_addr;
  uint64_t aw_prot;
  uint64_t aw_region;
  uint64_t aw_len;
  uint64_t aw_size;
  uint64_t aw_burst;
  uint64_t aw_lock;
  uint64_t aw_cache;
  uint64_t aw_qos;
  uint64_t aw_id;
  uint64_t aw_user;
  uint64_t aw_ready;
  uint64_t aw_valid;

  uint64_t ar_addr;
  uint64_t ar_prot;
  uint64_t ar_region;
  uint64_t ar_len;
  uint64_t ar_size;
  uint64_t ar_burst;
  uint64_t ar_lock;
  uint64_t ar_cache;
  uint64_t ar_qos;
  uint64_t ar_id;
  uint64_t ar_user;
  uint64_t ar_ready;
  uint64_t ar_valid;

  uint64_t w_valid;
  uint64_t w_data;
  uint64_t w_strb;
  uint64_t w_user;
  uint64_t w_last;
  uint64_t w_ready;

  uint64_t r_data;
  uint64_t r_resp;
  uint64_t r_last;
  uint64_t r_id;
  uint64_t r_user;
  uint64_t r_ready;
  uint64_t r_valid;

  uint64_t b_resp;
  uint64_t b_id;
  uint64_t b_user;
  uint64_t b_ready;
  uint64_t b_valid;

  uint64_t unused, unused2, address, done, busy, error, state, state_rsp, state_wrd, state_rac;
  uint64_t strt_wrt, strt_wdt, strt_wat, strt_rdt, strt_rat, wrt_fin, wdt_fin, rdt_fin, wat_fin, rat_fin;
  uint64_t boot_we, boot_en, boot_wdata, boot_addr, boot_rdata;
  uint64_t write_valid, read_valid, wrap_addr, wrap_en, wrap_rdata;
} axi_t;

typedef enum {
        NONE, LOAD, STORE, ALU, CTRL_FLOW, MULT, CSR
    } fu_t;

typedef enum { // basic ALU op
  ADD, SUB, ADDW, SUBW,
  // logic operations
  XORL, ORL, ANDL,
  // shifts
  SRA, SRL, SLL, SRLW, SLLW, SRAW,
  // comparisons
  LTS, LTU, GES, GEU, EQ, NE,
  // jumps
  JALR,
  // set lower than operations
  SLTS, SLTU,
  // CSR functions
  MRET, SRET, ECALL, WFI, FENCE, FENCE_I, SFENCE_VMA, CSR_WRITE, CSR_READ, CSR_SET, CSR_CLEAR,
  // LSU functions
  LD, SD, LW, LWU, SW, LH, LHU, SH, LB, SB, LBU,
  // Atomic Memory Operations
  AMO_LRW, AMO_LRD, AMO_SCW, AMO_SCD,
  AMO_SWAPW, AMO_ADDW, AMO_ANDW, AMO_ORW, AMO_XORW, AMO_MAXW, AMO_MAXWU, AMO_MINW, AMO_MINWU,
  AMO_SWAPD, AMO_ADDD, AMO_ANDD, AMO_ORD, AMO_XORD, AMO_MAXD, AMO_MAXDU, AMO_MIND, AMO_MINDU,
  // Multiplications
  MUL, MULH, MULHU, MULHSU, MULW,
  // Divisions
  DIV, DIVU, DIVW, DIVUW, REM, REMU, REMW, REMUW
} fu_op;

typedef enum priv_lvl {
      PRIV_LVL_M = 3,
      PRIV_LVL_S = 1,
      PRIV_LVL_U = 0
    } priv_lvl_t;

typedef struct exception {
         uint64_t cause; // cause of exception
         uint64_t tval;  // additional information of causing exception (e.g.: instruction causing it),
                             // address of LD/ST fault
         uint64_t        valid;
    } exception_t;

typedef struct branchpredict_sbe {
        uint64_t predict_address; // target address at which to jump, or not
        uint64_t        predict_taken;   // branch is taken
        uint64_t        is_lower_16;     // branch instruction is compressed and resides
                                      // in the lower 16 bit of the word
        uint64_t        valid;           // this is a valid hint
    } branchpredict_sbe_t;

typedef struct scoreboard_entry {
  uint64_t               pc;            // PC of instruction
  uint64_t  trans_id;      // this can potentially be simplified, we could index the scoreboard entry
  // with the transaction id in any case make the width more generic
  fu_t                      fu;            // functional unit to use
  fu_op                     op;            // operation to perform in each functional unit
  uint64_t                rs1;           // register source address 1
  uint64_t                rs2;           // register source address 2
  uint64_t                rd;            // register destination address
  uint64_t               result;        // for unfinished instructions this field also holds the immediate
  uint64_t                     valid;         // is the result valid
  uint64_t                     use_imm;       // should we use the immediate as operand b?
  uint64_t                     use_zimm;      // use zimm as operand a
  uint64_t                     use_pc;        // set if we need to use the PC as operand a, PC from exception
  exception_t               ex;            // exception has occurred
  branchpredict_sbe_t       bp;            // branch predict scoreboard data structure
  uint64_t                     is_compressed; // signals a compressed instructions
} scoreboard_entry_t;

typedef struct commit {
    uint64_t              rstn;
    uint64_t              flush_unissued;
    uint64_t              flush;
    // Decode
    uint64_t              instruction;
    uint64_t              fetch_valid;
    uint64_t              fetch_ack;
    // Issue stage
    uint64_t              issue_ack; // issue acknowledged
    scoreboard_entry_t issue_sbe; // issue scoreboard entry
    // WB stage
    uint64_t              waddr;
    uint64_t              wdata;
    uint64_t              we;
    // commit stage
    scoreboard_entry_t commit_instr; // commit instruction
    uint64_t              commit_ack;

    // address translation
    // stores
    uint64_t              st_valid;
    // loads
    uint64_t              ld_valid;
    uint64_t              ld_kill;
    // load and store
    uint64_t              paddr;

    // exceptions
    exception_t           exception;
    // current privilege level
    priv_lvl_t            priv_lvl;
    uint64_t              raddr_a_i, raddr_b_i, waddr_a_i;
    uint64_t              rdata_a_o, rdata_b_o, wdata_a_i;

  uint64_t              count, notcount;
} commit_t;

void dump_time(void);
void close_vcd(void);
void vcd_info(const char *label, uint64_t dst, int w);
void scope(const char *hier);
void upscope(void);


