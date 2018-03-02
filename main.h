#ifndef _MAIN_H
#define _MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef enum {rd_mode = 0L, wr_mode = 1L << 32, inc_mode = 1L << 33,
      dbg_req = 1L<<34, dbg_resume = 2L<<34, dbg_halt = 4L<<34, dbg_fetch = 8L<<34} jtag_mode_t;

typedef enum {cpu_addr_mask = 0xFFFF, cpu_stall = 0x10000, cpu_stb = 0x20000, cpu_we = 0x40000,
              cpu_ack_ro = 0x80000, cpu_bp_ro = 0x100000} cpu_mode_t;

typedef enum {cap_addr = 0x300000,
      proto_addr_lo = 0x400000, proto_addr_hi = 0x500000, status_addr = 0x600000, burst_addr = 0x700000,
      shared_addr = 0x800000, cap_buf = 0x900000, debug_addr_lo = 0xFFF00000, debug_addr_hi = 0xFFF80000} jtag_addr_t;

  typedef enum {
    axi_state_reset = 000,
    axi_state_idle = 001,
    axi_state_prepare = 002,
    axi_state_read_transaction = 003,
    axi_state_write_transaction = 004,
    axi_state_error_detected = 005,
    axi_state_complete = 006,
    axi_state_unknown = 007} axi_state_t;

typedef enum {
        DBG_CTRL     = 0x0,
        DBG_HIT      = 0x8,
        DBG_IE       = 0x10,
        DBG_CAUSE    = 0x18,

        BP_CTRL0     = 0x80,
        BP_DATA0     = 0x88,
        BP_CTRL1     = 0x90,
        BP_DATA1     = 0x98,
        BP_CTRL2     = 0xA0,
        BP_DATA2     = 0xA8,
        BP_CTRL3     = 0xB0,
        BP_DATA3     = 0xB8,
        BP_CTRL4     = 0xC0,
        BP_DATA4     = 0xC8,
        BP_CTRL5     = 0xD0,
        BP_DATA5     = 0xD8,
        BP_CTRL6     = 0xE0,
        BP_DATA6     = 0xE8,
        BP_CTRL7     = 0xF0,
        BP_DATA7     = 0xF8,

        DBG_NPC      = 0x2000,
        DBG_PPC      = 0x2008,
        DBG_GPR      = 0x400,
        DBG_RA       = 0x408,
        DBG_SP       = 0x410,
        DBG_GP       = 0x418,
        DBG_TP       = 0x420,
        DBG_T0       = 0x428,
        DBG_T1       = 0x430,
        DBG_T2       = 0x438,
        DBG_S0       = 0x440,
        DBG_S1       = 0x448,
        DBG_A0       = 0x450,
        DBG_A1       = 0x458,
        DBG_A2       = 0x460,
        DBG_A3       = 0x468,
        DBG_A4       = 0x470,
        DBG_A5       = 0x478,
        DBG_A6       = 0x480,
        DBG_A7       = 0x488,
        DBG_S2       = 0x490,
        DBG_S3       = 0x498,
        DBG_S4       = 0x4A0,
        DBG_S5       = 0x4A8,
        DBG_S6       = 0x4B0,
        DBG_S7       = 0x4B8,
        DBG_S8       = 0x4C0,
        DBG_S9       = 0x4C8,
        DBG_S10      = 0x4D0,
        DBG_S11      = 0x4D8,
        DBG_T3       = 0x4E0,
        DBG_T4       = 0x4E8,
        DBG_T5       = 0x4F0,
        DBG_T6       = 0x4F8,

        // CSRs 0x4000-0xBFFF
        CSR_BASE     = 0x4000,
        DBG_CSR_U0   = 0x8000,
        DBG_CSR_U1   = 0x9000,
        DBG_CSR_S0   = 0xA000,
        DBG_CSR_S1   = 0xB000,
        DBG_CSR_H0   = 0xC000,
        DBG_CSR_H1   = 0xD000,
        DBG_CSR_M0   = 0xE000,
        DBG_CSR_M1   = 0xF000
    } debug_reg_t;

// ---------------------
// Performance Counters
// ---------------------

enum {
    PERF_L1_ICACHE_MISS = 0x0,     // L1 Instr Cache Miss
    PERF_L1_DCACHE_MISS = 0x1,     // L1 Data Cache Miss
    PERF_ITLB_MISS      = 0x2,     // ITLB Miss
    PERF_DTLB_MISS      = 0x3,     // DTLB Miss
    PERF_LOAD           = 0x4,     // Loads
    PERF_STORE          = 0x5,     // Stores
    PERF_EXCEPTION      = 0x6,     // Taken exceptions
    PERF_EXCEPTION_RET  = 0x7,     // Exception return
    PERF_BRANCH_JUMP    = 0x8,     // Software change of PC
    PERF_CALL           = 0x9,     // Procedure call
    PERF_RET            = 0xA,     // Procedure Return
    PERF_MIS_PREDICT    = 0xB};    // Branch mis-predicted

typedef enum {
        // Supervisor Mode CSRs
        CSR_SSTATUS        = 0x100,
        CSR_SIE            = 0x104,
        CSR_STVEC          = 0x105,
        CSR_SCOUNTEREN     = 0x106,
        CSR_SSCRATCH       = 0x140,
        CSR_SEPC           = 0x141,
        CSR_SCAUSE         = 0x142,
        CSR_STVAL          = 0x143,
        CSR_SIP            = 0x144,
        CSR_SATP           = 0x180,
        // Machine Mode CSRs
        CSR_MSTATUS        = 0x300,
        CSR_MISA           = 0x301,
        CSR_MEDELEG        = 0x302,
        CSR_MIDELEG        = 0x303,
        CSR_MIE            = 0x304,
        CSR_MTVEC          = 0x305,
        CSR_MCOUNTEREN     = 0x306,
        CSR_MSCRATCH       = 0x340,
        CSR_MEPC           = 0x341,
        CSR_MCAUSE         = 0x342,
        CSR_MTVAL          = 0x343,
        CSR_MIP            = 0x344,
        CSR_MVENDORID      = 0xF11,
        CSR_MARCHID        = 0xF12,
        CSR_MIMPID         = 0xF13,
        CSR_MHARTID        = 0xF14,
        CSR_MCYCLE         = 0xB00,
        CSR_MINSTRET       = 0xB02,
        CSR_DCACHE         = 0x701,
        CSR_ICACHE         = 0x700,
        // Counters and Timers
        CSR_CYCLE          = 0xC00,
        CSR_TIME           = 0xC01,
        CSR_INSTRET        = 0xC02,
        // Performance counters
        CSR_L1_ICACHE_MISS = PERF_L1_ICACHE_MISS + 0xC03,
        CSR_L1_DCACHE_MISS = PERF_L1_DCACHE_MISS + 0xC03,
        CSR_ITLB_MISS      = PERF_ITLB_MISS      + 0xC03,
        CSR_DTLB_MISS      = PERF_DTLB_MISS      + 0xC03,
        CSR_LOAD           = PERF_LOAD           + 0xC03,
        CSR_STORE          = PERF_STORE          + 0xC03,
        CSR_EXCEPTION      = PERF_EXCEPTION      + 0xC03,
        CSR_EXCEPTION_RET  = PERF_EXCEPTION_RET  + 0xC03,
        CSR_BRANCH_JUMP    = PERF_BRANCH_JUMP    + 0xC03,
        CSR_CALL           = PERF_CALL           + 0xC03,
        CSR_RET            = PERF_RET            + 0xC03,
        CSR_MIS_PREDICT    = PERF_MIS_PREDICT    + 0xC03
    } csr_reg_t;

  void write_data(jtag_addr_t addr, int len, uint64_t *cnvptr);
  uint64_t *read_data(jtag_addr_t addr, int len);
  void axi_test(long addr, int rnw, int siz, int len);
  uint64_t cpu_ctrl(int cpu_addr, uint64_t cpu_data);
  uint64_t cpu_read(int cpu_addr);
  void cpu_debug(void);
  void cpu_flush(void);
  void cpu_halt(void);
  uint64_t htonll(uint64_t addr);
  uint64_t ntohll(uint64_t addr);
  void new_bridge(int portNumber);
  
#ifdef __cplusplus
};
#endif
#endif
