#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/time_support.h>
#include <stdlib.h>

#include "target/target.h"
#include <jtag/interface.h>
#include <jtag/swd.h>
#include <jtag/commands.h>
#include <libjaylink/libjaylink.h>
#include "jim.h"
#include "jtag.h"
#include "minidriver.h"
#include "interface.h"
#include "interfaces.h"
#include <transport/transport.h>
#include <jtag/jtag.h>

extern struct jtag_interface ftdi_interface;

struct target *all_targets;
static struct target_event_callback *target_event_callbacks;
static struct target_timer_callback *target_timer_callbacks;
LIST_HEAD(target_reset_callback_list);
LIST_HEAD(target_trace_callback_list);
static const int polling_interval = 100;
struct command_context context, *global_cmd_ctx = &context;
struct command_invocation my_command, *cmd = &my_command;
struct command current;
struct command current;
struct jtag_tap tap1;
int expect[] = {0x13631093};

struct jtag_interface jlink_interface = {
        .name = "jlink",
};

int Jim_InitStaticExtensions(Jim_Interp *interp)
{
        return JIM_OK;
}

/* invoke periodic callbacks immediately */
int target_call_timer_callbacks_now(void)
{
  return ERROR_OK;
}

int gdb_actual_connections;

struct target *get_target_by_num(int num)
{
        struct target *target = all_targets;

        while (target) {
                if (target->target_number == num)
                        return target;
                target = target->next;
        }

        return NULL;
}

struct target *get_current_target(struct command_context *cmd_ctx)
{
        struct target *target = get_target_by_num(cmd_ctx->current_target);

        if (target == NULL) {
                LOG_ERROR("BUG: current_target out of bounds");
                exit(-1);
        }

        return target;
}

int my_command_init(int verbose)
{
  const char *argv_7[] = {"program", "<filename>", NULL};
  const char *argv_6[] = {"program", "default", NULL};
  const char *argv_5[] = {"measure_clk", "default", NULL};
  const char *argv_4[] = {"srst_deasserted", "default", NULL};
  const char *argv_3[] = {"power_restore", "default", NULL};
  const char *argv_2[] = {"script", "<file>", NULL};
  const char *argv_1[] = {"script", "filename of OpenOCD script (tcl) to run", NULL};
  const char *argv1[] = {"find", "<file>", NULL};
  const char *argv2[] = {"3", NULL};
  const char *argv3[] = {"ftdi", NULL};
  const char *argv4[] = {"Digilent USB Device", NULL};
  const char *argv5[] = {"0x0403", "0x6010", NULL};
  const char *argv6[] = {"0", NULL};
  const char *argv7[] = {"0x0088", "0x008b", NULL};
  const char *argv8[] = {"none", NULL};
  const char *argv9[] = {"10000", NULL};
  const char *argv10[] = {NULL};
  log_init();
  jtag_constructor();
  aice_constructor();
  swd_constructor();
  context.interp = Jim_CreateInterp();
  my_command.ctx = global_cmd_ctx;
  my_command.current = &current;
  my_command.name = "add_usage_text";
  my_command.argc = 2;
  my_command.argv = argv1;
  handle_help_add_command(&my_command);
  my_command.name = "add_help_text";
  my_command.argc = 2;
  my_command.argv = argv1;
  handle_help_add_command(&my_command);
  my_command.name = "add_help_text";
  my_command.argc = 2;
  my_command.argv = argv_1;
  handle_help_add_command(&my_command);
  my_command.name = "add_help_text";
  my_command.argc = 2;
  my_command.argv = argv_2;
  handle_help_add_command(&my_command);
  my_command.name = "add_help_text";
  my_command.argc = 2;
  my_command.argv = argv_3;
  handle_help_add_command(&my_command);
  my_command.name = "add_help_text";
  my_command.argc = 2;
  my_command.argv = argv_4;
  handle_help_add_command(&my_command);
  my_command.name = "add_help_text";
  my_command.argc = 2;
  my_command.argv = argv_5;
  handle_help_add_command(&my_command);
  my_command.name = "add_help_text";
  my_command.argc = 2;
  my_command.argv = argv_6;
  handle_help_add_command(&my_command);
  my_command.name = "add_usage_text";
  my_command.argc = 2;
  my_command.argv = argv_7;
  handle_help_add_command(&my_command);
  if (verbose)
    {
      my_command.name = "debug_level";
      my_command.argc = 1;
      my_command.argv = argv2;
      handle_debug_level_command(&my_command);
    }
  my_command.name = "interface";
  my_command.argc = 1;
  my_command.argv = argv3;
  handle_interface_command (&my_command);
  my_command.name = "ftdi_device_desc";
  my_command.argc = 1;
  my_command.argv = argv4;
  ftdi_handle_device_desc_command(&my_command);
  my_command.name = "ftdi_vid_pid";
  my_command.argc = 2;
  my_command.argv = argv5;
  ftdi_handle_vid_pid_command(&my_command);
  my_command.name = "ftdi_channel";
  my_command.argc = 1;
  my_command.argv = argv6; 
  ftdi_handle_channel_command(&my_command);
  my_command.name = "ftdi_layout_init";
  my_command.argc = 2;
  my_command.argv = argv7; 
  ftdi_handle_layout_init_command(&my_command);
  my_command.name = "reset_config";
  my_command.argc = 1;
  my_command.argv = argv8; 
  handle_reset_config_command(&my_command);
  my_command.name = "adapter_khz";
  my_command.argc = 1;
  my_command.argv = argv9; 
  handle_adapter_khz_command(&my_command);
  tap1.chip = "artix";
  tap1.tapname = "tap";
  tap1.dotted_name = "artix.tap";
  tap1.abs_chain_position = 0;
  tap1.disabled_after_reset = false;
  tap1.enabled = true;
  tap1.ir_length = 6;
  tap1.ir_capture_value = 1;
  tap1.expected = 0x0;
  tap1.ir_capture_mask = 3;
  tap1.expected_mask = 0x0;
  tap1.idcode = 0;
  tap1.hasidcode = false;
  tap1.expected_ids = expect;
  tap1.expected_ids_cnt = 1;
  tap1.ignore_version = false;
  tap1.cur_instr = 0x0;
  tap1.bypass = 0;
  tap1.event_action = 0x0;
  tap1.next_tap = 0x0;
  tap1.dap = 0x0;
  tap1.priv = 0x0;
  jtag_tap_init(&tap1);
  jtag_init(global_cmd_ctx);
  jtag_init_inner(global_cmd_ctx);
  jtag_add_statemove(TAP_IRSHIFT);
  my_command.name = "svf";
  my_command.argc = 0;
  my_command.argv = argv10;
  my_command.ctx = global_cmd_ctx;
  handle_scan_chain_command(&my_command);
  return 0;
}

enum {wr = 1L << 32,
      inc = 1L << 33,
      dbg_req = 1L<<34, dbg_resume = 2L<<34, dbg_halt = 4L<<34, dbg_fetch = 8L<<34};

enum {status_addr = 0x600000, burst_addr = 0x700000, shared_addr = 0x800000, debug_addr = 0xFFF00000};

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

        // CSRs 0x4000-0xBFFF
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

static int tstcnt;
static long prev_addr;

void my_addr(long addr);
uint64_t *raw_read_data(int len);
void raw_write_data(int len, uint64_t *ibuf);

void show_tdo(uint32_t *rslt)
{
  int j;
  if (rslt) for (j = rslt_len(); j--; )
	      printf("%.8X%c", rslt[j], j?':':'\n');
}

static uint64_t dbg_flag, inc_flag, wr_flag;

void my_addr(long addr)
{
  char addrbuf[20];
  sprintf(addrbuf, "(%lX)", dbg_flag|inc_flag|wr_flag|addr);
  // select address reg
  my_svf(SIR, "6", "TDI", "(03)", NULL);
  // auto-inc on
  my_svf(SDR, "40", "TDI", addrbuf, NULL);
  // select data reg
  my_svf(SIR, "6", "TDI", "(02)", NULL);
  prev_addr = addr;
#ifdef VERBOSE  
  printf("my_addr = %s\n", addrbuf);
#endif  
}

uint64_t *raw_read_data(int len)
{
  uint64_t *rslt;
  char lenbuf[10];
  sprintf(lenbuf, "%d", (1+len)<<6);
  rslt = my_svf(SDR, lenbuf, "TDI", "(0)", "TDO", "(0)", "MASK", "(0)", NULL);
  assert(prev_addr == *rslt);
  return rslt+1;
}

void raw_write_data(int len, uint64_t *cnvptr)
{
  int j, cnt = 0;
  uint64_t *rslt;
  char lenbuf[10];
  char *outptr = (char *)malloc(len*16+3);
  outptr[cnt++] = '(';
  for (j = len; j--; )
    {
    sprintf(outptr+cnt, "%.016lX", cnvptr[j]);
    cnt += 16;
    }
  strcpy(outptr+cnt, ")");
  sprintf(lenbuf, "%d", (len) << 6);
  rslt = my_svf(SDR, lenbuf, "TDI", outptr, "TDO", "(0)", "MASK", "(0)", NULL);
  free(outptr);
  assert(prev_addr == *rslt);
  for (j = 0; j < len-1; j++)
    {
      if (cnvptr[j] != rslt[j+1])
	printf("Write jtag chain mismatch: %.16lX != %.16lX\n", cnvptr[j], rslt[j+1]);
      else
        ++tstcnt;
    }
  free(rslt);
}

uint64_t rand64(void)
{
  uint32_t rslt[2];
  rslt[0] = mrand48();
  rslt[1] = mrand48();
  return *(uint64_t *)rslt;
}

void my_mem_test(int shft, long addr)
{
  int i, j;
  srand48(time(0));
  for (i = 1; i < shft; i++)
    {
      uint64_t *rslt1, *rslt2;
      int len = 1 << i;
      rslt1 = calloc(len, sizeof(uint64_t));
      for (j = 0; j < len; j++) rslt1[j] = rand64();
      inc_flag = inc;
      wr_flag = wr;
      my_addr(addr);
      raw_write_data(len, rslt1);
      inc_flag = inc;
      wr_flag = 0;
      my_addr(addr);
      rslt2 = raw_read_data(len);
      for (j = 0; j < len; j++)
	{
	  if (rslt1[j] != rslt2[j])
	    {
	    printf("Memory test mismatch: %.16lX != %.16lX\n", rslt1[j], rslt2[j]);
            abort();
	    }
          else
            ++tstcnt;
	}
    }
}

const char *dbgnam(int reg)
{
  switch(reg)
    {
      case DBG_CTRL    : return "DBG_CTRL    ";
      case DBG_HIT     : return "DBG_HIT     ";
      case DBG_IE      : return "DBG_IE      ";
      case DBG_CAUSE   : return "DBG_CAUSE   ";

      case BP_CTRL0    : return "BP_CTRL0    ";
      case BP_DATA0    : return "BP_DATA0    ";
      case BP_CTRL1    : return "BP_CTRL1    ";
      case BP_DATA1    : return "BP_DATA1    ";
      case BP_CTRL2    : return "BP_CTRL2    ";
      case BP_DATA2    : return "BP_DATA2    ";
      case BP_CTRL3    : return "BP_CTRL3    ";
      case BP_DATA3    : return "BP_DATA3    ";
      case BP_CTRL4    : return "BP_CTRL4    ";
      case BP_DATA4    : return "BP_DATA4    ";
      case BP_CTRL5    : return "BP_CTRL5    ";
      case BP_DATA5    : return "BP_DATA5    ";
      case BP_CTRL6    : return "BP_CTRL6    ";
      case BP_DATA6    : return "BP_DATA6    ";
      case BP_CTRL7    : return "BP_CTRL7    ";
      case BP_DATA7    : return "BP_DATA7    ";

      case DBG_NPC     : return "DBG_NPC     ";
      case DBG_PPC     : return "DBG_PPC     ";
      case DBG_GPR     : return "DBG_GPR     ";

        // CSRs 4000-0xBFFF

      case DBG_CSR_U0  : return "DBG_CSR_U0  ";
      case DBG_CSR_U1  : return "DBG_CSR_U1  ";
      case DBG_CSR_S0  : return "DBG_CSR_S0  ";
      case DBG_CSR_S1  : return "DBG_CSR_S1  ";
      case DBG_CSR_H0  : return "DBG_CSR_H0  ";
      case DBG_CSR_H1  : return "DBG_CSR_H1  ";
      case DBG_CSR_M0  : return "DBG_CSR_M0  ";
      case DBG_CSR_M1  : return "DBG_CSR_M1  ";
      default: return "???";
       }
}

void my_jtag(void)
{
  int i, len = 0x10000/8;
  uint64_t *rslt1, *rsltc, *rsltd, ctrl;
  dbg_flag = dbg_fetch|dbg_req;
  // Try to set debug request
  ctrl = -1;
  inc_flag = 0;
  wr_flag = wr;
  my_addr(debug_addr+DBG_CTRL);
  raw_write_data(1, &ctrl);
  wr_flag = 0;
  rsltc = raw_read_data(1);
  // Try to set debug regs all on
  rslt1 = calloc(len, sizeof(uint64_t));
  memset(rslt1, -1, len*sizeof(uint64_t));
  inc_flag = inc;
  wr_flag = wr;
  my_addr(debug_addr);
  raw_write_data(len, rslt1);
  // Readout to see what sticks
  inc_flag = inc;
  wr_flag = 0;
  my_addr(debug_addr);
  rsltd = raw_read_data(len);
  for (i = 0; i < len; i++)
    {
      const char *reg = dbgnam(i*8);
      if ((*reg != '?') || (rsltd[i] && ~rsltd[i]))
        printf("addr[%.4X] %s = %.16lX\n", i*8, reg, rsltd[i]);
    }
  my_mem_test(3, debug_addr+DBG_GPR+16);
  svf_free();
}

void jtag_poke(int addr, uint64_t data)
{
  inc_flag = 0;
  wr_flag = wr;
  my_addr(addr);
  raw_write_data(1, &data);
}

uint64_t jtag_peek(int addr)
{
  inc_flag = 0;
  wr_flag = 0;
  my_addr(addr);
  return *raw_read_data(1);
}

void verify_poke(int addr, uint64_t data)
{
  uint64_t rslt;
  jtag_poke(addr, data);
  rslt = jtag_peek(addr);
  if (data != rslt)
    {
      printf("JTAG verify mismatch: %.16lX != %.16lX\n", data, rslt);
    }
}

void axi_test(void)
{
  uint32_t axi_addr = 0;
  uint64_t mask0, mask1, maskgo, rslt2, status;
  uint64_t burst_reset = 1, burst_go = 1, burst_inc = 0, burst_rnw = 1, burst_size = 1, burst_length = 2;
  mask0 = ((burst_inc&1)<<48)|((burst_rnw&1)<<47)|((burst_size&0x7F)<<40)|((burst_length&0xFF)<<32)|(axi_addr&0xFFFFFFFF);
  mask1 = ((burst_reset&1)<<50)|mask0;
  maskgo = ((burst_go&1)<<49)|mask1;
  verify_poke(burst_addr, mask0);  
  verify_poke(burst_addr, mask1);  
  verify_poke(burst_addr, maskgo);  
  verify_poke(burst_addr, mask1);  
  status = jtag_peek(status_addr);
  printf("Wrap address: %.16lX\n", status&0xFFFFFFFF);
  switch( (status>>32)&7)
    {
    case 000: printf("State: reset\n"); break;
    case 001: printf("State: idle\n"); break;
    case 002: printf("State: prepare\n"); break;
    case 003: printf("State: read_transaction\n"); break;
    case 004: printf("State: write_transaction\n"); break;
    case 005: printf("State: error_detected\n"); break;
    case 006: printf("State: complete\n"); break;
    default:  printf("State: unknown\n"); break;
    }
  printf("Done: %lX\n", (status>>35)&1);
  printf("Busy: %lX\n", (status>>36)&1);
  printf("Error: %lX\n", (status>>37)&1);
  printf("Resetn: %lX\n", (status>>38)&1);
  printf("start_write_response_transaction: %lX\n", (status>>39)&1);
  printf("start_write_data_transaction: %lX\n", (status>>40)&1);
  printf("start_write_address_transaction: %lX\n", (status>>41)&1);
  printf("start_read_data_transaction: %lX\n", (status>>42)&1);
  printf("start_read_address_transaction: %lX\n", (status>>43)&1);
  switch( (status>>44)&7)
    {
    case 000: printf("Read address channel state: reset\n"); break;
    case 001: printf("Read address channel state: idle\n"); break;
    case 002: printf("Read address channel state: running\n"); break;
    case 003: printf("Read address channel state: error_detected\n"); break;
    case 004: printf("Read address channel state: complete\n"); break;
    default:  printf("Read address channel state: unknown\n"); break;
    }
 }

int main(int argc, const char **argv)
{
  int verbose = 0;
  if (argc == 2 && !strcmp(argv[1], "-v"))
    {
    verbose = 1;
    --argc; ++argv;
    }
  my_command_init(verbose);
  if (argc > 1)
   {
     my_command.name = "svf";
     my_command.argc = --argc;
     my_command.argv = ++argv;
     my_command.ctx = global_cmd_ctx;
     handle_svf_command(&my_command);
   }
 else
   {
     svf_init();
     my_svf(TRST, "OFF", NULL);
     my_svf(ENDIR, "IDLE", NULL);
     my_svf(ENDDR, "IDLE", NULL);
     my_svf(STATE, "RESET", NULL);
     my_svf(STATE, "IDLE", NULL);
     my_svf(FREQUENCY, "1.00E+07", "HZ", NULL);
     my_mem_test(12, shared_addr);
     printf("Tests passed = %d\n", tstcnt);
     //     my_jtag();
     axi_test();
   }
}
