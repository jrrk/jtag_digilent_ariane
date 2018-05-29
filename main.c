#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/time_support.h>
#include <stdlib.h>
#include <bfd.h>

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
#include <stdio.h>
#include <stdlib.h>
#include <search.h>
#include "dump.h"
#include "main.h"

extern struct jtag_interface ftdi_interface;

struct target *all_targets;
LIST_HEAD(target_reset_callback_list);
LIST_HEAD(target_trace_callback_list);
static const int polling_interval = 100;
struct command_context context, *global_cmd_ctx = &context;
struct command_invocation my_command, *cmd = &my_command;
struct command current;
struct command current;
struct jtag_tap tap1;
unsigned int expect[] = {0x13631093};

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

int my_command_init(int verbose, const char *interface)
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
  const char *argv4[] = {"Digilent USB Device", NULL};
  const char *argv5[] = {"0x0403", "0x6010", NULL};
  const char *argv6[] = {"0", NULL};
  const char *argv7[] = {"0x0088", "0x008b", NULL};
  const char *argv8[] = {"none", NULL};
  const char *argv9[] = {"10000", NULL};
  const char *argv10[] = {NULL};
  char const *argvi[] = {interface, NULL};
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
  if (verbose > 1)
    {
      my_command.name = "debug_level";
      my_command.argc = 1;
      my_command.argv = argv2;
      handle_debug_level_command(&my_command);
    }
  my_command.name = "interface";
  my_command.argc = 1;
  my_command.argv = argvi;
  handle_interface_command (&my_command);
  if (!strcmp(interface, "remote_bitbang"))
    {
      my_command.name = "remote_bitbang_host";
      my_command.argc = 1;
      my_command.argv = argvi;
      argvi[0] = "localhost";
      remote_bitbang_handle_remote_bitbang_host_command(&my_command);      
      my_command.name = "remote_bitbang_port";
      my_command.argc = 1;
      my_command.argv = argvi;
      argvi[0] = "4242";
      remote_bitbang_handle_remote_bitbang_port_command(&my_command);      
    }
  else if (!strcmp(interface, "jtag_vpi"))
    {
      my_command.name = "jtag_vpi_set_address";
      my_command.argc = 1;
      my_command.argv = argvi;
      argvi[0] = "127.0.0.1";
      jtag_vpi_set_address(&my_command);      
      my_command.name = "jtag_vpi_set_port";
      my_command.argc = 1;
      my_command.argv = argvi;
      argvi[0] = "5555";
      jtag_vpi_set_port(&my_command);      
    }
  else if (!strcmp(interface, "ftdi"))
    {
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
    }
  else
    {
      fprintf(stderr, "Unknown interface %s\n", interface);
      exit(1);
    }
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

static int tstcnt;
static long prev_addr;

void my_addr(jtag_addr_t addr);
uint64_t *raw_read_data(int len);
uint64_t *read_data(jtag_addr_t addr, int len);
void raw_write_data(int len, uint64_t *ibuf);
void write_data(jtag_addr_t addr, int len, uint64_t *ibuf);

void show_tdo(uint32_t *rslt)
{
  int j;
  if (rslt) for (j = rslt_len(); j--; )
	      printf("%.8X%c", rslt[j], j?':':'\n');
}

static jtag_mode_t inc_flag, wr_flag;
static int dbg_master, capture = 0;
int verbose = 0;

void my_addr(jtag_addr_t addr)
{
  char addrbuf[20], iraddrbuf[20], irdatabuf[20];
  sprintf(addrbuf, "(%lX)", inc_flag|wr_flag|addr);
  sprintf(iraddrbuf, "(%.2X)", dbg_master ? 0x23 : 0x03);
  sprintf(irdatabuf, "(%.2X)", dbg_master ? 0x22 : 0x02);
  // select address reg
  my_svf(SIR, "6", "TDI", iraddrbuf, NULL);
  // auto-inc on
  my_svf(SDR, "40", "TDI", addrbuf, NULL);
  // select data reg
  my_svf(SIR, "6", "TDI", irdatabuf, NULL);
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

uint64_t *read_data(jtag_addr_t addr, int len)
{
  inc_flag = inc_mode;
  wr_flag = 0;
  my_addr(addr);
  return raw_read_data(len);
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

void write_data(jtag_addr_t addr, int len, uint64_t *cnvptr)
{
  inc_flag = inc_mode;
  wr_flag = wr_mode;
  my_addr(addr);
  raw_write_data(len, cnvptr);
}

void write_data_noinc(jtag_addr_t addr, int len, uint64_t *cnvptr)
{
  inc_flag = 0;
  wr_flag = wr_mode;
  my_addr(addr);
  raw_write_data(len, cnvptr);
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
  for (i = 1; i < shft; i++)
    {
      uint64_t *rslt1, *rslt2;
      int len = 1 << i;
      rslt1 = calloc(len, sizeof(uint64_t));
      for (j = 0; j < len; j++) rslt1[j] = rand64();
      write_data(addr, len, rslt1);
      rslt2 = read_data(addr, len);
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
  static char unknown[20];
  switch(reg)
    {
      case DBG_CTRL    : return "DBG_CTRL";
      case DBG_HIT     : return "DBG_HIT";
      case DBG_IE      : return "DBG_IE ";
      case DBG_CAUSE   : return "DBG_CAUSE";

      case BP_CTRL0    : return "BP_CTRL0";
      case BP_DATA0    : return "BP_DATA0";
      case BP_CTRL1    : return "BP_CTRL1";
      case BP_DATA1    : return "BP_DATA1";
      case BP_CTRL2    : return "BP_CTRL2";
      case BP_DATA2    : return "BP_DATA2";
      case BP_CTRL3    : return "BP_CTRL3";
      case BP_DATA3    : return "BP_DATA3";
      case BP_CTRL4    : return "BP_CTRL4";
      case BP_DATA4    : return "BP_DATA4";
      case BP_CTRL5    : return "BP_CTRL5";
      case BP_DATA5    : return "BP_DATA5";
      case BP_CTRL6    : return "BP_CTRL6";
      case BP_DATA6    : return "BP_DATA6";
      case BP_CTRL7    : return "BP_CTRL7";
      case BP_DATA7    : return "BP_DATA7";

      case DBG_NPC     : return "DBG_NPC";
      case DBG_PPC     : return "DBG_PPC";
      case DBG_GPR     : return "DBG_GPR";
      case DBG_RA      : return "DBG_RA";
      case DBG_SP      : return "DBG_SP";
      case DBG_GP      : return "DBG_GP";
      case DBG_TP      : return "DBG_TP";
      case DBG_T0      : return "DBG_T0";
      case DBG_T1      : return "DBG_T1";
      case DBG_T2      : return "DBG_T2";
      case DBG_S0      : return "DBG_S0";
      case DBG_S1      : return "DBG_S1";
      case DBG_A0      : return "DBG_A0";
      case DBG_A1      : return "DBG_A1";
      case DBG_A2      : return "DBG_A2";
      case DBG_A3      : return "DBG_A3";
      case DBG_A4      : return "DBG_A4";
      case DBG_A5      : return "DBG_A5";
      case DBG_A6      : return "DBG_A6";
      case DBG_A7      : return "DBG_A7";
      case DBG_S2      : return "DBG_S2";
      case DBG_S3      : return "DBG_S3";
      case DBG_S4      : return "DBG_S4";
      case DBG_S5      : return "DBG_S5";
      case DBG_S6      : return "DBG_S6";
      case DBG_S7      : return "DBG_S7";
      case DBG_S8      : return "DBG_S8";
      case DBG_S9      : return "DBG_S9";
      case DBG_S10     : return "DBG_S10";
      case DBG_S11     : return "DBG_S11";
      case DBG_T3      : return "DBG_T3";
      case DBG_T4      : return "DBG_T4";
      case DBG_T5      : return "DBG_T5";
      case DBG_T6      : return "DBG_T6";

        // CSRs 4000-0xBFFF

      case DBG_CSR_U0  : return "DBG_CSR_U0";
      case DBG_CSR_U1  : return "DBG_CSR_U1";
      case DBG_CSR_S0  : return "DBG_CSR_S0";
      case DBG_CSR_S1  : return "DBG_CSR_S1";
      case DBG_CSR_H0  : return "DBG_CSR_H0";
      case DBG_CSR_H1  : return "DBG_CSR_H1";
      case DBG_CSR_M0  : return "DBG_CSR_M0";
      case DBG_CSR_M1  : return "DBG_CSR_M1";
      default: sprintf(unknown, "0x%.04X", reg); return unknown;
       }
}

void jtag_poke(uint32_t addr, uint64_t data)
{
  if (verbose)
    printf("jtag_poke(%X, %lX);\n", addr, data);
  write_data(addr, 1, &data);
}

uint64_t jtag_peek(int addr)
{
  uint64_t retval;
  retval = *read_data(addr, 1);
  if (verbose)
    printf("jtag_peek(%X) => %lX;\n", addr, retval);
  return retval;
}

static cpu_mode_t capture_flags_saved;

void verify_poke(uint32_t addr, uint64_t data, uint64_t mask)
{
  uint64_t rslt;
  if (addr==debug_addr_hi)
    data |= capture_flags_saved;
  jtag_poke(addr, data);
  rslt = jtag_peek(addr);
  if (data != (rslt&~mask))
    {
      printf("JTAG verify mismatch @%.08X: %.16lX != %.16lX\n", addr, data, rslt);
    }
}

void capture_flags(cpu_mode_t flags)
{
  capture_flags_saved = flags;
}

uint64_t verify_cpu_ctrl(int cpu_addr, uint64_t cpu_data, int force_halt)
{
  cpu_mode_t ctrl;
  uint64_t rslt, halt = force_halt ? cpu_halt : 0;
  // set up the data to write
  jtag_poke(debug_addr_lo, cpu_data);
  // Try to set debug request
  ctrl = cpu_req|halt|cpu_nofetch|(cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  do {
    rslt = jtag_peek(debug_addr_hi);
  } while (cpu_gnt_ro&~rslt);
  ctrl = cpu_we|cpu_req|halt|cpu_nofetch|(cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  ctrl = cpu_req|cpu_nofetch|(cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  rslt = jtag_peek(debug_addr_lo);
  ctrl = (cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  if (verbose)
    printf("cpu_ctrl(0x%.4X,%s): wrote 0x%.16lX, read 0x%.16lX\n",
           cpu_addr, dbgnam(cpu_addr), cpu_data, rslt);
  return rslt;
}

void cpu_ctrl(int cpu_addr, uint64_t cpu_data, int force_halt)
{
#if 0  
  uint64_t instr[4], halt = force_halt ? cpu_halt/* |cpu_nofetch */ : 0;
  // set up the data to write
  jtag_poke(debug_addr_lo, cpu_data);
  // Try to set debug request
  instr[0] = cpu_req|halt|(cpu_addr&cpu_addr_mask);
  instr[1] = cpu_we|instr[0];
  instr[2] = instr[0];
  instr[3] = instr[0]&~cpu_req;
  write_data_noinc(debug_addr_hi, 4, instr);
  if (verbose)
    {
    printf("cpu_ctrl(0x%.4X,%s): wrote 0x%.16lX\n", cpu_addr, dbgnam(cpu_addr), cpu_data);
    }
#else
  static int prev_force;
  if (force_halt < 0) prev_force = 0;
  if (force_halt > 0) prev_force = 1;
  verify_cpu_ctrl(cpu_addr, cpu_data, prev_force);
#endif  
}

uint64_t cpu_read(int cpu_addr)
{
  cpu_mode_t ctrl;
  uint64_t rslt;
  // Try to set debug request
  ctrl = cpu_req|cpu_nofetch|(cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  rslt = jtag_peek(debug_addr_lo);
  ctrl = cpu_nofetch|(cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  if (verbose)
    printf("cpu_read(0x%.4X,%s): read 0x%.16lX\n", cpu_addr, dbgnam(cpu_addr), rslt);
  return rslt;
}

void cpu_stop(void)
{
  uint64_t old_dbg = cpu_read(DBG_CTRL);
  cpu_ctrl(DBG_CTRL, old_dbg|0x10000, 1);
}

int cpu_is_stopped(void)
{
  //  uint64_t data = cpu_read(DBG_CTRL) & 0x10000;
  uint64_t flags = jtag_peek(debug_addr_hi) & cpu_halted_ro;
  if (flags)
    {
      putchar('*');
      fflush(stdout);
      return true;
    }
  else
    {
      putchar('#');
      fflush(stdout);
      return false;
    }
}

int cap_offset, step, formal;
static const char *regression = NULL;
enum {sleep_dly=100};

#define ext(wid) _ext(cap_raw, wid)
#define ext2(dst,wid) dst = _ext(cap_raw, wid), vcd_info(#dst, dst, wid)

static uint32_t _ext32(uint64_t *cap_raw, int wid)
{
  int shift = cap_offset&63;
  uint32_t retval, mask = 1;
  uint64_t lo = cap_raw[cap_offset>>6];
  uint64_t hi = (cap_raw[(cap_offset>>6)+1] << 32) | (lo >> 32);
  assert(wid <= 32);
  if (shift >= 32) // value is split across words (we assume width <= 32)
    {
      retval = hi >> (shift-32);
    }
  else
    retval = lo >> shift;
  if (wid < 32)
    retval &= (mask << wid)-1;
  cap_offset += wid;
  return retval;
}

static uint64_t _ext(uint64_t *cap_raw, int wid)
{
  if (wid > 32)
    {
      uint64_t rslt1 = _ext32(cap_raw, 32);
      uint64_t rslt2 = _ext32(cap_raw, wid-32);
      return rslt1 | (rslt2 << 32); 
    }
  else
    {
      return _ext32(cap_raw, wid);
    }
}

exception_t cpu_exc_decode(uint64_t *cap_raw)
{
  exception_t exception;
  // exceptions
  ext2(exception.valid, 1);
  ext2(exception.tval, 64);
  ext2(exception.cause, 64);
  return exception;
}

branchpredict_sbe_t cpu_bp_decode(uint64_t *cap_raw)
{
  branchpredict_sbe_t bp;
  // bps
  ext2(bp.valid, 1);
  ext2(bp.is_lower_16, 1);
  ext2(bp.predict_taken, 1);
  ext2(bp.predict_address, 64);
  return bp;
}

scoreboard_entry_t cpu_scoreboard_decode(uint64_t *cap_raw)
{
  scoreboard_entry_t scoreboard_entry;
  ext2(scoreboard_entry.is_compressed, 1);
  scope("bp");
  scoreboard_entry.bp = cpu_bp_decode(cap_raw);
  upscope();
  scope("ex");
  scoreboard_entry.ex = cpu_exc_decode(cap_raw);
  upscope();
  ext2(scoreboard_entry.use_pc, 1);
  ext2(scoreboard_entry.use_zimm, 1);
  ext2(scoreboard_entry.use_imm, 1);
  ext2(scoreboard_entry.valid, 1);
  ext2(scoreboard_entry.result, 64);
  ext2(scoreboard_entry.rd, 5);
  ext2(scoreboard_entry.rs2, 5);
  ext2(scoreboard_entry.rs1, 5);
  ext2(scoreboard_entry.op, 7);
  ext2(scoreboard_entry.fu, 4);
  ext2(scoreboard_entry.trans_id, 3);
  ext2(scoreboard_entry.pc, 64);
  return scoreboard_entry;
}

commit_t cpu_commit_decode(uint64_t *cap_raw)
{
  commit_t commit;
  memset(&commit, 0xAA, sizeof(commit_t));
  cap_offset = 0;
  scope(NULL);
  scope("commit");
  for (int i = 0; i < 20; i++)
    {
      char raw[10];
      sprintf(raw, "raw%d", i);
      vcd_info(strdup(raw), cap_raw[i], 64);
    }
  ext2(commit.count, 9);
  ext2(commit.wdata_a_i, 64);
  ext2(commit.rdata_b_o, 64);
  ext2(commit.rdata_a_o, 64);
  ext2(commit.waddr_a_i, 5);
  ext2(commit.raddr_b_i, 5);
  ext2(commit.raddr_a_i, 5);
  // register file signals (for debug)
  ext2(commit.priv_lvl, 2);
  // current privilege level
  scope("exception");
  commit.exception = cpu_exc_decode(cap_raw);
  upscope();
  // exceptions
  ext2(commit.ld_kill, 1);
  ext2(commit.ld_valid, 1);
  // loads
  ext2(commit.paddr, 64);
  ext2(commit.st_valid, 1);
  // stores
  // address translation
  ext2(commit.commit_ack, 1);
  scope("commit_instr");
  commit.commit_instr =  cpu_scoreboard_decode(cap_raw);
  upscope();
  // commit
  ext2(commit.we, 1);
  ext2(commit.wdata, 64);
  ext2(commit.waddr, 5);
  // write-back
  scope("issue_sbe");
  commit.issue_sbe = cpu_scoreboard_decode(cap_raw);
  upscope();
  ext2(commit.issue_ack, 1);
  // Issue
  ext2(commit.fetch_ack, 1);
  ext2(commit.fetch_valid, 1);
  ext2(commit.instruction, 32);
  // fetch
  ext2(commit.flush, 1);
  ext2(commit.flush_unissued, 1);
  ext2(commit.rstn, 1);
  ext2(commit.notcount, 9);
  assert(cap_offset == 1248);
  upscope();
  dump_time();
  return commit;
}

enum {mchunk = 1<<20};
static struct hsearch_data htab;

void search_error(const char *file, int line)
{
  fprintf(stderr, "Search error %s:%d\n", file, line);
  abort();
}

ENTRY *msearch(uint64_t addr, ACTION action)
{
  ENTRY e, *ep;
  char key[20];
  if (!addr)
    abort();
  sprintf(key, "%lX", addr&(-mchunk));
  e.key = key;
  if (hsearch_r(e, FIND, &ep, &htab))
    {
      if (verbose)
        fprintf(stderr, "Found %s\n", key);
      return ep;
    }
  if (action == ENTER)
    {
      e.key = strdup(key);
      e.data = calloc(sizeof(uint64_t), mchunk>>6);
      if (!hsearch_r(e, ENTER, &ep, &htab))
        search_error(__FILE__,__LINE__);
    }
  return ep;
}

int mdefined(uint64_t addr)
{
  uint64_t *ptr, mask = 1;
  uint32_t low = addr & (mchunk-1);
  ENTRY *ep = msearch(addr, FIND);
  if (ep) 
    {
      ptr = ep->data;
      return ptr[low>>6] & (mask << (low&63)) ? 1 : 0;
    }
  return 0;
}

void mdefine(uint64_t addr)
{
  uint64_t *ptr, mask = 1;
  uint32_t low = addr & (mchunk-1);
  ENTRY *ep = msearch(addr, ENTER);
  ptr = ep->data;
  ptr[low>>6] |= (mask << (low&63));
}

void mrange_define(uint64_t addr, uint64_t bufsz)
{
  while (bufsz--)
    mdefine(addr++);
}

void cpu_commit_status(void)
{
  static int cap_last = 0;
  uint64_t status = jtag_peek(cap_addr);
  int len = status;
#if 0
  commit_t commit_idle;
  uint64_t commit_stat[20];
  for (int i = 0; i < 20; i++)
    commit_stat[i] = jtag_peek(debug_addr_cap+i*8);
  commit_idle = cpu_commit_decode(commit_stat);
  printf("Idle status: %.16lX\n", commit_idle.instruction);
#endif  
  uint64_t *cap_raw = read_data(cap_buf, len*32);
  if (len < cap_last)
    {
      close_vcd();
      cap_last = 0;
    }
  for (int j = cap_last; j < len; j++)
    {
      commit_t commit = cpu_commit_decode(cap_raw+j*32);
      commit.commit_ack = 1; // hack alert
      assert(commit.count+commit.notcount == 511);
      if (regression)
        {
          if (!mdefined(commit.commit_instr.pc))
            {
              printf("PC=%.16lX is out of defined range\n", commit.commit_instr.pc);
              commit.commit_instr.ex.tval = 0xDEADBEEF;
            }
          if (formal)
            pipe27(commit.rstn, commit.commit_ack, commit.commit_instr.pc, commit.commit_instr.ex.tval & 0xFFFFFFFF, commit.exception.valid, 
             commit.commit_instr.ex.cause, commit.flush_unissued, commit.flush, commit.instruction, commit.fetch_valid, 
             commit.fetch_ack, commit.issue_ack, commit.waddr, commit.wdata, commit.we, 
             commit.commit_ack, commit.st_valid, commit.paddr, commit.ld_valid, commit.ld_kill, 
             commit.priv_lvl, commit.raddr_a_i, commit.rdata_a_o, commit.raddr_b_i,
             commit.rdata_b_o, commit.waddr_a_i, commit.wdata_a_i);
        }
      if (verbose > 1) for (int i = 0; i < 20; i++)
        printf("Raw status[%d,%d]: %.16lX\n", j, i, cap_raw[j*32+i]);
    }
  printf("Capture address: %.16lX\n", status);
  cap_last = status;
}

uint64_t gpr_read(int gpr)
{
  return cpu_read(DBG_GPR+gpr*8);
}

void gpr_write(int gpr, uint64_t data)
{
  cpu_ctrl(DBG_GPR+gpr*8, data, 0);
}

uint64_t csr_read(int csr)
{
  return cpu_read(CSR_BASE+csr*8);
}

void csr_write(int csr, uint64_t data)
{
  cpu_ctrl(CSR_BASE+csr*8, data, 0);
}

void cpu_flush(void)
{
  uint64_t data = cpu_read(DBG_NPC);
  cpu_ctrl(DBG_NPC, data, 1);
}

void cpu_reset(void)
{
  verify_poke(debug_addr_hi, capture_flags_saved, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  verify_poke(dma_ctl_addr, axi_reset, dma_move_done_ro);
  verify_poke(dma_ctl_addr, 0, dma_move_done_ro);
}

void cpu_debug(void)
{
  int stopped;
  capture_flags(cpu_halt);
  cpu_reset();
  cpu_stop();
  stopped = cpu_is_stopped();
  if (stopped)
    {
      uint32_t m_thread_id;
      printf("CPU is stopped\n");
      m_thread_id = csr_read(0xF10);
      printf("Found a core with id %X\n", m_thread_id);
    }
  else
    printf("CPU is running\n");
}

void axi_counters(void)
{
  uint64_t capa = jtag_peek(cap_addr);
  printf("Capture address: %.16lX\n", capa);
}

void axi_proto_status(void)
{
  uint64_t status0 = jtag_peek(proto_addr_lo);
  uint64_t status1 = jtag_peek(proto_addr_hi);
  printf("Protocol checker status: %.16lX:%.16lX\n", status1, status0);
}

void axi_readout(long addr, int len)
{
  int j;
  uint64_t *rslt = read_data(addr, len);
  for (j = 0; j < len; j++)
    {
      printf("Memory readout[%d]: %.16lX\n", j, rslt[j]);
    }
}

void axi_capture_status(void)
{
  int j;
  uint64_t status = jtag_peek(cap_addr);
  printf("Capture address: %.16lX\n", status);
  int len = status+1;
  uint64_t *cap_raw = read_data(cap_buf, len*8);
  axi_t *dbg = (axi_t *)calloc(len, sizeof(axi_t));
  cap_offset = 0;
  for (j = 0; j < len; j++)
    {
      dbg[j].ar_addr   = ext(32);
      dbg[j].aw_addr   = ext(32);
      dbg[j].r_data    = ext(32);
      dbg[j].r_data   |= ext(32) << 32;
      dbg[j].w_data    = ext(32);
      dbg[j].w_data   |= ext(32) << 32;
      dbg[j].b_ready   = ext(1);
      dbg[j].b_id      = ext(4);
      dbg[j].b_resp    = ext(2);
      dbg[j].b_valid   = ext(1);
      dbg[j].r_ready   = ext(1);
      dbg[j].r_id      = ext(4);
      dbg[j].r_last    = ext(1);
      dbg[j].r_resp    = ext(2);
      dbg[j].r_valid   = ext(1);
      dbg[j].w_ready   = ext(1);
      dbg[j].w_last    = ext(1);
      dbg[j].w_strb    = ext(8);
      dbg[j].w_valid   = ext(1);
      dbg[j].ar_ready  = ext(1);
      dbg[j].ar_id     = ext(4);
      dbg[j].ar_qos    = ext(4);
      dbg[j].ar_cache  = ext(4);
      dbg[j].ar_lock   = ext(1);
      dbg[j].ar_burst  = ext(2);
      dbg[j].ar_size   = ext(3);
      dbg[j].ar_len    = ext(8);
      dbg[j].ar_region = ext(4);
      dbg[j].ar_prot   = ext(3);
      dbg[j].ar_valid  = ext(1);
      dbg[j].aw_ready  = ext(1);
      dbg[j].aw_id     = ext(4);
      dbg[j].aw_qos    = ext(4);
      dbg[j].aw_cache  = ext(4);
      dbg[j].aw_lock   = ext(1);
      dbg[j].aw_burst  = ext(2);
      dbg[j].aw_size   = ext(3);
      dbg[j].aw_len    = ext(8);
      dbg[j].aw_region = ext(4);
      dbg[j].aw_prot   = ext(3);
      dbg[j].aw_valid  = ext(1);
      dbg[j].error     = ext(1);
      dbg[j].busy      = ext(1);
      dbg[j].done      = ext(1);
      dbg[j].strt_wrt  = ext(1);
      dbg[j].strt_wdt  = ext(1);
      dbg[j].strt_wat  = ext(1);
      dbg[j].strt_rdt  = ext(1);
      dbg[j].strt_rat  = ext(1);
      dbg[j].wrt_fin   = ext(1);
      dbg[j].wdt_fin   = ext(1);
      dbg[j].rdt_fin   = ext(1);
      dbg[j].wat_fin   = ext(1);
      dbg[j].rat_fin   = ext(1);
      dbg[j].state_rac = ext(3);
      dbg[j].state_wrd = ext(3);
      dbg[j].state     = ext(3);
      dbg[j].state_rsp = ext(3);
      dbg[j].address   = ext(9);
      dbg[j].boot_we   = ext(8);
      dbg[j].boot_en   = ext(1);
      dbg[j].boot_wdata= ext(32);
      dbg[j].boot_wdata|= ext(32) << 32;
      dbg[j].boot_addr = ext(16);
      dbg[j].boot_rdata= ext(32);
      dbg[j].boot_rdata|= ext(32) << 32;
      dbg[j].write_valid = ext(1);
      dbg[j].read_valid = ext(1);
      dbg[j].wrap_addr  = ext(14);
      dbg[j].wrap_en    = ext(1);
      dbg[j].wrap_rdata = ext(18);
      assert(cap_offset%512 == 0);
      dump_time();
    }
  close_vcd();
}

#define HID_VGA 0x2000
#define HID_LED 0x400F
#define HID_DIP 0x401F

volatile uint32_t *const sd_base = (uint32_t *)(axi_base+0x01010000);
volatile uint32_t *const hid_vga_ptr = (uint32_t *)(axi_base+0x01008000);
const size_t eth = (axi_base+0x01020000), hid = (axi_base+0x01000000);
static int addr_int = scroll_start;

void dma_copy(uint64_t axi_src_addr, uint64_t axi_dst_addr, int mask, int len)
{
  uint64_t status, dma_move_mask = mask & dma_strb_mask;
  assert(len <= 2048);
  verify_poke(dma_ctl_addr, dma_move_mask, dma_move_done_ro);  
  verify_poke(dma_src_addr, axi_src_addr, 0);
  verify_poke(dma_dest_addr, axi_dst_addr, 0);
  verify_poke(dma_len_addr, len*sizeof(uint64_t), 0);
  verify_poke(dma_ctl_addr, dma_move_mask|dma_move_en, dma_move_done_ro);  
  do {
    status = jtag_peek(dma_ctl_addr);
  } while (dma_move_done_ro & ~status);
  verify_poke(dma_ctl_addr, dma_move_mask, dma_move_done_ro);  
}

void axi_dma(void)
{
  enum {chunk=32, chkoff=0x100};
  uint64_t *chk1, *chk2;
  uint64_t *rslt = calloc(chunk, sizeof(uint64_t));
  for (int j = 0; j < chunk; j++) rslt[j] = rand64();
  tstcnt = 0;
  write_data(shared_addr, chunk, rslt);
  dma_copy(axi_shared_addr, axi_base, -1, chunk);
  chk1 = read_data(boot_addr, chunk);
  for (int i = 0; i < chunk; i++)
    {
      if (chk1[i] != rslt[i])
        {
          printf("Readback mismatch at offset %d (%.016lX != %.016lX)\n", i, chk1[i], rslt[i]);
        }
      ++tstcnt;
    }
  dma_copy(axi_base, axi_shared_addr+chkoff, -1, chunk);
  chk2 = read_data(shared_addr+chkoff, chunk);
  for (int i = 0; i < chunk; i++)
    {
      if (chk1[i] != chk2[i])
        {
          printf("Readback mismatch at offset %d (%.016lX != %.016lX)\n", i, chk1[i], chk2[i]);
        }
      ++tstcnt;
    }
  printf("DMA tests passed = %d\n", tstcnt);
  dma_copy(axi_shared_addr, axi_vga_addr, -1, chunk);
}
  
void axi_vga(const char *str)
{
  enum {burst=128};
  enum {line=64*4};
  uint64_t *chk1, *chk2;
  uint8_t *frambuf = calloc(line, sizeof(uint64_t));
  for (int l = 0; l < 4; l++)
       {
#if 0         
         for (int i = 0; i < line*sizeof(uint64_t); i+=sizeof(uint64_t))
           {
           frambuf[i] = mrand48()%26 + 'A';
           frambuf[i+1] = ' ';
           frambuf[i+2] = mrand48()%10 + '0';
           frambuf[i+3] = '~';
           frambuf[i+4] = mrand48()%26 + 'a';
           frambuf[i+5] = '!';
           frambuf[i+6] = mrand48()%10 + ' ';
           frambuf[i+7] = '?';
           }
#else
         if ((l < 1) || (l > 2))
           {
             for (int i = 0; i < line*sizeof(uint64_t); i++)
               frambuf[i] = '0' + i%10 + (l*16&0x3f);
           }
         else
           {
             memset(frambuf, ' ', line*sizeof(uint64_t));
             if (l == 2)
               {
               int len = strlen(str);
               for (int i = 0; i < len; i++)
                 {
                   frambuf[line*2+i-len*2] = str[i];
                 }
               }
           }
#endif         
         write_data(shared_addr, line, (uint64_t *)frambuf);
         dma_copy(axi_shared_addr, axi_vga_addr+(l<<10), -1, line);
         
         dma_copy(axi_vga_addr+(l<<10), axi_shared_addr, -1, line);
         chk1 = read_data(shared_addr+(1<<10), line);
         chk2 = (uint64_t *)frambuf;
          for (int i = 0; i < burst; i++)
            {
              if (chk1[i] != chk2[i])
                {
                  printf("Readback mismatch at offset %d (%.016lX != %.016lX)\n", i, chk1[i], chk2[i]);
                }
            }
       }
   }

void axi_ramtest(uint64_t axi_addr, int siz)
{
     enum {line=128};
     enum {words=line/sizeof(uint64_t)};
     uint64_t *chk1, *chk2, pass = 0;
     char *frambuf = malloc(line);
     for (int l = 0; l < siz/line; l++)
       {
         int len = sprintf(frambuf, ":%.4d:", l);
         strncpy(frambuf+line-len, frambuf, len);
         for (int i = len; i < line-len; i++)
           frambuf[i] = (i+l)%0x5F + ' ';
         write_data(shared_addr, words, (uint64_t *)frambuf);
         dma_copy(axi_shared_addr, axi_addr+(l<<7), -1, words);
         
         dma_copy(axi_addr+(l<<7), axi_shared_addr+(1<<10), -1, words);
         chk1 = read_data(shared_addr+(1<<10), words);
         chk2 = (uint64_t *)frambuf;
         for (int i = 0; i < words; i++)
           {
             if (chk1[i] != chk2[i])
               {
                 printf("Readback mismatch at offset %d (%.016lX != %.016lX)\n", i, chk1[i], chk2[i]);
               }
             else
               ++pass;
           }
       }
     printf("axi_ramtest at address %.016lX, passes = %ld\n", axi_addr, pass);
}

void axi_dipsw(void)
{
  dma_copy(hid + HID_DIP*4, axi_shared_addr, -1, 1);
  uint64_t dip = *read_data(shared_addr, 1);
  printf("DIP SW: %.4lX\n", dip);
  dma_copy(axi_shared_addr, hid + HID_LED*4, -1, 1);
}

void write_chunk(uint64_t addr, int beats, uint64_t *buffer, uint64_t *zeros)
{
  uint64_t *rdata;
#if 0
  for (int i = 0; i < beats; i++)
    printf("memwrite[%.016lX] = %.016lX\n", i*8+addr, buffer[i]);
#endif
  write_data(shared_addr, beats, buffer);
  dma_copy(axi_shared_addr, addr, -1, beats);
  // verify
  write_data(shared_addr, beats, zeros);
  dma_copy(addr, axi_shared_addr, -1, beats);
  rdata = read_data(shared_addr, beats);
  for (int i = 0; i < beats; i++)
    if (rdata[i] != buffer[i])
      printf("%d/%d: memverify[%.016lX] = %.016lX (was %.016lX)\n", i+1, beats+1, i*8+addr, rdata[i], buffer[i]);
}

void main_access(bool write, uint64_t addr, int size, uint64_t *buffer)  
     {
       uint64_t *rdata;
       if ((addr >= 0x40000000) && (addr <= 0x4000FFFF))
         {
           int i, beats = (size+sizeof(uint64_t)-1)/sizeof(uint64_t);
           jtag_addr_t baddr = (jtag_addr_t)(boot_addr+(addr&0xFFFF));
           if (write)
             {
               // write
#if 0
               for (i = 0; i < beats; i++) // if (i*8+addr < 0x40000100)
                 printf("bootmemwrite[%.016lX] = %.016lX\n", i*8+addr, buffer[i]);
#endif
               write_data(baddr, beats, buffer);
               rdata = read_data(baddr, beats);
               for (i = 0; i < beats; i++)
                 if (rdata[i] != buffer[i])
                   printf("%d/%d: bootmemverify[%.016lX] = %.016lX (was %.016lX)\n", i+1, beats+1, i*8+addr, rdata[i], buffer[i]);
             }
           else
             {
               // read
               rdata = read_data(baddr, beats);
#if 0
               for (i = 0; i < beats; i++) if (i*8+addr < 0x40000020)
                                             printf("bootmemread[%.016lX] = %.016lX\n", i*8+addr, rdata[i]);
#endif
               memcpy(buffer, rdata, size);
             }
         }
       else
         {
           int i, beats = (size+sizeof(uint64_t)-1)/sizeof(uint64_t);
           uint64_t *zeros = (uint64_t *)calloc(beats, sizeof(uint64_t));
           if (write)
             {
               //               enum {chunk=2048};
               enum {chunk=1024};
               // write
               while (beats > chunk)
                 {
                   write_chunk(addr, chunk, buffer, zeros);
                   addr += chunk*sizeof(uint64_t);
                   buffer += chunk;
                   beats -= chunk;
                 }
               write_chunk(addr, beats, buffer, zeros);
             }
           else
             {
               // read
               write_data(shared_addr, beats, zeros);
               dma_copy(addr, axi_shared_addr, -1, beats);
               rdata = read_data(shared_addr, beats);
               for (i = 0; i < beats; i++)
                 printf("memread[%.016lX] = %.016lX\n", i*8+addr, rdata[i]);
               memcpy(buffer, rdata, size);
             }
           free(zeros);
         }
     }

typedef struct chain {
  uint8_t *buf;
  uint64_t addr;
  uint64_t bufsz;
  struct chain *nxt;
} chain_t;

chain_t *chain_head = NULL;

uint64_t mem_chain(uint8_t *buf, uint64_t addr, uint64_t bufsz)
{
  if (chain_head && chain_head->addr+chain_head->bufsz == addr)
    {
      /* we need to merge the last two blocks */
      chain_head->buf = (uint8_t *)realloc(chain_head->buf, chain_head->bufsz+bufsz);
      assert(chain_head->buf);
      memcpy(chain_head->buf+chain_head->bufsz, buf, bufsz);
      chain_head->bufsz += bufsz;
    }
  else
    {
      chain_t *chain_nxt = (chain_t *)malloc(sizeof(chain_t));
      chain_nxt->buf = (uint8_t *)malloc(bufsz);
      assert(chain_nxt->buf);
      chain_nxt->addr = addr;
      chain_nxt->bufsz = bufsz;
      chain_nxt->nxt = chain_head;
      chain_head = chain_nxt;
      memcpy(chain_nxt->buf, buf, bufsz);
    }
  return bufsz;
}

void chain_load(chain_t *chain_nxt)
{
  if (chain_nxt)
    {
      int round;
      uint64_t *buf2;
      chain_load(chain_nxt->nxt);
      round = (chain_nxt->bufsz+sizeof(uint64_t)-1) & (-sizeof(uint64_t));
      buf2 = (uint64_t *)calloc(sizeof(uint8_t), round);
      memcpy(buf2, chain_nxt->buf, chain_nxt->bufsz);
      fprintf(stderr, "Write address %.lX(len=%ld/round=%d)\n", chain_nxt->addr, chain_nxt->bufsz, round);
      assert(chain_nxt->addr % sizeof(uint64_t) == 0);
      main_access(true, chain_nxt->addr, round, buf2);
      mrange_define(chain_nxt->addr, chain_nxt->bufsz);
      free(buf2);
    }
}

void chain_check(chain_t *chain_nxt)
{
  if (chain_nxt)
    {
      int round;
      uint64_t *buf2;
      chain_check(chain_nxt->nxt);
      round = (chain_nxt->bufsz+sizeof(uint64_t)-1) & (-sizeof(uint64_t));
      buf2 = (uint64_t *)calloc(sizeof(uint8_t), round);
      fprintf(stderr, "Check address %.lX(len=%ld/round=%d): ", chain_nxt->addr, chain_nxt->bufsz, round);
      main_access(false, chain_nxt->addr, round, buf2);
      if (memcmp(chain_nxt->buf, buf2, chain_nxt->bufsz))
        {
          uint64_t tmp;
          fprintf(stderr, "FAILED!\n");
          for (int i = 0; i < round/sizeof(uint64_t); i++)
            {
              memcpy(&tmp, chain_nxt->buf+i*sizeof(uint64_t), sizeof(uint64_t));
              if (buf2[i] != tmp)
                {
                  fprintf(stderr, "At offset %d/%ld, %.016lX != %.016lX\n", i, round/sizeof(uint64_t), buf2[i], tmp);
                }
              exit(1);
            }
        }
      else
        fprintf(stderr, "OK\n");
      free(buf2);
      free(chain_nxt->buf);
      free(chain_nxt);
    }
}

uint64_t regression_load(const char *regression, int voffset)
        {
          uint64_t total_bytes = 0;
          int chk, entry;
          bfd *handle;
          
          hcreate_r(30, &htab);
          bfd_init();
          handle = bfd_openr(regression, "default");
          if (!handle)
            {
              perror(regression);
              exit(1);
            }
          chk = bfd_check_format(handle, bfd_object);
          if (!chk)
            {
              perror(regression);
              exit(1);
            }
          entry = bfd_get_start_address(handle);
          /* load the corresponding section to memory */
          for (asection *s = handle->sections; s; s = s->next)
            {
              int flags = bfd_get_section_flags (handle, s);
              int siz = (unsigned int) bfd_section_size (handle, s);
              bfd_vma lma = (unsigned int) bfd_section_vma (handle, s);
              bfd_vma vma = (unsigned int) bfd_section_vma (handle, s);
              const char *nam = bfd_section_name (handle, s);
              
              if (flags & (SEC_LOAD))
                {
                  if (lma != vma)
                    {
                      fprintf (stderr, "loadable section %s: lma = 0x%08x (vma = 0x%08x)  size = 0x%08x\n",
                              nam,
                              (unsigned int) lma,
                              (unsigned int) vma,
                              siz);
                    }
                  else
                    {
                      bfd_byte contents[siz];
                      
                      fprintf (stderr, "loadable section %s: addr = 0x%08x size = 0x%08x (voffset=%x)\n",
                              nam,
                              (unsigned int) vma,
                               siz,
                               -voffset);
                      if (bfd_get_section_contents (handle, s,
                                                    contents, (file_ptr) 0,
                                            siz))
                        {
                          if (strcmp(nam,".sdata.CSWTCH.80") && strcmp(nam, ".sdata.Stat")) // Yikes
                            total_bytes += mem_chain(contents, vma-voffset, siz);
                        }
                    }
                }
              else
                {
                  fprintf (stderr, "non-loadable section %s: addr = 0x%08x size = 0x%08x (voffset=%x)\n",
                          nam,
                          (unsigned int) vma,
                           siz, -voffset);
                  if (vma)
                    {
                      uint8_t *buf = (uint8_t *)calloc(sizeof(uint8_t), siz);
                      total_bytes += mem_chain(buf, vma-voffset, siz);
                      free(buf);
                    }
                }
            }                   //end of for loop
          
          fprintf(stderr, "Loaded: %ld B\n", total_bytes);

          bfd_close(handle);
          chain_load(chain_head);
          chain_check(chain_head);
          return entry;
        }

void regression_test(const char *regression, int voffset)
        {
          static char env[256];
          uint64_t entry = regression_load(regression, voffset);
          printf("Entry point is at address %.8lX\n", entry);
          if (formal)
            {
              sprintf(env, "SIM_ELF_FILENAME=%s", regression);
              putenv(env);
              rocketlog_main(regression);
            }
          capture_flags(capture_rst);
          cpu_ctrl(DBG_NPC, entry, 1);
          cpu_ctrl(DBG_PPC, entry, 1);
          cpu_ctrl(DBG_CTRL, 0x1, 1); // This seems to be necessary to latch the PC
          axi_counters();
          capture_flags(cpu_capture);
          if (step)
            {
              do
                {
                  cpu_ctrl(DBG_CTRL, 0x1, 1);
                }
              while (jtag_peek(cap_addr) < 0x1FF);
            }
          else
            {
              cpu_reset();
              usleep(10000);
              axi_counters();
              //              cpu_debug();
            }
          cpu_commit_status();        
        }

int main(int argc, const char **argv)
{
  int memtest = 0;
  int bridge = 0;
  int grab = 0;
  int vidtest = 0;
  int axitest = 0;
  int dmatest = 0;
  int voffset = 0;
  const char *interface = "ftdi";
  srand48(time(0));
  while (argc >= 2 && (argv[1][0]=='-'))
    {
    switch(argv[1][1])
      {
      case 'c':
        capture = 1;
        break;
      case 'd':
        dmatest = 1;
        break;
      case 'f':
        formal = 1;
        break;
      case 'g':
        grab = 1;
        break;
      case 'i':
        interface = 2+argv[1];
        break;
      case 'o':
        voffset = strtol(2+argv[1], NULL, 16);
        break;
      case 'p':
        bridge = atoi(2+argv[1]);
        break;
      case 'r':
        regression = 2+argv[1];
        break;
      case 's':
        step = 1;
        break;
      case 't':
        memtest = 1;
        break;
      case 'v':
        verbose = 1 + atoi(2+argv[1]);
        break;
      case 'x':
        axitest = 1;
        break;
      case 'z':
        vidtest = 1;
        break;
      }
    --argc; ++argv;
    }
  my_command_init(verbose, interface);
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
      dbg_master = 0;
      cpu_debug();
      if (grab)
        {
          enum {burst=1<<12};
          uint64_t *chk = read_data(boot_addr, burst);
          FILE *grabf = fopen("grab.txt", "w");
          fwrite(chk, burst, sizeof(uint64_t), grabf);
        }
      if (dmatest) axi_dma();
      if (memtest)
        {
          enum {burst=128};
          uint64_t *chk1, *chk2, *pattern1 = calloc(burst, sizeof(uint64_t));;
          for (int j = 0; j < burst; j++) pattern1[j] = 1ULL << j&63;
          tstcnt = 0;
          my_mem_test(12, axi_shared_addr);
          printf("Shared addr tests passed = %d\n", tstcnt);
          tstcnt = 0;
          my_mem_test(14, boot_addr);
          printf("Boot addr tests passed = %d\n", tstcnt);
          
          dma_copy(axi_base, axi_shared_addr, -1, burst);
          chk1 = read_data(shared_addr, burst);
          chk2 = read_data(boot_addr, burst);
          for (int i = 0; i < burst; i++)
            {
              if (chk1[i] != chk2[i])
                {
                  printf("Readback mismatch at offset %d (%.016lX != %.016lX)\n", i, chk1[i], chk2[i]);
                }
            }
          my_mem_test(12, shared_addr);
          dma_copy(axi_shared_addr, axi_base, -1, burst);
          chk1 = read_data(shared_addr, burst);
          chk2 = read_data(boot_addr, burst);
          for (int i = 0; i < burst; i++)
            {
              if (chk1[i] != chk2[i])
                {
                  printf("Readback mismatch at offset %d (%.016lX != %.016lX)\n", i, chk1[i], chk2[i]);
                }
            }
        }
      if (axitest)
        {
          axi_ramtest(axi_vga_addr, 1 << 12);
          //          axi_ramtest(axi_base, 1 << 12);
          axi_ramtest(axi_ddr, 1 << 7);
        }
      if (vidtest)
        {
          axi_vga(" ** Hello JTAG Master ** ");
          axi_dipsw();
        }
      if (regression)
        {
          regression_test(regression, voffset);
        }
      if (bridge)
        {
          new_bridge(bridge);
        }
      svf_free();
    }
}

extern void hid_init(void);
extern void hid_console_putchar(unsigned char ch);
extern void hid_send_string(const char *str);

void hid_console_putchar(unsigned char ch)
{
  switch(ch)
    {
    case 8: case 127: if (addr_int & 127) hid_vga_ptr[--addr_int] = ' '; break;
    case 13: addr_int = addr_int & -128; break;
    case 10:
      {
        int lmt = (addr_int|127)+1;
        while (addr_int < lmt) hid_vga_ptr[addr_int++] = ' ';
        break;
      }
    default: hid_vga_ptr[addr_int++] = ch;
    }
  if (addr_int >= 4096-128)
    {
      // this is where we scroll
      for (addr_int = 0; addr_int < 4096; addr_int++)
        if (addr_int < 4096-128)
          hid_vga_ptr[addr_int] = hid_vga_ptr[addr_int+128];
        else
          hid_vga_ptr[addr_int] = ' ';
      addr_int = 4096-256;
    }
}

void hid_send_string(const char *str) {
  while (*str) hid_console_putchar(*str++);
}

uint64_t htonll(uint64_t addr)
{
  uint64_t rslt;
  uint32_t tmp[2];
  uint32_t tmp2[2];
  memcpy(tmp, &addr, sizeof(uint64_t));
  tmp2[1] = htonl(tmp[0]);
  tmp2[0] = htonl(tmp[1]);
  memcpy(&rslt, tmp2, sizeof(uint64_t));
  return rslt;
}

uint64_t ntohll(uint64_t addr)
{
  uint64_t rslt;
  uint32_t tmp[2];
  uint32_t tmp2[2];
  memcpy(tmp, &addr, sizeof(uint64_t));
  tmp2[1] = ntohl(tmp[0]);
  tmp2[0] = ntohl(tmp[1]);
  memcpy(&rslt, tmp2, sizeof(uint64_t));
  return rslt;
}

