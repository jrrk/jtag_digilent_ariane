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
  const char *interface = getenv("INTERFACE");
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
  my_command.argv = interface ? argvi : argv3;
  handle_interface_command (&my_command);
  if (interface && !strcmp(interface, "remote_bitbang"))
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
  else if (interface && !strcmp(interface, "jtag_vpi"))
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
  else
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
      case DBG_RA      : return "DBG_RA      ";
      case DBG_SP      : return "DBG_SP      ";
      case DBG_GP      : return "DBG_GP      ";
      case DBG_TP      : return "DBG_TP      ";
      case DBG_T0      : return "DBG_T0      ";
      case DBG_T1      : return "DBG_T1      ";
      case DBG_T2      : return "DBG_T2      ";
      case DBG_S0      : return "DBG_S0      ";
      case DBG_S1      : return "DBG_S1      ";
      case DBG_A0      : return "DBG_A0      ";
      case DBG_A1      : return "DBG_A1      ";
      case DBG_A2      : return "DBG_A2      ";
      case DBG_A3      : return "DBG_A3      ";
      case DBG_A4      : return "DBG_A4      ";
      case DBG_A5      : return "DBG_A5      ";
      case DBG_A6      : return "DBG_A6      ";
      case DBG_A7      : return "DBG_A7      ";
      case DBG_S2      : return "DBG_S2      ";
      case DBG_S3      : return "DBG_S3      ";
      case DBG_S4      : return "DBG_S4      ";
      case DBG_S5      : return "DBG_S5      ";
      case DBG_S6      : return "DBG_S6      ";
      case DBG_S7      : return "DBG_S7      ";
      case DBG_S8      : return "DBG_S8      ";
      case DBG_S9      : return "DBG_S9      ";
      case DBG_S10     : return "DBG_S10     ";
      case DBG_S11     : return "DBG_S11     ";
      case DBG_T3      : return "DBG_T3      ";
      case DBG_T4      : return "DBG_T4      ";
      case DBG_T5      : return "DBG_T5      ";
      case DBG_T6      : return "DBG_T6      ";

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

void verify_poke(uint32_t addr, uint64_t data, uint64_t mask)
{
  uint64_t rslt;
  jtag_poke(addr, data);
  rslt = jtag_peek(addr);
  if (data != (rslt&~mask))
    {
      printf("JTAG verify mismatch: %.16lX != %.16lX\n", data, rslt);
    }
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
  ctrl = cpu_we|cpu_req|halt|cpu_nofetch|(cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  ctrl = cpu_req|cpu_nofetch|(cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  rslt = jtag_peek(debug_addr_lo);
  ctrl = (cpu_addr&cpu_addr_mask);
  verify_poke(debug_addr_hi, ctrl, cpu_gnt_ro|cpu_halted_ro|cpu_rvalid_ro);
  if (verbose)
    printf("cpu_ctrl(0x%.4X,%s): wrote 0x%.16lX, read 0x%.16lX\n", cpu_addr, dbgnam(cpu_addr), cpu_data, rslt);
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

void cpu_debug(void)
{
  int stopped;
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

typedef struct {  
  uint64_t cap_rst; uint64_t wrap_rst; uint64_t reset;
  uint64_t go; uint64_t inc; uint64_t rnw; uint64_t size; uint64_t length; uint64_t axi_addr;
  } axi_rec_t;

void axi_poke(axi_rec_t *burst)
{
  uint64_t mask = ((burst->cap_rst&1)<<52)|
    ((burst->wrap_rst&1)<<51)|((burst->reset&1)<<50)|
    ((burst->go&1)<<49)|((burst->inc&1)<<48)|((burst->rnw&1)<<47)|
    ((burst->size&0x7F)<<40)|((burst->length&0xFF)<<32)|(burst->axi_addr&0xFFFFFFFF);
  verify_poke(burst_addr, mask, 0);  
}

void axi_counters(void)
{
  uint64_t status = jtag_peek(status_addr);
  uint32_t wrapaddr = status&0xFFFFFFFF;
  printf("Wrap address: %.08X\n", wrapaddr);
  uint64_t capa = jtag_peek(cap_addr);
  printf("Capture address: %.16lX\n", capa);
}

void axi_status(void)
{
  uint64_t status = jtag_peek(status_addr);
  axi_counters();
  switch( (status>>32)&7)
    {
    case axi_state_reset: printf("State: reset\n"); break;
    case axi_state_idle: printf("State: idle\n"); break;
    case axi_state_prepare: printf("State: prepare\n"); break;
    case axi_state_read_transaction: printf("State: read_transaction\n"); break;
    case axi_state_write_transaction: printf("State: write_transaction\n"); break;
    case axi_state_error_detected: printf("State: error_detected\n"); break;
    case axi_state_complete: printf("State: complete\n"); break;
    case axi_state_unknown:  printf("State: unknown\n"); break;
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
  printf("write_response_transaction_finished: %lX\n", (status>>44)&1);
  printf("write_data_transaction_finished: %lX\n", (status>>45)&1);
  printf("read_data_transaction_finished: %lX\n", (status>>46)&1);
  printf("write_address_transaction_finished: %lX\n", (status>>47)&1);
  printf("read_address_transaction_finished: %lX\n", (status>>48)&1);
  switch( (status>>49)&7)
    {
    case 000: printf("Read address channel state: reset\n"); break;
    case 001: printf("Read address channel state: idle\n"); break;
    case 002: printf("Read address channel state: running\n"); break;
    case 003: printf("Read address channel state: error_detected\n"); break;
    case 004: printf("Read address channel state: complete\n"); break;
    default:  printf("Read address channel state: unknown\n"); break;
    }
  switch( (status>>52)&7)
    {
    case 000: printf("Write response channel state: reset\n"); break;
    case 001: printf("Write response channel state: idle\n"); break;
    case 002: printf("Write response channel state: running\n"); break;
    case 003: printf("Write response channel state: success\n"); break;
    case 004: printf("Write response channel state: error_detected\n"); break;
    case 005: printf("Write response channel state: complete\n"); break;
    default:  printf("Write response channel state: unknown\n"); break;
    }
  printf("Protocol checker assert: %lX\n", (status>>55)&1);
  printf("Capture busy: %lX\n", (status>>56)&1);
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

axi_t *dbg;
uint64_t *cap_raw;
int cap_offset, vcdcnt = 0;
enum {sleep_dly=100};

static uint64_t ext(int wid)
{
  int shift = cap_offset&63;
  uint64_t retval, mask = 1;
  uint64_t lo = cap_raw[cap_offset>>6];
  uint64_t hi = (cap_raw[(cap_offset>>6)+1] << 32) | (lo >> 32);
  assert(wid <= 32);
  if (shift >= 32) // value is split across words (we assume width <= 32)
    {
      retval = hi >> (shift-32);
    }
  else
    retval = lo >> shift;    
  retval &= (mask << wid)-1;
  cap_offset += wid;
  return retval;
}

void axi_capture_status(void)
{
  int j;
  uint64_t status = jtag_peek(cap_addr);
  printf("Capture address: %.16lX\n", status);
  int len = status+1;
  cap_offset = 0;
  cap_raw = read_data(cap_buf, len*8);
  dbg = (axi_t *)calloc(len, sizeof(axi_t));
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
    }
  open_vcd(vcdcnt++);
  for (j = 0; j < len; j++)
    {
      dump_rec(dbg+j);
    }
  close_vcd();
}

int axi_check_status(void)
{
  return (jtag_peek(status_addr)>>32)&7;
}

int axi_check_complete(axi_state_t target_state)
{
  int waiting, waitcnt = 0;
  axi_state_t current_state;
  do {
    current_state = axi_check_status();
    waiting = current_state != target_state;
    if (waiting)
      usleep(sleep_dly);
  }
  while (waiting && ++waitcnt < 100);
  if (waiting)
    {
      printf("AXI timeout, resetting\n");
      return 0;
    }
  return 1;
}

void axi_test(long addr, int rnw, int siz, int len, int bufadr)
{
  axi_rec_t burst;
  if (verbose) printf("Reset...\n");
  burst.reset =  0; // axi_check_complete(axi_state_idle);
  burst.cap_rst = 1;
  burst.wrap_rst = 1;
  burst.go = 0;
  burst.inc = 1;
  burst.rnw = rnw;
  burst.size = siz;
  burst.length = len;
  burst.axi_addr = bufadr;
  axi_poke(&burst);
  usleep(sleep_dly);
  if (verbose) printf("Make idle...\n");
  burst.reset = 1;
  axi_poke(&burst);
  usleep(sleep_dly);
  if (verbose) printf("Enable capture and wrap counters...\n");
  burst.cap_rst = 0;
  burst.wrap_rst = 0;
  burst.axi_addr = addr;
  axi_poke(&burst);
  usleep(sleep_dly);
  if (verbose); axi_counters();
  if (verbose) printf("Go...\n");
  burst.go = 1;
  axi_poke(&burst);
  axi_check_complete(axi_state_complete);
  if (verbose)
    {
      axi_status();
      axi_proto_status();
    }
  if (capture)
      axi_capture_status();
  burst.go = 0;
  axi_poke(&burst);
}

#define HID_VGA 0x2000
#define HID_LED 0x400F
#define HID_DIP 0x401F

enum {burst=128};
enum {scroll_start=0, base=0x40000000};
volatile uint32_t *const sd_base = (uint32_t *)(base+0x01010000);
volatile uint32_t *const hid_vga_ptr = (uint32_t *)(base+0x01008000);
const size_t eth = (base+0x01020000), hid = (base+0x01000000);
static int addr_int = scroll_start;
static long vga_addr = (long)(base+0x01008000);

void axi_vga(const char *str)
{
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
         axi_test(vga_addr+(l<<10), 0, 8, 128, 0);
         
         axi_test(vga_addr+(l<<10), 1, 8, burst, 1<<10);
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

void axi_dipsw(void)
{
  axi_test(hid + HID_DIP*4, 1, 4, 1, -8);
  uint64_t dip = *read_data(shared_addr, 1);
  printf("DIP SW: %.4lX\n", dip);
  axi_test(hid + HID_LED*4, 0, 4, 1, -8);
}

void bist(char *contents)
{
  uint64_t *chk1, *chk2, *rand = calloc(burst, sizeof(uint64_t));
  char *vidtest = (char *)malloc(burst*16);
  for (int i = 0; i < burst*16; i++) vidtest[i] = mrand48();
  if (*contents)
    {
      FILE *fd = fopen(contents,"r");
      if (fd)
        {
          fread(vidtest, burst, 16, fd);
          fclose(fd);
        }
    }
  for (int l = 0; l < 4; l++)
    {
      int matches = 0;
      char msg1[burst+1];
      char msg2[burst+1];
      char msg3[burst+1];
      for (int j = 0; j < burst; j++) rand[j] = rand64()<<8;
      usleep(sleep_dly);
      write_data(shared_addr+burst*8, burst, rand);
      axi_test(vga_addr+(l<<10), 0, 8, burst, burst*8);
      axi_test(vga_addr+(l<<10), 1, 8, burst, burst*16);
      chk1 = read_data(shared_addr+burst*16, burst);
      chk2 = read_data(shared_addr, 1 << 11);
      for (int j = 0; j < burst; j++) msg1[j] = chk1[j]&0x7f;
      for (int j = 0; j < burst; j++) msg2[j] = chk2[j+burst*2]&0x7f;
      msg1[burst] = 0; msg2[burst] = 0; msg3[burst] = 0;
      for (int j = 0; j < (1 << 11) - burst; j++)
        {
          for (int k = 0; k < burst; k++) msg3[k] = chk2[j+k]&0x7f;
          if ((msg3[0] == msg1[0]) && (msg3[1] == msg1[1]))
            {
              ++matches;
              for (l = 0; l < 3; l++)
                printf("Memory match(off=%d+%d): %.2X,%.2X,%.2X\n", j, l, msg1[l], msg2[l], msg3[l]);
            }
        }
      printf("Matches = %d\n", matches);
    }
  free(rand);
}

int main(int argc, const char **argv)
{
  int memtest = 0;
  int bridge = 0;
  int vidtest = 0;
  srand48(time(0));
  while (argc >= 2 && (argv[1][0]=='-'))
    {
    switch(argv[1][1])
      {
      case 'c':
        capture = 1;
        break;
      case 'p':
        bridge = atoi(2+argv[1]);
        break;
      case 't':
        memtest = 1;
        break;
      case 'v':
        verbose = 1 + atoi(2+argv[1]);
        break;
      case 'z':
        vidtest = 1;
        break;
      }
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
      dbg_master = 0;
      cpu_debug();
      if (memtest)
        {
          uint64_t *chk1, *chk2, *pattern1 = calloc(burst, sizeof(uint64_t));;
          for (int j = 0; j < burst; j++) pattern1[j] = 1ULL << j&63;
          tstcnt = 0;
          my_mem_test(12, shared_addr);
          printf("Shared addr tests passed = %d\n", tstcnt);
          tstcnt = 0;
          my_mem_test(14, boot_addr);
          printf("Boot addr tests passed = %d\n", tstcnt);
          
          axi_test(base, 1, 8, burst, 0);
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
          axi_test(base, 0, 8, burst, 0);
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
      if (vidtest)
        {
          axi_vga(" ** Hello JTAG Master ** ");
          axi_dipsw();
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

