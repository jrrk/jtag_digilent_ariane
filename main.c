#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/time_support.h>

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

  int my_command_init(void)
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
#if 1
  my_command.name = "debug_level";
  my_command.argc = 1;
  my_command.argv = argv2;
  handle_debug_level_command(&my_command);
#endif  
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

enum {dbg_req = 1, dbg_resume = 2, dbg_halt = 4, dbg_clksel = 8, dbg_unused = 16};
enum {prog_addr = 0, data_addr = 0x100000, shared_addr = 0x800000, debug_addr = 0xF00000};

enum edcl_mode {
  edcl_mode_unknown,
  edcl_mode_read,
  edcl_mode_write,
  edcl_mode_block_read,
  edcl_mode_bootstrap,
  edcl_max=256};

#pragma pack(4)

static struct etrans {
  enum edcl_mode mode;
  volatile uint32_t *ptr;
  uint32_t val;
} edcl_trans[edcl_max+1];

#pragma pack()

static int edcl_cnt;
static long prev_addr;

/* shared address space pointer (appears at 0x800000 in minion address map */
volatile static struct etrans *shared_base;
volatile uint32_t * const rxfifo_base = (volatile uint32_t*)(4<<20);
void my_addr(long dbg, long inc, long wr, long addr);
uint64_t *raw_read_data(int len);
void raw_write_data(int len, uint64_t *ibuf);

void show_tdo(uint32_t *rslt)
{
  int j;
  if (rslt) for (j = rslt_len(); j--; )
	      printf("%.8X%c", rslt[j], j?':':'\n');
}

void my_addr(long dbg, long inc, long wr, long addr)
{
  char addrbuf[20];
  sprintf(addrbuf, "(%lX)", (dbg<<34)|(inc<<33)|(wr<<32)|addr);
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
    }
  free(rslt);
}

void my_mem_test(int shft, long addr)
{
  int i, j;
  for (i = 1; i < shft; i++)
    {
      static const uint64_t pattern[] = {0xDEAD0000,0xBEEF0000,0xC0010000,0xF00D0000,0xAAAA0000,0x55550000,0x33330000,0xCCCC0000};
      uint64_t *rslt1, *rslt2;
      int len = 1 << i;
      // readout 2^i locations
      my_addr(0,1,0,addr);
      rslt1 = raw_read_data(len);
      for (j = 0; j < len; j++) rslt1[j] = (pattern[(j>>4)&7]<<((j>>7)<<2)) | (1 << (j&15));
      my_addr(0,1,1,addr);
      raw_write_data(len, rslt1);
      my_addr(0,1,0,addr);
      rslt2 = raw_read_data(len);
      for (j = 0; j < len; j++)
	{
	  if (rslt1[j] != rslt2[j])
	    {
	    printf("Memory test mismatch: %.16lX != %.16lX\n", rslt1[j], rslt2[j]);
            //	    abort();
	    }
	}
    }
}

int fact(int n)
{
  return n > 0 ? n * fact(n-1) : 1;
}

void my_jtag(void)
{
  int i;
  svf_init();
  my_svf(TRST, "OFF", NULL);
  my_svf(ENDIR, "IDLE", NULL);
  my_svf(ENDDR, "IDLE", NULL);
  my_svf(STATE, "RESET", NULL);
  my_svf(STATE, "IDLE", NULL);
  my_svf(FREQUENCY, "1.00E+07", "HZ", NULL);
  my_addr(dbg_resume,0,0,shared_addr);
  //  my_mem_test(dbg_halt|dbg_clksel, prog_addr+0x100);
  //  my_mem_test(0, shared_addr+0x10);
  my_mem_test(4, shared_addr);
  svf_free();
}

int main(int argc, const char **argv)
{
  my_command_init();
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
     my_jtag();
   }
}
