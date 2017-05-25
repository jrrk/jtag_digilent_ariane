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
#if 0
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
uint32_t *raw_read_data(int len);
struct etrans *my_read_data(long addr, int len);
void raw_write_data(int len, uint32_t *ibuf);
void my_write_data(long addr, int len, struct etrans *ibuf);

int shared_read(volatile struct etrans *addr, int cnt, struct etrans *obuf)
  {
    int i;
    struct etrans *rslt;
    long laddr = addr - shared_base;
    rslt = my_read_data(shared_addr+laddr*sizeof(struct etrans), cnt);
    for (i = 0; i < cnt; i++)
      {
        obuf[i] = rslt[i];
#ifdef VERBOSE4
        printf("shared_read(%d, %p) => %p,%x;\n", i, addr+i, obuf[i].ptr, obuf[i].val);
#endif
      }
    return 0;
  }

int shared_write(volatile struct etrans *addr, int cnt, struct etrans *ibuf)
  {
    int i;
    long laddr = addr - shared_base;
    for (i = 0; i < cnt; i++)
      {
#ifdef VERBOSE4
        {
          int j;
          printf("shared_write(%d, %p, 0x%x, 0x%p);\n", i, addr+i, cnt, ibuf);
          for (j = 0; j < sizeof(struct etrans); j++)
            printf("%x ", ((volatile uint8_t *)(&addr[i]))[j]);
          printf("\n");
        }
#endif  
      }
    my_write_data(shared_addr+laddr*sizeof(struct etrans), cnt, ibuf);
    return 0;
  }

int queue_flush(void)
{
  int cnt;
  struct etrans tmp;
  tmp.val = 0xDEADBEEF;
  edcl_trans[edcl_cnt++].mode = edcl_mode_unknown;
#ifdef VERBOSE
  printf("sizeof(struct etrans) = %ld\n", sizeof(struct etrans));
  for (int i = 0; i < edcl_cnt; i++)
    {
      switch(edcl_trans[i].mode)
        {
        case edcl_mode_write:
          printf("queue_mode_write(%p, 0x%x);\n", edcl_trans[i].ptr, edcl_trans[i].val);
          break;
        case edcl_mode_read:
          printf("queue_mode_read(%p, 0x%x);\n", edcl_trans[i].ptr, edcl_trans[i].val);
          break;
        case edcl_mode_unknown:
          if (i == edcl_cnt-1)
            {
            printf("queue_end();\n");
            break;
            }
        default:
          printf("queue_mode %d\n", edcl_trans[i].mode);
          break;
        }
    }
#endif
  shared_write(shared_base, edcl_cnt, edcl_trans);
  shared_write(shared_base+edcl_max, 1, &tmp);
  do {
#ifdef VERBOSE
    int i = 10000000;
    int tot = 0;
    while (i--) tot += i;
    printf("waiting for minion %x\n", tot);
#endif
    shared_read(shared_base, 1, &tmp);
  } while (tmp.ptr);
  tmp.val = 0;
  shared_write(shared_base+edcl_max, 1, &tmp);
  cnt = edcl_cnt;
  edcl_cnt = 1;
  edcl_trans[0].mode = edcl_mode_read;
  edcl_trans[0].ptr = (volatile uint32_t*)(8<<20);
  return cnt;
}

void queue_write(volatile uint32_t *const sd_ptr, uint32_t val, int flush)
 {
   struct etrans tmp;
#if 0
   flush = 1;
#endif   
   tmp.mode = edcl_mode_write;
   tmp.ptr = sd_ptr;
   tmp.val = val;
   edcl_trans[edcl_cnt++] = tmp;
   if (flush || (edcl_cnt==edcl_max-1))
     {
       queue_flush();
     }
#ifdef VERBOSE  
   printf("queue_write(%p, 0x%x);\n", tmp.ptr, tmp.val);
#endif
 }

uint32_t queue_read(volatile uint32_t * const sd_ptr)
 {
   int cnt;
   struct etrans tmp;
   tmp.mode = edcl_mode_read;
   tmp.ptr = sd_ptr;
   tmp.val = 0xDEADBEEF;
   edcl_trans[edcl_cnt++] = tmp;
   cnt = queue_flush();
   shared_read(shared_base+(cnt-2), 1, &tmp);
#ifdef VERBOSE
   printf("queue_read(%p, %p, 0x%x);\n", sd_ptr, tmp.ptr, tmp.val);
#endif   
   return tmp.val;
 }

void queue_read_array(volatile uint32_t * const sd_ptr, uint32_t cnt, uint32_t iobuf[])
 {
   int i, n, cnt2;
   struct etrans tmp;
   if (edcl_cnt+cnt >= edcl_max)
     {
     queue_flush();
     }
   for (i = 0; i < cnt; i++)
     {
       tmp.mode = edcl_mode_read;
       tmp.ptr = sd_ptr+i;
       tmp.val = 0xDEADBEEF;
       edcl_trans[edcl_cnt++] = tmp;
     }
   cnt2 = queue_flush();
   n = cnt2-1-cnt;
   shared_read(shared_base+n, cnt, edcl_trans+n);
   for (i = n; i < n+cnt; i++) iobuf[i-n] = edcl_trans[i].val;
 }

#if 0
uint32_t queue_block_read2(int i)
{
  uint32_t rslt = __be32_to_cpu(((volatile uint32_t *)(shared_base+1))[i]);
  return rslt;
}
#endif

int queue_block_read1(void)
{
   struct etrans tmp;
   queue_flush();
   tmp.mode = edcl_mode_block_read;
   tmp.ptr = rxfifo_base;
   tmp.val = 1;
   shared_write(shared_base, 1, &tmp);
   tmp.val = 0xDEADBEEF;
   shared_write(shared_base+edcl_max, 1, &tmp);
   do {
    shared_read(shared_base, 1, &tmp);
  } while (tmp.ptr);
#ifdef VERBOSE3
   printf("queue_block_read1 completed\n");
#endif
   return tmp.mode;
}

void rx_write_fifo(uint32_t data)
{
  queue_write(rxfifo_base, data, 0);
}

uint32_t rx_read_fifo(void)
{
  return queue_read(rxfifo_base);
}

void write_led(uint32_t data)
{
  volatile uint32_t * const led_base = (volatile uint32_t*)(7<<20);
  queue_write(led_base, data, 1);
}

static void minion_console_putchar(unsigned char ch)
{
  static int addr_int = 0;
  volatile uint32_t * const video_base = (volatile uint32_t*)(10<<20);
  if (ch != 10) queue_write(video_base+addr_int, ch, 0);
  else
    {
      while ((addr_int & 127) < 127)
         {
           queue_write(video_base+addr_int, ' ', 0);
           addr_int++;
         }
    }
  if (++addr_int >= 4096)
    {
      // this is where we would scroll
      addr_int = 0;
    }
}

int minion_console_printf (const char *fmt, ...)
{
  char buffer[99];
  va_list va;
  int i, rslt;
  va_start(va, fmt);
  rslt = vsnprintf(buffer, sizeof(buffer), fmt, va);
  va_end(va);
  for (i = 0; i < rslt; i++) minion_console_putchar(buffer[i]);
  queue_flush();
  return rslt;
}

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

uint32_t *raw_read_data(int len)
{
  uint32_t *rslt;
  char lenbuf[10];
  sprintf(lenbuf, "%d", (1+len)<<5);
  rslt = my_svf(SDR, lenbuf, "TDI", "(0)", "TDO", "(0)", "MASK", "(0)", NULL);
  assert(prev_addr == *rslt);
  return rslt;
}

struct etrans *my_read_data(long addr, int len)
{
  uint32_t *rslt;
  my_addr(0,1,0,addr);
  rslt = raw_read_data(len*sizeof(struct etrans)/sizeof(uint32_t));
  return (struct etrans *)(rslt+1);
}

void raw_write_data(int len, uint32_t *cnvptr)
{
  int j, cnt = 0;
  uint32_t *rslt;
  char lenbuf[10];
  char *outptr = (char *)malloc(len*8+3);
  outptr[cnt++] = '(';
  for (j = len; j--; )
    {
    sprintf(outptr+cnt, "%.08X", cnvptr[j]);
    cnt += 8;
    }
  strcpy(outptr+cnt, ")");
  sprintf(lenbuf, "%d", (len) << 5);
  rslt = my_svf(SDR, lenbuf, "TDI", outptr, "TDO", "(0)", "MASK", "(0)", NULL);
  free(outptr);
  assert(prev_addr == *rslt);
  for (j = 0; j < len-1; j++)
    {
      if (cnvptr[j] != rslt[j+1])
	printf("Write jtag chain mismatch: %.8X != %.8X\n", cnvptr[j], rslt[j+1]);
    }
  free(rslt);
}

void my_write_data(long addr, int len, struct etrans *iptr)
{
  int j;
  uint32_t *rslt2, *rslt1 = (uint32_t *)iptr;
  my_addr(0,1,1,addr);
  raw_write_data(len*sizeof(struct etrans)/sizeof(uint32_t), rslt1);
  my_addr(0,1,0,addr);
  rslt2 = raw_read_data(len*sizeof(struct etrans)/sizeof(uint32_t));
  for (j = 0; j < len*sizeof(struct etrans)/sizeof(uint32_t); j++)
    {
      if (rslt1[j] != rslt2[j+1])
	printf("Memory test mismatch: %.8X != %.8X\n", rslt1[j], rslt2[j+1]);
    }
}

void my_mem_test(int shft, long addr)
{
  int i, j;
  for (i = 1; i < shft; i++)
    {
      static const uint32_t pattern[] = {0xDEAD0000,0xBEEF0000,0xC0010000,0xF00D0000,0xAAAA0000,0x55550000,0x33330000,0xCCCC0000};
      uint32_t *rslt1, *rslt2;
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
	  if (rslt1[j] != rslt2[j+1])
	    {
	    printf("Memory test mismatch: %.8X != %.8X\n", rslt1[j], rslt2[j+1]);
	    abort();
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
  my_mem_test(2, shared_addr);
  write_led(0x55);
  minion_console_printf("lowRISC was here\n");
  for (i = 0; i < 10; i++)
    {
      minion_console_printf("%d! = %d\n", i, fact(i));
    }
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
