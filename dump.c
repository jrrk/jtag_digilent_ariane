#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <memory.h>
#include <assert.h>
#include "dump.h"

FILE *vcdf;
static struct {
  uint64_t dst;
  int width;
} prev[128];
static int time_inc;
static int vcd_offset;

static char *backup(void)
{
  int cnt = -1;
  char nam[20];
  char nam1[20];
  do {
    sprintf(nam1, "test%d.vcd", ++cnt);
    if (!cnt) strcpy(nam, nam1);
  }
  while (!access(nam1, F_OK));
  printf("rename(%s, %s);\n", nam, nam1);
  rename(nam, nam1);
  return strdup(nam);
}

void scope(const char *hier)
{
  if (!hier)
    {
      vcd_offset = '!';
      if (!time_inc)
        {
          time_t now;
          vcdf = fopen(backup(),"w");
          assert(vcdf != NULL);
          time(&now);
          fprintf(vcdf, "$date\n");
          fprintf(vcdf, "	%s\n", ctime(&now));
          fprintf(vcdf, "$end\n");
          fprintf(vcdf, "\n");
          fprintf(vcdf, "$version\n");
          fprintf(vcdf, "	jtag_digilent_ariane\n");
          fprintf(vcdf, "$end\n");
          fprintf(vcdf, "\n");
          fprintf(vcdf, "$timescale\n");
          fprintf(vcdf, "	10ns\n");
          fprintf(vcdf, "$end\n");
          fprintf(vcdf, "\n");
        }
    }
  else if (!time_inc)
    {
      fprintf(vcdf, "$scope module %s $end\n", hier);
      fprintf(vcdf, "\n");
    }
}

void upscope(void)
{
  if (!time_inc)
    {
      assert(vcdf);
      fprintf(vcdf, "$upscope $end\n");
      fprintf(vcdf, "\n");
    }
}

void bin(uint64_t value, int wid)
{
  if (wid > 1) bin(value>>1, wid-1);
  fputc((value&1)+'0', vcdf);
}

static void dump(int i, int w, uint64_t value)
{
  assert(vcdf);
  if (w > 1)
    {
      fprintf(vcdf, "b");
      bin(value, w);
      fprintf(vcdf, " %c\n", i);
    }
  else
    fprintf(vcdf, "%c%c\n", value&1?'1':'0', i);
}

void vcd_info(const char *label, uint64_t dst, int w)
{
  char nambuf[256];
  const char *field = strchr(label, '.');
  const char *name = field ? field+1 : label;
  if (w > 1)
    sprintf(nambuf, " [%d:0]", w-1);
  else
    *nambuf = 0;
  assert(vcdf);
  if (!time_inc)
    {
      assert(vcd_offset < 128);
      prev[vcd_offset].width = w;
      fprintf(vcdf, "$var wire %d %c %s%s $end\n", w, vcd_offset, name, nambuf);
    }
  else
    {
      assert(prev[vcd_offset].width == w);
      if (prev[vcd_offset].dst != dst)
        dump(vcd_offset, w, dst);
    }
  prev[vcd_offset].dst = dst;
  vcd_offset++;
}

void dump_time(void)
{
  assert(vcdf);
  if (!time_inc)
    {
      fprintf(vcdf, "$enddefinitions $end\n");
      fprintf(vcdf, "\n");
      fprintf(vcdf, "#0\n");
      fprintf(vcdf, "$dumpvars\n");
      for (int i = '!'; i < vcd_offset; i++)
        dump(i, prev[i].width, prev[i].dst);
    }
  fprintf(vcdf, "#%d\n", ++time_inc);
  fflush(vcdf);
}

void close_vcd(void)
{
	fprintf(vcdf, "$end\n");
        fclose(vcdf);
        vcdf = 0;
        time_inc = 0;
}
