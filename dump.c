#include <stdio.h>
#include <memory.h>
#include <assert.h>
#include "dump.h"

FILE *vcdf;
static char *name[256];
static int width[256];
static uint64_t prev[256];
static int cnt, last;

void open_vcd(int vcdcnt)
{
  char nam[20];
  sprintf(nam, "test%d.vcd", vcdcnt);
  vcdf = fopen(nam,"w");
  assert(vcdf != NULL);
  memset(prev, -1, sizeof(prev));
  cnt = 0;
        width['!'] = 9;
	width['"'] = 1;
	width['#'] = 1;
	width['$'] = 1;
	width['%'] = 4;
	width['&'] = 32;
	width['\''] = 8;
	width['('] = 3;
	width[')'] = 2;
	width['*'] = 1;
	width['+'] = 4;
	width[','] = 3;
	width['-'] = 4;
	width['.'] = 4;
	width['/'] = 2;
	width['0'] = 1;
	width['1'] = 1;
	width['2'] = 1;
	width['3'] = 64;
	width['4'] = 8;
	width['5'] = 2;
	width['6'] = 1;
	width['7'] = 1;
	width['8'] = 4;
	width['9'] = 2;
	width[':'] = 2;
	width[';'] = 1;
	width['<'] = 1;
	width['='] = 4;
	width['>'] = 32;
	width['?'] = 8;
	width['@'] = 3;
	width['A'] = 2;
	width['B'] = 1;
	width['C'] = 4;
	width['D'] = 3;
	width['E'] = 4;
	width['F'] = 4;
	width['G'] = 2;
	width['H'] = 1;
	width['I'] = 1;
	width['J'] = 4;
	width['K'] = 1;
	width['L'] = 64;
	width['M'] = 2;
	width['N'] = 2;
	width['O'] = 1;
	width['P'] = 1;
	width['Q'] = 3;
	width['R'] = 3;
	width['S'] = 1;
	width['T'] = 1;
	width['U'] = 1;
	width['V'] = 1;
	width['W'] = 1;
	width['X'] = 1;
	width['Y'] = 1;
	width['Z'] = 1;
	width['['] = 1;
	width['\\'] = 1;
	width[']'] = 3;
	width['^'] = 3;
	width['_'] = 8;
	width['`'] = 1;
	width['a'] = 64;
	width['b'] = 16;
	width['c'] = 64;
	width['d'] = 1;
	width['e'] = 1;
	width['f'] = 14;
	width['g'] = 1;
	width['h'] = 18;

        name['!'] = "cap_address";
        name['"'] = "error";
        name['#'] = "busy";
        name['$'] = "done";
        name['%'] = "axi_awid";
        name['&'] = "axi_awaddr";
        name['\''] = "axi_awlen";
        name['('] = "axi_awsize";
        name[')'] = "axi_awburst";
        name['*'] = "axi_awlock";
        name['+'] = "axi_awcache";
        name[','] = "axi_awprot";
        name['-'] = "axi_awqos";
        name['.'] = "axi_awregion";
        name['/'] = "axi_awuser";
        name['0'] = "axi_awvalid";
        name['1'] = "axi_awready";
        name['2'] = "axi_wlast";
        name['3'] = "axi_wdata";
        name['4'] = "axi_wstrb";
        name['5'] = "axi_wuser";
        name['6'] = "axi_wvalid";
        name['7'] = "axi_wready";
        name['8'] = "axi_bid";
        name['9'] = "axi_bresp";
        name[':'] = "axi_buser";
        name[';'] = "axi_bvalid";
        name['<'] = "axi_bready";
        name['='] = "axi_arid";
        name['>'] = "axi_araddr";
        name['?'] = "axi_arlen";
        name['@'] = "axi_arsize";
        name['A'] = "axi_arburst";
        name['B'] = "axi_arlock";
        name['C'] = "axi_arcache";
        name['D'] = "axi_arprot";
        name['E'] = "axi_arqos";
        name['F'] = "axi_arregion";
        name['G'] = "axi_aruser";
        name['H'] = "axi_arvalid";
        name['I'] = "axi_arready";
        name['J'] = "axi_rid";
        name['K'] = "axi_rlast";
        name['L'] = "axi_rdata";
        name['M'] = "axi_rresp";
        name['N'] = "axi_ruser";
        name['O'] = "axi_rvalid";
        name['P'] = "axi_rready";
        name['Q'] = "state";
        name['R'] = "state_resp";
	name['S'] = "strt_wrt";
	name['T'] = "strt_wdt";
	name['U'] = "strt_wat";
	name['V'] = "strt_rdt";
	name['W'] = "strt_rat";
	name['X'] = "wrt_fin";
	name['Y'] = "wdt_fin";
	name['Z'] = "rdt_fin";
	name['['] = "wat_fin";
	name['\\'] = "rat_fin";
	name[']'] = "state_wrd";
	name['^'] = "state_rac";
	name['_'] = "boot_we";
	name['`'] = "boot_en";
	name['a'] = "boot_wdata";
	name['b'] = "boot_addr";
	name['c'] = "boot_rdata";
	name['d'] = "write_valid";
	name['e'] = "read_valid";
	name['f'] = "wrap_addr";
	name['g'] = "wrap_en";
	name['h'] = "wrap_rdata";

	fprintf(vcdf, "$date\n");
	fprintf(vcdf, "	Wed Feb 21 14:40:43 2018\n");
	fprintf(vcdf, "$end\n");
	fprintf(vcdf, "\n");
	fprintf(vcdf, "$version\n");
	fprintf(vcdf, "	Synopsys VCS version L-2016.06_Full64\n");
	fprintf(vcdf, "$end\n");
	fprintf(vcdf, "\n");
	fprintf(vcdf, "$timescale\n");
	fprintf(vcdf, "	10ns\n");
	fprintf(vcdf, "$end\n");
	fprintf(vcdf, "\n");
	fprintf(vcdf, "$scope module cap_buf $end\n");
	fprintf(vcdf, "\n");

        last = sizeof(width)/sizeof(*width);
        while (!width[--last])
          ;
        for (int i = '!'; i <= last; i++)
          {
            int w = width[i];
            char nambuf[256];
            if (w > 1)
              sprintf(nambuf, " [%d:0]", w-1);
            else
              *nambuf = 0;
            fprintf(vcdf, "$var wire %d %c %s%s $end\n", w, i, name[i], nambuf);
          }
	fprintf(vcdf, "$upscope $end\n");
	fprintf(vcdf, "\n");
	fprintf(vcdf, "$enddefinitions $end\n");
	fprintf(vcdf, "\n");
	fprintf(vcdf, "#0\n");
	fprintf(vcdf, "$dumpvars\n");
}

void bin(uint64_t value, int wid)
{
  if (wid > 1) bin(value>>1, wid-1);
  fputc((value&1)+'0', vcdf);
}

static void dump(int i, int w, uint64_t value)
{
  if (prev[i] != value)
    {
      if (w > 1)
        {
          fprintf(vcdf, "b");
          bin(value, w);
          fprintf(vcdf, " %c\n", i);
        }
      else
        fprintf(vcdf, "%c%c\n", value&1?'1':'0', i);
    }
  prev[i] = value;
}

void dump_rec(axi_t *rec)
{
  for (int i = '!'; i <= last; i++)
    {
      int w = width[i];
      char nambuf[256];
      if (w > 1)
        sprintf(nambuf, " [%d:0]", w-1);
      else
        *nambuf = 0;
      switch(i)
        {
        case '!': dump(i, w, rec->address); break;
        case '"': dump(i, w, rec->error); break;
        case '#': dump(i, w, rec->busy); break;
        case '$': dump(i, w, rec->done); break;
        case '%': dump(i, w, rec->aw_id); break;
        case '&': dump(i, w, rec->aw_addr); break;
        case '\'': dump(i, w, rec->aw_len); break;
        case '(': dump(i, w, rec->aw_size); break;
        case ')': dump(i, w, rec->aw_burst); break;
        case '*': dump(i, w, rec->aw_lock); break;
        case '+': dump(i, w, rec->aw_cache); break;
        case ',': dump(i, w, rec->aw_prot); break;
        case '-': dump(i, w, rec->aw_qos); break;
        case '.': dump(i, w, rec->aw_region); break;
        case '/': dump(i, w, rec->aw_user); break;
        case '0': dump(i, w, rec->aw_valid); break;
        case '1': dump(i, w, rec->aw_ready); break;
        case '2': dump(i, w, rec->w_last); break;
        case '3': dump(i, w, rec->w_data); break;
        case '4': dump(i, w, rec->w_strb); break;
        case '5': dump(i, w, rec->w_user); break;
        case '6': dump(i, w, rec->w_valid); break;
        case '7': dump(i, w, rec->w_ready); break;
        case '8': dump(i, w, rec->b_id); break;
        case '9': dump(i, w, rec->b_resp); break;
        case ':': dump(i, w, rec->b_user); break;
        case ';': dump(i, w, rec->b_valid); break;
        case '<': dump(i, w, rec->b_ready); break;
        case '=': dump(i, w, rec->ar_id); break;
        case '>': dump(i, w, rec->ar_addr); break;
        case '?': dump(i, w, rec->ar_len); break;
        case '@': dump(i, w, rec->ar_size); break;
        case 'A': dump(i, w, rec->ar_burst); break;
        case 'B': dump(i, w, rec->ar_lock); break;
        case 'C': dump(i, w, rec->ar_cache); break;
        case 'D': dump(i, w, rec->ar_prot); break;
        case 'E': dump(i, w, rec->ar_qos); break;
        case 'F': dump(i, w, rec->ar_region); break;
        case 'G': dump(i, w, rec->ar_user); break;
        case 'H': dump(i, w, rec->ar_valid); break;
        case 'I': dump(i, w, rec->ar_ready); break;
        case 'J': dump(i, w, rec->r_id); break;
        case 'K': dump(i, w, rec->r_last); break;
        case 'L': dump(i, w, rec->r_data); break;
        case 'M': dump(i, w, rec->r_resp); break;
        case 'N': dump(i, w, rec->r_user); break;
        case 'O': dump(i, w, rec->r_valid); break;
        case 'P': dump(i, w, rec->r_ready); break;
        case 'Q': dump(i, w, rec->state); break;
        case 'R': dump(i, w, rec->state_rsp); break;
	case 'S': dump(i, w, rec->strt_wrt); break;
	case 'T': dump(i, w, rec->strt_wdt); break;
	case 'U': dump(i, w, rec->strt_wat); break;
	case 'V': dump(i, w, rec->strt_rdt); break;
	case 'W': dump(i, w, rec->strt_rat); break;
	case 'X': dump(i, w, rec->wrt_fin); break;
	case 'Y': dump(i, w, rec->wdt_fin); break;
	case 'Z': dump(i, w, rec->rdt_fin); break;
	case '[': dump(i, w, rec->wat_fin); break;
	case '\\': dump(i, w, rec->rat_fin); break;
        case ']': dump(i, w, rec->state_wrd); break;
        case '^': dump(i, w, rec->state_rac); break;
        case '_': dump(i, w, rec->boot_we); break;
        case '`': dump(i, w, rec->boot_en); break;
        case 'a': dump(i, w, rec->boot_wdata); break;
        case 'b': dump(i, w, rec->boot_addr); break;
        case 'c': dump(i, w, rec->boot_rdata); break;
        case 'd': dump(i, w, rec->write_valid); break;
        case 'e': dump(i, w, rec->read_valid); break;
        case 'f': dump(i, w, rec->wrap_addr); break;
        case 'g': dump(i, w, rec->wrap_en); break;
        case 'h': dump(i, w, rec->wrap_rdata); break;
        default: break;
        }
    }
  fprintf(vcdf, "#%d\n", ++cnt);
}

void close_vcd(void)
{
	fprintf(vcdf, "$end\n");
        fclose(vcdf);
}
