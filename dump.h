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

  uint64_t unused, unused2, address, done, busy, error, state, state_rsp, state_wrd;
  uint64_t strt_wrt, strt_wdt, strt_wat, strt_rdt, strt_rat, wrt_fin, wdt_fin, rdt_fin, wat_fin, rat_fin;
} axi_t;

void open_vcd(int vcdcnt);
void dump_rec(axi_t *rec);
void close_vcd(void);

