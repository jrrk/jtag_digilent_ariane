#ifndef BREAKPOINTS_H
#define BREAKPOINTS_H

#include <stdbool.h>
#include <stdint.h>
#include <list>

#include "mem.h"
#include "cache.h"

struct bp_insn {
  uint64_t addr;
  bool present, enabled;
};

class BreakPoints {
  public:
    BreakPoints(MemIF* mem, Cache* cache);

    bool insert(uint64_t addr);
    bool remove(uint64_t addr);

    bool clear();

    bool at_addr(uint64_t addr);

    bool enable_all();
    bool disable_all();

    bool disable(uint64_t addr);
    bool enable(uint64_t addr);

  private:
    void sync(int);
    struct bp_insn m_bp[8];
    MemIF* m_mem;
    Cache* m_cache;
};

#endif
