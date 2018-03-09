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
    BreakPoints(std::list<DbgIF*> list_dbgif, Cache* cache);

    void insert(int m_thread_sel, uint64_t addr);
    void remove(int m_thread_sel, uint64_t addr);

    void clear(int m_thread_sel);

    bool at_addr(uint64_t addr);

    void enable_all(int m_thread_sel);
    void disable_all(int m_thread_sel);

    void disable(int m_thread_sel, uint64_t addr);
    void enable(int m_thread_sel, uint64_t addr);

  private:
    DbgIF* get_dbgif(int thread_id);
    void sync(int m_thread_sel, int);
    struct bp_insn m_bp[8];
    std::list<DbgIF*> m_dbgifs;
    Cache* m_cache;
};

#endif
