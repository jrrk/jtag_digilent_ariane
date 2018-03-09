#ifndef CACHE_H
#define CACHE_H

#include "mem.h"
#include "debug_if.h"
#include <list>

class Cache {
  public:
    Cache(MemIF* mem, std::list<DbgIF*>* dbgIfList) { m_mem = mem; p_dbgIfList = dbgIfList; }

    virtual bool flush() { flushCores(); return true; }
    void flushCores();

  protected:
    MemIF* m_mem;
    std::list<DbgIF*>* p_dbgIfList;
};

#endif
