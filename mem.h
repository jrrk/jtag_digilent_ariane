#ifndef MEM_H
#define MEM_H

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

class MemIF {
  public:
    virtual bool access(bool write, uint64_t addr, int size, uint64_t *buffer) = 0;
};

#endif
