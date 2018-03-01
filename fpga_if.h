#ifndef FPGA_H
#define FPGA_H

#include "mem.h"

#include <stdint.h>

class FpgaIF : public MemIF {
  public:
    FpgaIF();
    ~FpgaIF();

    bool access(bool write, uint64_t addr, int size, uint64_t *buffer);

  private:
    bool mem_write(uint64_t addr, uint8_t be, uint64_t wdata);
    bool mem_read(uint64_t addr, uint64_t *rdata);

    int g_spi_fd;
};

#endif
