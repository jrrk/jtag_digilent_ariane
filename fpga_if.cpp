#include "fpga_if.h"
#include "main.h"

#include <byteswap.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <arpa/inet.h>

FpgaIF::FpgaIF() {
  printf("FPGA device opened!\n");
}

FpgaIF::~FpgaIF() {
}

bool
FpgaIF::mem_write(uint64_t addr, uint8_t be, uint64_t wdata) {
  return this->access(true, addr, sizeof(uint32_t), &wdata);
}

bool
FpgaIF::mem_read(uint64_t addr, uint64_t *rdata) {
  return this->access(false, addr, sizeof(uint32_t), rdata);
}

bool
FpgaIF::access(bool write, uint64_t addr, int size, uint64_t *buffer) {
  bool retval = true;
  if (size > 0)
    main_access(write, addr, size, buffer);
  return retval;
}
