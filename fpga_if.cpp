#include "mem_zynq_spi.h"

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
FpgaIF::mem_write(uint32_t addr, uint8_t be, uint32_t wdata) {

  return true;
}

bool
FpgaIF::mem_read(uint32_t addr, uint32_t *rdata) {

  return true;
}

bool
FpgaIF::access(bool write, unsigned int addr, int size, char* buffer) {
  bool retval = true;
  uint32_t rdata;
  uint8_t be;

  if (write) {
    // write

  } else {
    // read
  }

  return retval;
}
