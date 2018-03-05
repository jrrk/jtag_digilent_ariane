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
  uint64_t *rdata;
  uint8_t be;
  if (size > 0)
     {
  if ((addr >= 0x40000000) && (addr <= 0x4000FFFF))
    {
      int i, beats = (size+sizeof(uint64_t)-1)/sizeof(uint64_t);
      if (write)
          {
            // write
#if 0
            for (i = 0; i < beats; i++)
              printf("memwrite[%.016lX] = %.016lX\n", i*8+addr, buffer[i]);
#endif
            write_data(boot_addr, beats, buffer);
            rdata = read_data(boot_addr, beats);
            for (i = 0; i < beats; i++)
              if (rdata[i] != buffer[i])
                printf("%d/%d: memverify[%.016lX] = %.016lX (was %.016lX)\n", i+1, beats+1, i*8+addr, rdata[i], buffer[i]);
          }
        else
          {
            // read
            rdata = read_data(boot_addr, beats);
#if 0
            for (i = 0; i < beats; i++)
              printf("memread[%.016lX] = %.016lX\n", i*8+addr, rdata[i]);
#endif
            memcpy(buffer, rdata, size);
          }
    }
  else
      {
        int i, beats = (size+sizeof(uint64_t)-1)/sizeof(uint64_t);
        uint64_t *zeros = (uint64_t *)calloc(beats, sizeof(uint64_t));
        if (write)
          {
            // write
#if 0
            for (i = 0; i < beats; i++)
              printf("memwrite[%.016lX] = %.016lX\n", i*8+addr, buffer[i]);
#endif
            write_data(shared_addr, beats, buffer);
            axi_test(addr, 0, 8, beats, 0);
            // verify
            write_data(shared_addr, beats, zeros);
            axi_test(addr, 1, 8, beats, 0);
            rdata = read_data(shared_addr, beats);
            for (i = 0; i < beats; i++)
              if (rdata[i] != buffer[i])
                printf("%d/%d: memverify[%.016lX] = %.016lX (was %.016lX)\n", i+1, beats+1, i*8+addr, rdata[i], buffer[i]);
          }
        else
          {
            // read
            write_data(shared_addr, beats, zeros);
            axi_test(addr, 1, 8, beats, 0);
            rdata = read_data(shared_addr, beats);
            for (i = 0; i < beats; i++)
              printf("memread[%.016lX] = %.016lX\n", i*8+addr, rdata[i]);
            memcpy(buffer, rdata, size);
          }
        free(zeros);
      }
     }
  return retval;
}
