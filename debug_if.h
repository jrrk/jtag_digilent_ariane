#ifndef DEBUG_IF_H
#define DEBUG_IF_H

#include "mem.h"
#include "main.h"

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#define DBG_CAUSE_BP  0x3

class LogIF {
  public:
    virtual void user(const char *str, ...) = 0;
    virtual void debug(const char *str, ...) = 0;
};

class DbgIF {
  public:
    DbgIF(MemIF* mem, unsigned int base_addr, LogIF *log);

    bool pc_read(uint64_t* pc);
    void pc_write(uint64_t wdata, bool trace_rst);
    void flush();

    bool halt();
    bool resume(bool step);
    bool is_stopped();

    bool write(unsigned int addr, uint64_t wdata);
    bool write_and_stop(unsigned int addr, uint64_t wdata);
    bool write_and_go(unsigned int addr, uint64_t wdata);
    bool read(unsigned int addr, uint64_t* rdata);
    bool step_and_stop(bool capture, uint64_t wdata);
    bool ctrl_and_go();

    bool gpr_write(unsigned int addr, uint64_t wdata);
    bool gpr_read_all(uint64_t* data);
    bool gpr_read(unsigned int addr, uint64_t* data);

    bool csr_write(unsigned int addr, uint64_t wdata);
    bool csr_read(unsigned int addr, uint64_t* rdata);

    unsigned int get_thread_id() { return m_thread_id; }

    void get_name(char* str, size_t len);

  private:
    void pc_override(bool);
    unsigned int m_base_addr;

    uint64_t m_thread_id;
    bool m_pc_override;

    MemIF* m_mem;
    LogIF *log;
};

#endif
