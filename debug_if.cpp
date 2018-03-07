
#include "debug_if.h"
#include "main.h"
#include "mem.h"

#include <stdio.h>

DbgIF::DbgIF(MemIF* mem, unsigned int base_addr, LogIF *log) {
  this->m_mem = mem;
  this->m_base_addr = base_addr;
  this->log = log;

  // let's discover core id and cluster id
  this->halt();
  this->csr_read(0xF10, &m_thread_id);
  log->debug("Found a core with id %X\n", m_thread_id);
}

void
DbgIF::flush() {
  // Write back the value of NPC so that it triggers a flush of the prefetch buffer
  uint64_t npc;
  read(DBG_NPC_REG, &npc);
  write(DBG_NPC_REG, npc);
}

bool
DbgIF::write(uint32_t addr, uint64_t wdata) {
  cpu_ctrl(addr, wdata, 0);
  return true;
}

bool
DbgIF::write_and_stop(uint32_t addr, uint64_t wdata) {
  cpu_ctrl(addr, wdata, 1);
  return true;
}

bool
DbgIF::write_and_go(uint32_t addr, uint64_t wdata) {
  cpu_ctrl(addr, wdata, -1);
  return true;
}

bool
DbgIF::read(uint32_t addr, uint64_t* rdata) {
  *rdata = cpu_read(addr);
  return true;
}

bool
DbgIF::halt() {
  uint64_t data;
  if (!this->read(DBG_CTRL_REG, &data)) {
    fprintf(stderr, "debug_is_stopped: Reading from CTRL reg failed\n");
    return false;
  }

  data |= 0x1 << 16;
  return this->write(DBG_CTRL_REG, data);
}

bool
DbgIF::is_stopped() {
    return cpu_is_stopped();
}

bool
DbgIF::gpr_read_all(uint64_t *data) {
  for (int i = 0; i < 32; i++)
    {
      data[i] = cpu_read(DBG_GPR+i*8);
    }
  return true;
}

bool
DbgIF::gpr_read(unsigned int i, uint64_t *data) {
  return this->read(DBG_GPR + i * 8, data);
}

bool
DbgIF::gpr_write(unsigned int i, uint64_t data) {
  return this->write_and_stop(DBG_GPR + i * 8, data);
}

bool
DbgIF::csr_read(unsigned int i, uint64_t *data) {
  return this->read(CSR_BASE + i * 8, data);
}

bool
DbgIF::csr_write(unsigned int i, uint64_t data) {
  return this->write_and_stop(CSR_BASE + i * 8, data);
}

void
DbgIF::get_name(char* str, size_t len) {
  snprintf(str, len, "Core %08lX", this->m_thread_id);
}
