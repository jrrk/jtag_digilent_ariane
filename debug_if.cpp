
#include "debug_if.h"
#include "main.h"
#include "mem.h"

#include <stdio.h>

DbgIF::DbgIF(MemIF* mem, unsigned int base_addr, LogIF *log) {
  this->m_mem = mem;
  this->m_base_addr = base_addr;
  this->log = log;
  pc_override(false);

  // let's discover core id and cluster id
  this->halt();
  this->csr_read(0xF10, &m_thread_id);
  log->debug("Found a core with id %X\n", m_thread_id);
}

void
DbgIF::pc_override(bool status) {
  m_pc_override = status;
  if (status)
    printf("pc_override on\n");
  else
    printf("pc_override off\n");
}

void
DbgIF::pc_write(uint64_t wdata) {
  write_and_stop(DBG_NPC_REG, wdata);
  write_and_stop(DBG_PPC_REG, wdata);
  pc_override(true);
}

bool
DbgIF::pc_read(uint64_t* pc) {
  uint64_t npc;
  uint64_t ppc;
  uint64_t cause;
  uint64_t hit;

  read(DBG_PPC_REG, &ppc);
  read(DBG_NPC_REG, &npc);

  read(DBG_HIT_REG, &hit);
  read(DBG_CAUSE_REG, &cause);

  if (m_pc_override)
    *pc = ppc;
  else if (npc && (hit & 0x1))
    *pc = npc;
  else if(cause & (1 << 31)) // interrupt
    *pc = npc;
  else if(cause == 3)  // breakpoint
    *pc = ppc;
  else if(cause == 2)
    *pc = ppc;
  else if(cause == 5)
    *pc = ppc;
  else if(npc)
    *pc = npc;
  else
    *pc = ppc;
  
  return true;
}

void
DbgIF::flush() {
  // Write back the value of NPC so that it triggers a flush of the prefetch buffer
  uint64_t npc;
  pc_read(&npc);
  pc_write(npc);
}

bool
DbgIF::write(uint32_t addr, uint64_t wdata) {
  printf("reg_write(%s,%.016lX)\n", dbgnam(addr), wdata);
  cpu_ctrl(addr, wdata, 0);
  return true;
}

bool
DbgIF::write_and_stop(uint32_t addr, uint64_t wdata) {
  printf("reg_write_and_stop(%s,%.016lX)\n", dbgnam(addr), wdata);
  if (addr==DBG_CTRL_REG)
    pc_override(false);
  cpu_ctrl(addr, wdata, 1);
  return true;
}

bool
DbgIF::write_and_go(uint32_t addr, uint64_t wdata) {
  printf("reg_write_and_go(%s,%.016lX)\n", dbgnam(addr), wdata);
  cpu_ctrl(addr, wdata, -1);
  return true;
}

bool
DbgIF::read(uint32_t addr, uint64_t* rdata) {
  *rdata = cpu_read(addr);
  printf("reg_read(%s) => %.016lX\n", dbgnam(addr), *rdata);
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
