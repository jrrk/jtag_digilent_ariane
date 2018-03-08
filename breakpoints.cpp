
#include "breakpoints.h"
#include "mem.h"

#include <stdio.h>
#include <stdlib.h>

BreakPoints::BreakPoints(MemIF* mem, Cache* cache) {
  m_mem   = mem;
  m_cache = cache;
}

void
BreakPoints::sync(int idx)
{
  cpu_ctrl(BP_CTRL0+idx*8, m_bp[idx].enabled, 0);
  cpu_ctrl(BP_DATA0+idx*8, m_bp[idx].addr, 0);  
}

bool
BreakPoints::insert(uint64_t addr) {

  for (int i = 0; i < 8; i++)
    {
      if (!m_bp[i].present)
        {
          m_bp[i].addr = addr;
          m_bp[i].present = true;
          m_bp[i].enabled = true;
          this->sync(i);
        }
    }
  return m_cache->flush();
}

bool
BreakPoints::remove(uint64_t addr) {

  for (int i = 0; i < 8; i++)
    {
    if (m_bp[i].addr == addr) {
      m_bp[i].addr = 0;
      m_bp[i].present = false;
      m_bp[i].enabled = false;
      this->sync(i);
      return m_cache->flush();
    }
  }

  return false;
}

bool
BreakPoints::clear() {

  bool retval = this->disable_all();

  for (int i = 0; i < 8; i++)
    {
      m_bp[i].addr = 0;
      m_bp[i].present = false;
      m_bp[i].enabled = false;
    }      

  return retval;
}


bool
BreakPoints::at_addr(uint64_t addr) {
  for (int i = 0; i < 8; i++)
    {
    if (m_bp[i].addr == addr)
      // we found our bp
      return true;
    }

  return false;
}

bool
BreakPoints::enable(uint64_t addr) {
  bool retval;
  uint32_t data;

  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
    if (m_bp[i].addr == addr) {
      m_bp[i].enabled = true;
      this->sync(i);
      return m_cache->flush();
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %.016lX\n", addr);

  return false;
}

bool
BreakPoints::disable(uint64_t addr) {
  bool retval;

  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
    if (m_bp[i].addr == addr) {
      m_bp[i].enabled = false;
      this->sync(i);
      return m_cache->flush();
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %.016lX\n", addr);

  return false;
}

bool
BreakPoints::enable_all() {
  bool retval = true;

  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
      m_bp[i].enabled = true;
      this->sync(i);
      return m_cache->flush();
    }

  return retval;
}

bool
BreakPoints::disable_all() {
  bool retval = true;

  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
      m_bp[i].enabled = false;
      this->sync(i);
      return m_cache->flush();
    }

  return retval;
}
