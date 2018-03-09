
#include "breakpoints.h"
#include "mem.h"

#include <stdio.h>
#include <stdlib.h>

BreakPoints::BreakPoints(std::list<DbgIF*> list_dbgif, Cache* cache) {
  m_dbgifs = list_dbgif;
  m_cache = cache;
}

void
BreakPoints::sync(int m_thread_sel, int idx)
{
  DbgIF *dbgif = this->get_dbgif(m_thread_sel);
  if ((idx >= 0) && (idx <= 7))
    {
      dbgif->write(BP_CTRL0+idx*16, m_bp[idx].enabled && m_bp[idx].present);
      dbgif->write(BP_DATA0+idx*16, m_bp[idx].addr);
    }
}

void
BreakPoints::insert(int m_thread_sel, uint64_t addr) {
  for (int i = 0; i < 8; i++)
    {
      if (!m_bp[i].present)
        {
          m_bp[i].addr = addr;
          m_bp[i].present = true;
          m_bp[i].enabled = true;
          this->sync(m_thread_sel, i);
          return; // m_cache->flush();
        }
    }
}

void
BreakPoints::remove(int m_thread_sel, uint64_t addr) {
  for (int i = 0; i < 8; i++)
    {
    if (m_bp[i].addr == addr) {
      m_bp[i].addr = 0;
      m_bp[i].present = false;
      m_bp[i].enabled = false;
      this->sync(m_thread_sel, i);
      return; // m_cache->flush();
    }
  }
}

void
BreakPoints::clear(int m_thread_sel) {
  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
      m_bp[i].addr = 0;
      m_bp[i].present = false;
      m_bp[i].enabled = false;
      this->sync(m_thread_sel, i);
    }      
}


bool
BreakPoints::at_addr(uint64_t addr) {
  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
    if (m_bp[i].addr == addr)
      // we found our bp
      return true;
    }

  return false;
}

void
BreakPoints::enable(int m_thread_sel, uint64_t addr) {
  uint32_t data;
  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
    if (m_bp[i].addr == addr) {
      m_bp[i].enabled = true;
      this->sync(m_thread_sel, i);
      return; // m_cache->flush();
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %.016lX\n", addr);
}

void
BreakPoints::disable(int m_thread_sel, uint64_t addr) {
  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
    if (m_bp[i].addr == addr) {
      m_bp[i].enabled = false;
      this->sync(m_thread_sel, i);
      return; // m_cache->flush();
    }
  }

  fprintf(stderr, "bp_enable: Did not find any bp at addr %.016lX\n", addr);
}

void
BreakPoints::enable_all(int m_thread_sel) {
  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
      m_bp[i].enabled = true;
      this->sync(m_thread_sel, i);
    }

  return; // m_cache->flush();
}

void
BreakPoints::disable_all(int m_thread_sel) {
  for (int i = 0; i < 8; i++) if ( m_bp[i].present )
    {
      m_bp[i].enabled = false;
      this->sync(m_thread_sel, i);
    }

  return; // m_cache->flush();
}

DbgIF*
BreakPoints::get_dbgif(int thread_id) {
  for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
    if ((*it)->get_thread_id() == thread_id)
      return *it;
  }
  return NULL;
}
