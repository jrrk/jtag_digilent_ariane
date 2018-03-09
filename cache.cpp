
#include "cache.h"
#include <stdio.h>

void Cache::flushCores() {
  for (std::list<DbgIF*>::iterator it = p_dbgIfList->begin(); it != p_dbgIfList->end(); it++) {
    (*it)->flush();
  }
}
