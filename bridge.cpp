#include "bridge.h"
#include "main.h"
#include <stdarg.h>

Platforms platform_detect(MemIF* mem) {
  uint32_t info;

  printf ("Assumed Ariane\n");
  return Ariane;
}

bool platform_ariane(MemIF* mem, std::list<DbgIF*>* p_list, LogIF *log) {
  p_list->push_back(new DbgIF(mem, 0x0, log));

  return true;
}

Bridge::Bridge(Platforms platform, int portNumber, LogIF *log) {
  initBridge(platform, portNumber, NULL, log);
}

Bridge::Bridge(Platforms platform, MemIF *memIF, LogIF *log) {
  initBridge(platform, -1, memIF, log);
}

void Bridge::initBridge(Platforms platform, int portNumber, MemIF *memIF, LogIF *log) {

  // initialization
  if (log == NULL)
    this->log = this;
  else
    this->log = log;

#ifdef FPGA
#ifdef PULPEMU
  mem = new ZynqAPBSPIIF();
#else
  mem = new FpgaIF();
#endif
#else
  if (memIF != NULL) mem = memIF;
  else {
    fprintf(stderr, "Either a memory interface or a port number must be provided\n");
    exit (-1);
  }
#endif

  if (platform == unknown) {
    printf ("Unknown platform, trying auto-detect\n");
    platform = platform_detect(mem);
  }

  switch(platform) {
    case Ariane:
      platform_ariane(mem, &dbgifs, this->log);
      cache = new Cache(mem, &dbgifs);
      break;

    default:
      printf ("ERROR: Unsupported platform found!\n");
      return;
  }

  bp = new BreakPoints(dbgifs, cache);

  rsp = new Rsp(1234, mem, this->log, dbgifs, bp);
}

void Bridge::mainLoop()
{
  // main loop
  while (1) {
    rsp->open();
    while(!rsp->wait_client());
    rsp->loop();
    rsp->close();
  }
}

Bridge::~Bridge()
{
  // cleanup
  delete rsp;

  for (std::list<DbgIF*>::iterator it = dbgifs.begin(); it != dbgifs.end(); it++) {
    delete (*it);
  }

  delete bp;
  delete cache;
  delete mem;
}

void Bridge::user(const char *str, ...)
{
  va_list va;
  va_start(va, str);
  if (verbose)
    vprintf(str, va);
  va_end(va);
}

void Bridge::debug(const char *str, ...)
{
  va_list va;
  va_start(va, str);
  if (verbose)
    vprintf(str, va);
  va_end(va);
}

void new_bridge(int portNumber)
{
  Bridge *bridge = new Bridge(unknown, portNumber);
  bridge->mainLoop();
  delete bridge;
}
