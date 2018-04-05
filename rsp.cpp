
#include "rsp.h"
#include "main.h"
#include "riscv-tdep.h"

enum mp_type {
  BP_MEMORY   = 0,
  BP_HARDWARE = 1,
  WP_WRITE    = 2,
  WP_READ     = 3,
  WP_ACCESS   = 4
};

enum target_signal {
  TARGET_SIGNAL_NONE =  0,
  TARGET_SIGNAL_INT  =  2,
  TARGET_SIGNAL_ILL  =  4,
  TARGET_SIGNAL_TRAP =  5,
  TARGET_SIGNAL_FPE  =  8,
  TARGET_SIGNAL_BUS  = 10,
  TARGET_SIGNAL_SEGV = 11,
  TARGET_SIGNAL_ALRM = 14,
  TARGET_SIGNAL_STOP = 17,
  TARGET_SIGNAL_USR2 = 31,
  TARGET_SIGNAL_PWR  = 32
};

#define PACKET_MAX_LEN 4096

Rsp::Rsp(int socket_port, MemIF* mem, LogIF *log, std::list<DbgIF*> list_dbgif, BreakPoints* bp) {
  m_socket_port = socket_port;
  m_mem = mem;
  m_dbgifs = list_dbgif;
  m_bp = bp;
  this->log = log;

  // select one dbg if at random
  if (m_dbgifs.size() == 0) {
    fprintf(stderr, "No debug interface available! Exiting now\n");
    exit(1);
  }

  m_thread_sel = m_dbgifs.front()->get_thread_id();
}

bool
Rsp::open() {
  struct sockaddr_in addr;
  int yes = 1;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(m_socket_port);
  addr.sin_addr.s_addr = INADDR_ANY;
  memset(addr.sin_zero, '\0', sizeof(addr.sin_zero));

  m_socket_in = socket(PF_INET, SOCK_STREAM, 0);
  if(m_socket_in < 0)
  {
    fprintf(stderr, "Unable to create comm socket: %s\n", strerror(errno));
    return false;
  }

  if(setsockopt(m_socket_in, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    fprintf(stderr, "Unable to setsockopt on the socket: %s\n", strerror(errno));
    return false;
  }

  if(bind(m_socket_in, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    fprintf(stderr, "Unable to bind the socket: %s\n", strerror(errno));
    return false;
  }

  if(listen(m_socket_in, 1) == -1) {
    fprintf(stderr, "Unable to listen: %s\n", strerror(errno));
    return false;
  }

  fprintf(stderr, "Debug bridge listening on port %d\n", m_socket_port);

  // now clear resources
  for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
    (*it)->halt();
  }

  return true;
}

void
Rsp::close() {
  m_bp->clear(m_thread_sel);
  ::close(m_socket_in);
}

bool
Rsp::wait_client() {
  if((m_socket_client = accept(m_socket_in, NULL, NULL)) == -1) {
    if(errno == EAGAIN)
      return false;

    fprintf(stderr, "Unable to accept connection: %s\n", strerror(errno));
    return false;
  }

  log->debug("RSP: Client connected!\n");
  return true;
}

bool
Rsp::loop() {
  char pkt[PACKET_MAX_LEN];
  size_t len;

  fd_set rfds;
  struct timeval tv;

  while (this->get_packet(pkt, &len)) {
    if (*pkt != 'X')
      log->debug("Received $%.*s\n", len, pkt);
    if (!this->decode(pkt, len))
      return false;
  }

  return true;
}

bool
Rsp::decode(char* data, size_t len) {
  if (data[0] == 0x03) {
    log->debug ("Received break\n");
    return this->signal();
  }

  switch (data[0]) {
  case 'q':
    return this->query(&data[0], len);

  case 'g':
    return this->regs_send();

  case 'p':
    return this->reg_read(&data[1], len-1);

  case 'P':
    return this->reg_write(&data[1], len-1);

  case 'c':
  case 'C':
    return this->cont(&data[0], len);

  case 's':
  case 'S':
    return this->step(&data[0], len);

  case 'H':
    return this->multithread(&data[1], len-1);

  case 'm':
    return this->mem_read(&data[1], len-1);

  case '?':
    return this->signal();

  case 'v':
    return this->v_packet(&data[0], len);

  case 'M':
    return this->mem_write_ascii(&data[1], len-1);

  case 'X':
    return this->mem_write(&data[1], len-1);

  case 'z':
    return this->bp_remove(&data[0], len);

  case 'Z':
    return this->bp_insert(&data[0], len);

  case 'T':
    return this->send_str("OK"); // threads are always alive

  case 'D':
    this->send_str("OK");
    return false;

  default:
    fprintf(stderr, "Unknown packet: starts with %c\n", data[0]);
    break;
  }

  return false;
}

bool
Rsp::cont(char* data, size_t len) {
  uint32_t sig;
  uint64_t addr;
  uint64_t npc;
  int i;
  bool npc_found = false;
  DbgIF* dbgif;

  // strip signal first
  if (data[0] == 'C') {
    if (sscanf(data, "C%X;%lX", &sig, &addr) == 2)
      npc_found = true;
  } else {
    if (sscanf(data, "c%lX", &addr) == 1)
      npc_found = true;
  }

  if (npc_found) {
    dbgif = this->get_dbgif(m_thread_sel);
    // only when we have received an address
    dbgif->pc_read(&npc);

    if (npc != addr)
      dbgif->pc_write(addr, false);
  }

  m_thread_sel = 0;

  return this->resume();
}

bool
Rsp::step(char* data, size_t len) {
  uint64_t addr;
  uint64_t npc;
  int i;
  DbgIF* dbgif;

  // strip signal first
  if (data[0] == 'S') {
    for (i = 0; i < len; i++) {
      if (data[i] == ';') {
        data = &data[i+1];
        break;
      }
    }
  }

  if (sscanf(data, "%lx", &addr) == 1) {
    dbgif = this->get_dbgif(m_thread_sel);
    // only when we have received an address
    dbgif->pc_read(&npc);

    if (npc != addr)
      dbgif->pc_write(addr, false);
  }

  m_thread_sel = 0;

  return this->stepCores();
}

bool
Rsp::multithread(char* data, size_t len) {
  int thread_id;

  switch (data[0]) {
    case 'c':
    case 'g':
      if (sscanf(&data[1], "%d", &thread_id) != 1)
        return false;

      if (thread_id == -1) // affects all threads
        return this->send_str("OK");

      // we got the thread id, now let's look for this thread in our list
      if (this->get_dbgif(thread_id) != NULL) {
        m_thread_sel = thread_id;
        return this->send_str("OK");
      }

      return this->send_str("E01");
  }

  return false;
}

bool
Rsp::query(char* data, size_t len) {
  int ret;
  char reply[256];

  if (strncmp ("qSupported", data, strlen ("qSupported")) == 0)
  {
    return this->send_str("PacketSize=256");
  }
  else if (strncmp ("qTStatus", data, strlen ("qTStatus")) == 0)
  {
    // not supported, send empty packet
    return this->send_str("");
  }
  else if (strncmp ("qfThreadInfo", data, strlen ("qfThreadInfo")) == 0)
  {
    reply[0] = 'm';
    ret = 1;

    for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
      ret += snprintf(&reply[ret], 256 - ret, "%u,", (*it)->get_thread_id());
    }

    return this->send(reply, ret-1);
  }
  else if (strncmp ("qsThreadInfo", data, strlen ("qsThreadInfo")) == 0)
  {
    return this->send_str("l");
  }
  else if (strncmp ("qThreadExtraInfo", data, strlen ("qThreadExtraInfo")) == 0)
  {
    const char* str_default = "Unknown Core";
    char str[256];
    unsigned int thread_id;
    if (sscanf(data, "qThreadExtraInfo,%d", &thread_id) != 1) {
      fprintf(stderr, "Could not parse qThreadExtraInfo packet\n");
      return this->send_str("");
    }

    DbgIF* dbgif = this->get_dbgif(thread_id);

    if (dbgif != NULL)
      dbgif->get_name(str, 256);
    else
      strcpy(str, str_default);

    ret = 0;
    for(int i = 0; i < strlen(str); i++)
      ret += snprintf(&reply[ret], 256 - ret, "%02X", str[i]);

    return this->send(reply, ret);
  }
  else if (strncmp ("qAttached", data, strlen ("qAttached")) == 0)
  {
    return this->send_str("1");
  }
  else if (strncmp ("qC", data, strlen ("qC")) == 0)
  {
    snprintf(reply, 64, "0.%u", this->get_dbgif(m_thread_sel)->get_thread_id());
    return this->send_str(reply);
  }
  else if (strncmp ("qSymbol", data, strlen ("qSymbol")) == 0)
  {
    return this->send_str("OK");
  }
  else if (strncmp ("qOffsets", data, strlen ("qOffsets")) == 0)
  {
    return this->send_str("Text=0;Data=0;Bss=0");
  }
  else if (strncmp ("qT", data, strlen ("qT")) == 0)
  {
    // not supported, send empty packet
    return this->send_str("");
  }

  fprintf(stderr, "Unknown query packet\n");

  return false;
}

bool
Rsp::v_packet(char* data, size_t len) {
  if (strncmp ("vKill", data, strlen ("vKill")) == 0)
  {
    this->send_str("OK");
    return false;
  }
  else if (strncmp ("vCont?", data, strlen ("vCont?")) == 0)
  {
    return this->send_str("");
  }
  else if (strncmp ("vMustReplyEmpty", data, strlen ("vMustReplyEmpty")) == 0)
  {
    return this->send_str("");
  }
  else if (strncmp ("vCont", data, strlen ("vCont")) == 0)
  {
    bool threadsCmd[m_dbgifs.size()];
    for (int i=0; i<m_dbgifs.size(); i++) threadsCmd[i] = false;
    // vCont can contains several commands, handle them in sequence
      char *str = strtok(&data[6], ";");
    while(str != NULL) {
      // Extract command and thread ID
      char *delim = index(str, ':');
      int tid = -1;
      if (delim != NULL) {
        tid = atoi(delim+1);
        *delim = 0;
      }

      bool cont = false;
      bool step = false;

      if (str[0] == 'C' || str[0] == 'c') {
        cont = true;
        step = false;
      } else if (str[0] == 'S' || str[0] == 's') {
        cont = true;
        step = true;
      } else {
        fprintf(stderr, "Unsupported command in vCont packet: %s\n", str);
        exit(-1);
      }

      if (cont) {
        if (tid == -1) {
          for (int i=0; i<m_dbgifs.size(); i++) {
            if (!threadsCmd[i]) resumeCoresPrepare(this->get_dbgif(i), step);
          }
        } else {
          if (!threadsCmd[tid]) this->resumeCoresPrepare(this->get_dbgif(tid), step);
          threadsCmd[tid] = true;
        }
      }

      str = strtok(NULL, ";");
    }

    this->resumeCores();

    return this->waitStop(NULL);
  }

  fprintf(stderr, "Unknown v packet\n");

  return false;
}

bool
Rsp::regs_send() {
  uint64_t gpr[32];
  uint64_t npc;
  uint64_t ppc;
  char regs_str[1024];
  int i;
  DbgIF *dbgif = this->get_dbgif(m_thread_sel);
 
  dbgif->gpr_read_all(gpr);

  // now build the string to send back
  for(i = 0; i < 32; i++) {
    snprintf(&regs_str[i * 16], 17, "%.016lx", htonll(gpr[i]));
  }

  dbgif->pc_read(&npc);
  snprintf(&regs_str[32 * 16 + 0 * 16], 17, "%.016lx", htonll(npc));

  return this->send_str(regs_str);
}

bool
Rsp::reg_read(char* data, size_t len) {
  uint32_t addr;
  uint64_t rdata;
  char data_str[10];
  DbgIF *dbgif = this->get_dbgif(m_thread_sel);

  if (sscanf(data, "%x", &addr) != 1) {
    fprintf(stderr, "Could not parse packet\n");
    return false;
  }

  printf("reg_read(%s);\n", regnum(addr));

  if (addr < RISCV_PC_REGNUM)
    dbgif->gpr_read(addr, &rdata);
  else if (addr == RISCV_PC_REGNUM)
    dbgif->pc_read(&rdata);
  else if (addr == RISCV_CSR_MISA_REGNUM)
    dbgif->csr_read(CSR_MISA, &rdata);
  else if (addr == RISCV_PRIV_REGNUM)
    rdata = 0x3; // Fake this for now and assume machine mode
  else
    return this->send_str("");

  rdata = htonll(rdata);
  snprintf(data_str, 17, "%016lx", rdata);

  return this->send_str(data_str);
}

bool
Rsp::reg_write(char* data, size_t len) {
  uint64_t addr;
  uint64_t wdata;
  char data_str[10];
  DbgIF *dbgif = this->get_dbgif(m_thread_sel);

  if (sscanf(data, "%lx=%016lx", &addr, &wdata) != 2) {
    fprintf(stderr, "Could not parse packet\n");
    return false;
  }

  wdata = ntohll(wdata);
  
  if (addr < RISCV_PC_REGNUM)
    dbgif->gpr_write(addr, wdata);
  else if (addr == RISCV_PC_REGNUM)
    dbgif->pc_write(wdata, true);
  else
    return this->send_str("E01");

  return this->send_str("OK");
}

bool
Rsp::get_packet(char* pkt, size_t* p_pkt_len) {
  char c;
  char check_chars[2];
  char buffer[PACKET_MAX_LEN];
  int  buffer_len = 0;
  int  pkt_len;
  bool escaped = false;
  int ret;
  // packets follow the format: $packet-data#checksum
  // checksum is two-digit

  // poison packet
  memset(pkt, 0, PACKET_MAX_LEN);
  pkt_len = 0;

  // first look for start bit
  do {
    ret = recv(m_socket_client, &c, 1, 0);

    if((ret == -1 && errno != EWOULDBLOCK) || (ret == 0)) {
      fprintf(stderr, "RSP: Error receiving\n");
      return false;
    }

    if(ret == -1 && errno == EWOULDBLOCK) {
      // no data available
      continue;
    }

    // special case for 0x03 (asynchronous break)
    if (c == 0x03) {
      pkt[0]  = c;
      *p_pkt_len = 1;
      return true;
    }
  } while(c != '$');

  buffer[0] = c;

  // now store data as long as we don't see #
  do {
    if (buffer_len >= PACKET_MAX_LEN || pkt_len >= PACKET_MAX_LEN) {
      fprintf(stderr, "RSP: Too many characters received\n");
      return false;
    }

    ret = recv(m_socket_client, &c, 1, 0);

    if((ret == -1 && errno != EWOULDBLOCK) || (ret == 0)) {
      fprintf(stderr, "RSP: Error receiving\n");
      return false;
    }

    if(ret == -1 && errno == EWOULDBLOCK) {
      // no data available
      continue;
    }

    buffer[buffer_len++] = c;

    // check for 0x7d = '}'
    if (c == 0x7d) {
      escaped = true;
      continue;
    }

    if (escaped)
      pkt[pkt_len++] = c ^ 0x20;
    else
      pkt[pkt_len++] = c;

    escaped = false;
  } while(c != '#');

  buffer_len--;
  pkt_len--;

  // checksum, 2 bytes
  ret = recv(m_socket_client, &check_chars[0], 1, 0);
  if((ret == -1 && errno != EWOULDBLOCK) || (ret == 0)) {
    fprintf(stderr, "RSP: Error receiving\n");
    return false;
  }

  ret = recv(m_socket_client, &check_chars[1], 1, 0);
  if((ret == -1 && errno != EWOULDBLOCK) || (ret == 0)) {
    fprintf(stderr, "RSP: Error receiving\n");
    return false;
  }

  // check the checksum
  unsigned int checksum = 0;
  for(int i = 0; i < buffer_len; i++) {
    checksum += buffer[i];
  }

  checksum = checksum % 256;
  char checksum_str[3];
  snprintf(checksum_str, 3, "%02x", checksum);

  if (check_chars[0] != checksum_str[0] || check_chars[1] != checksum_str[1]) {
    fprintf(stderr, "RSP: Checksum failed; received %.*s; checksum should be %02x\n", pkt_len, pkt, checksum);
    return false;
  }

  // now send ACK
  char ack = '+';
  if (::send(m_socket_client, &ack, 1, 0) != 1) {
    fprintf(stderr, "RSP: Sending ACK failed\n");
    return false;
  }

  // NULL terminate the string
  pkt[pkt_len] = '\0';
  *p_pkt_len = pkt_len;

  return true;
}

bool
Rsp::signal() {
  uint64_t cause;
  uint64_t hit;
  int signal;
  char str[4];
  int len;
  DbgIF* dbgif;

  dbgif = this->get_dbgif(m_thread_sel);

  dbgif->write(DBG_IE_REG, 0xFFFF);

  // figure out why we are stopped
  if (dbgif->is_stopped()) {
    if (!dbgif->read(DBG_HIT_REG, &hit))
      return false;
    if (!dbgif->read(DBG_CAUSE_REG, &cause))
      return false;

    if (hit & 0x1)
      signal = TARGET_SIGNAL_TRAP;
    else if(cause & (1 << 31))
      signal = TARGET_SIGNAL_INT;
    else if(cause & (1 << 3))
      signal = TARGET_SIGNAL_TRAP;
    else if(cause & (1 << 2))
      signal = TARGET_SIGNAL_ILL;
    else if(cause & (1 << 5))
      signal = TARGET_SIGNAL_BUS;
    else
      signal = TARGET_SIGNAL_STOP;
  } else {
    signal = TARGET_SIGNAL_NONE;
  }

  len = snprintf(str, 4, "S%02x", signal);
  
  return this->send(str, len);
}

bool
Rsp::send(const char* data, size_t len) {
  int ret;
  int i;
  size_t raw_len = 0;
  char* raw = (char*)malloc(len * 2 + 4);
  unsigned int checksum = 0;

  raw[raw_len++] = '$';

  for (i = 0; i < len; i++) {
    char c = data[i];

    // check if escaping needed
    if (c == '#' || c == '%' || c == '}' || c == '*') {
      raw[raw_len++] = '}';
      raw[raw_len++] = c;
      checksum += '}';
      checksum += c;
    } else {
      raw[raw_len++] = c;
      checksum += c;
    }
  }

  // add checksum
  checksum = checksum % 256;
  char checksum_str[3];
  snprintf(checksum_str, 3, "%02x", checksum);

  raw[raw_len++] = '#';
  raw[raw_len++] = checksum_str[0];
  raw[raw_len++] = checksum_str[1];

  char ack;
  do {
    log->debug("Sending %.*s\n", raw_len, raw);

    if (::send(m_socket_client, raw, raw_len, 0) != raw_len) {
      free(raw);
      fprintf(stderr, "Unable to send data to client\n");
      return false;
    }

    ret = recv(m_socket_client, &ack, 1, 0);
    if((ret == -1 && errno != EWOULDBLOCK) || (ret == 0)) {
      free(raw);
      fprintf(stderr, "RSP: Error receiving\n");
      return false;
    }

    if(ret == -1 && errno == EWOULDBLOCK) {
      // no data available
      continue;
    }

  } while (ack != '+');

  free(raw);
  return true;
}

bool
Rsp::send_str(const char* data) {
  return this->send(data, strlen(data));
}

bool
Rsp::waitStop(DbgIF* dbgif) {
  int ret;
  char pkt;

  fd_set rfds;
  struct timeval tv;

  while(1) {
    putchar('.'); fflush(stdout);
    //First check if one core has stopped
    if (dbgif) {
      if (dbgif->is_stopped()) {
        axi_counters();
        cpu_commit_status();        
        return this->signal();
      }
    } else {
      for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
        if ((*it)->is_stopped()) {
          return this->signal();
        }
      }
    }

    // Otherwise wait for a stop request from gdb side for a while

    FD_ZERO(&rfds);
    FD_SET(m_socket_client, &rfds);

    tv.tv_sec = 0;
    tv.tv_usec = 100 * 1000;

    if (select(m_socket_client+1, &rfds, NULL, NULL, &tv)) {
      ret = recv(m_socket_client, &pkt, 1, 0);
      if (ret == 1 && pkt == 0x3) {
        if (dbgif) {
          dbgif->halt();

          if (!dbgif->is_stopped()) {
            printf("ERROR: failed to stop core\n");
            return false;
          }

          return this->signal();
        } else {          
          for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
            (*it)->halt();

            if (!(*it)->is_stopped()) {
              printf("ERROR: failed to stop core\n");
              return false;
            }
          }
        }
      }
    }
  }

  return true;
}

void
Rsp::resumeCoresPrepare(DbgIF *dbgif, bool step) {

  uint64_t ppc;

  // now let's handle software breakpoints

  dbgif->pc_read(&ppc);

  // if there is a breakpoint at this address, let's remove it and single-step over it
  bool hasStepped = false;

  log->debug("Preparing core to resume (step: %d, ppc: 0x%lx)\n", step, ppc);

  if (m_bp->at_addr(ppc)) {
    log->debug("Core is stopped on a breakpoint, stepping to go over (addr: 0x%lx)\n", ppc);

    m_bp->disable(m_thread_sel, ppc);
    dbgif->step_and_stop(false, ppc); // single-step
    while (1) {
      uint64_t value;
      dbgif->read(DBG_CTRL_REG, &value);
      if ((value >> 16) & 1) break;
    }
    m_bp->enable(m_thread_sel, ppc);
    hasStepped = true;
  }

  if (!step || !hasStepped) {
    // clear hit register, has to be done before CTRL
    dbgif->write(DBG_HIT_REG, 0);

    if (step)
      dbgif->write(DBG_CTRL_REG, (1<<16) | 0x1);
    else
      dbgif->write_and_go(DBG_CTRL_REG, (1<<16) | 0);
  }
}

void
Rsp::resumeCores() {
    uint64_t value;
    this->get_dbgif(0)->read(DBG_CTRL_REG, &value);
    this->get_dbgif(0)->write_and_stop(DBG_CTRL_REG, value & ~(1<<16));
}

bool
Rsp::resume() {
  if (m_dbgifs.size() == 1) {
    return resume(m_thread_sel);
  } else {
    for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
      resumeCoresPrepare(*it, false);
    }
    resumeCores();
    return waitStop(NULL);
  }
}

bool
Rsp::stepCores() {
  if (m_dbgifs.size() == 1) {
    int ret;
    char pkt;
    return this->step(m_thread_sel);
  } else {
    for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
      resumeCoresPrepare(*it, true);
    }
    resumeCores();
    return waitStop(NULL);
  }
}

bool
Rsp::resume(int tid) {
  uint64_t ppc, ppc1;
  char pkt;
  DbgIF *dbgif = this->get_dbgif(tid);
  // now let's handle software breakpoints

  dbgif->pc_read(&ppc);

  // if there is a breakpoint at this address, let's remove it and single-step over it

  if (m_bp->at_addr(ppc))
    m_bp->disable(m_thread_sel, ppc);
  
  dbgif->step_and_stop(false, ppc); // single-step

  dbgif->pc_read(&ppc1);
  if (ppc1 != ppc)
    {
      printf("Stepped from %.016lX to %.016lX\n", ppc, ppc1);
    }
    
  if (m_bp->at_addr(ppc))
    m_bp->enable(m_thread_sel, ppc);
  
  dbgif->ctrl_and_go();

  return waitStop(dbgif);
}

bool
Rsp::step(int tid) {
  int ret;
  char pkt;
  uint64_t ppc;
  bool bp;
  DbgIF *dbgif = this->get_dbgif(tid);

  printf("stepCore\n");
  dbgif->pc_read(&ppc);

  // if there is a breakpoint at this address, let's remove it and single-step over it
  if (m_bp->at_addr(ppc))
    m_bp->disable(tid, ppc);
  bp = m_bp->at_addr(ppc+4);
  if (bp)
    m_bp->enable(tid, ppc+4);
  else
    m_bp->insert(tid, ppc+4);
  dbgif->step_and_stop(true, ppc); // single-step
  if (!bp)
    m_bp->remove(tid, ppc+4);
  if (m_bp->at_addr(ppc))
    m_bp->enable(tid, ppc);

  return waitStop(dbgif);
}

bool
Rsp::mem_read(char* data, size_t len) {
  uint8_t *buffer;
  char *reply;
  uint64_t addr;
  uint64_t length;
  uint32_t rdata;
  int i, len2;
  bool retval;
  
  if (sscanf(data, "%lx,%lx", &addr, &length) != 2) {
    fprintf(stderr, "Could not parse packet\n");
    return false;
  }

  len2 = ((length+sizeof(uint64_t)-1)&(-sizeof(uint64_t)));
  
  buffer = (uint8_t *)malloc(len2);
  reply = (char *)malloc(length*2+1);
  m_mem->access(0, addr, len2, (uint64_t *)buffer);

  for(i = 0; i < length; i++) {
    rdata = buffer[i];
    snprintf(&reply[i * 2], 3, "%02x", rdata);
  }

  retval = this->send(reply, length*2);
  
  free(buffer);
  free(reply);
  return retval;
}

bool
Rsp::mem_write_ascii(char* data, size_t len) {
  uint64_t addr;
  size_t length;
  uint64_t wdata;
  int i, j;

  char* buffer;
  int buffer_len;

  if (sscanf(data, "%lx,%ld:", &addr, &length) != 2) {
    fprintf(stderr, "Could not parse packet\n");
    return false;
  }

  for(i = 0; i < len; i++) {
    if (data[i] == ':') {
      break;
    }
  }

  if (i == len)
    return false;

  // align to hex data
  data = &data[i+1];
  len = len - i - 1;

  buffer_len = len/2;
  buffer = (char*)malloc(buffer_len);
  if (buffer == NULL) {
    fprintf(stderr, "Failed to allocate buffer\n");
    return false;
  }

  for(j = 0; j < len/2; j++) {
    wdata = 0;
    for(i = 0; i < 2; i++) {
      char c = data[j * 2 + i];
      uint64_t hex = 0;
      if (c >= '0' && c <= '9')
        hex = c - '0';
      else if (c >= 'a' && c <= 'f')
        hex = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        hex = c - 'A' + 10;

      wdata |= hex << (4 * i);
    }

    buffer[j] = wdata;
  }

  m_mem->access(1, addr, buffer_len, (uint64_t *)buffer);

  free(buffer);

  return this->send_str("OK");
}

bool
Rsp::mem_write(char* data, size_t len) {
  uint64_t addr;
  size_t length;
  uint64_t wdata;
  int i, j;

  uint64_t *buffer = (uint64_t *)(((size_t)data+sizeof(uint64_t)-1)&(-sizeof(uint64_t)));

  if (sscanf(data, "%lx,%lx:", &addr, &length) != 2) {
    fprintf(stderr, "Could not parse packet\n");
    return false;
  }

  for(i = 0; i < len; i++) {
    if (data[i] == ':') {
      break;
    }
  }

  if (i == len)
    return false;

  // align to hex data
  len = len - i - 1;

  memcpy(buffer, &data[i+1], len);
  m_mem->access(1, addr, len, buffer);

  return this->send_str("OK");
}

bool
Rsp::bp_insert(char* data, size_t len) {
  enum mp_type type;
  uint64_t addr;
  uint64_t data_bp;
  int bp_len;

  if (3 != sscanf(data, "Z%1d,%lx,%1d", (int *)&type, &addr, &bp_len)) {
    fprintf(stderr, "Could not get three arguments\n");
    return false;
  }

  if (type != BP_MEMORY) {
    fprintf(stderr, "ERROR: Not a memory bp\n");
    this->send_str("");
    return false;
  }

  m_bp->insert(m_thread_sel, addr);

  return this->send_str("OK");
}

bool
Rsp::bp_remove(char* data, size_t len) {
  enum mp_type type;
  uint64_t addr;
  uint64_t ppc;
  int bp_len;
  DbgIF* dbgif;

  dbgif = this->get_dbgif(m_thread_sel);

  if (3 != sscanf(data, "z%1d,%lx,%1d", (int *)&type, &addr, &bp_len)) {
    fprintf(stderr, "Could not get three arguments\n");
    return false;
  }

  if (type != BP_MEMORY) {
    fprintf(stderr, "Not a memory bp\n");
    return false;
  }

  m_bp->remove(m_thread_sel, addr);

  // check if we are currently on this bp that is removed
  dbgif->pc_read(&ppc);

  if (addr == ppc) {
    dbgif->pc_write(ppc, false); // re-execute this instruction
  }

  return this->send_str("OK");
}

DbgIF*
Rsp::get_dbgif(int thread_id) {
  for (std::list<DbgIF*>::iterator it = m_dbgifs.begin(); it != m_dbgifs.end(); it++) {
    if ((*it)->get_thread_id() == thread_id)
      return *it;
  }

  return NULL;
}
