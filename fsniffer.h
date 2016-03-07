
struct flow {
  time_t startTime;
  std::string protocol;
  std::string srcAddr;
  std::string dstAddr;
  std::string dir; // direction
  int srcPort;
  int dstPort;
  unsigned int totalPkts;
  unsigned int totalBytes;
  std::string state;
  time_t dur; // duration

  flow& operator=(const flow& f) {
    startTime = f.startTime;
    protocol = f.protocol;
    srcAddr = f.srcAddr;
    dstAddr = f.dstAddr;
    dir = f.dir;
    srcPort = f.srcPort;
    dstPort = f.dstPort;
    totalPkts = f.totalPkts;
    totalBytes = f.totalBytes;
    state = f.state;
    dur = f.dur;
    return *this;
  }

  // determines flow equality
  bool operator==(const flow& f) {
    return (protocol == f.protocol &&
            srcAddr == f.srcAddr &&
            dstAddr == f.dstAddr &&
            srcPort == f.srcPort &&
            dstPort == f.dstPort);
  }
};
  
