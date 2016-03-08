#include <iostream>
#include <vector>
#include <algorithm>

#include "fsniffer.h"

static std::vector<Flow> flows;

std::string padString(std::string input, int size)
{
  std::string str(input);
  while (str.size() < size) {
    str += " ";
  }
  return str;
}

void printHeader()
{
  std::cout << padString("StartTime", 16)
  << padString("Proto", 6)
  << padString("SrcAddr", 15)
  << padString("Sport", 6)
  << padString("Dir", 4)
  << padString("DstAddr", 15)
  << padString("Dport", 6)
  << padString("TotPkts", 10)
  << padString("TotBytes", 10)
  << padString("State", 10)
  << "Dur\n";
}

void usage()
{
  std::cout << "Usage: ./fsniffer [-r filename] [-i interface] [-t time] [-o time_offset] [-N num] [-S secs]" << std::endl;
  exit(0);
}

void handlePacket(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
  /* packet headers */
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */
  const struct sniff_udp *udp;            /* The UDP header */
  const struct icmp *icmp;                /* The ICMP header */
  int size_ip;
  int size_tcp;

  // TODO handle timer


  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);

  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  Flow flow;
  flow.srcAddr = inet_ntoa(ip->ip_src);
  flow.dstAddr = inet_ntoa(ip->ip_dst);

  /* determine protocol */  
  switch(ip->ip_p) {
    case IPPROTO_TCP:
      /* define/compute tcp header offset */
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
      }
      flow.protocol = "TCP";
      flow.srcPort = ntohs(tcp->th_sport);
      flow.dstPort = ntohs(tcp->th_dport);

      //u_char flags;
      //if ((flags = tcp->th_flags) & (TH_URG|TH_ACK|TH_SYN|TH_FIN|TH_RST|TH_PUSH)) {
      //  fprintf(stdout,"[ ");
      //  if (flags & TH_FIN)
      //    fprintf(stdout,"FIN ");
      //  if (flags & TH_SYN)
      //    fprintf(stdout,"SYN ");
      //  if (flags & TH_RST)
      //    fprintf(stdout,"RST ");
      //  if (flags & TH_PUSH)
      //    fprintf(stdout,"PSH ");
      //  if (flags & TH_ACK)
      //    fprintf(stdout,"ACK ");
      //  if (flags & TH_URG)
      //    fprintf(stdout,"URG ");
      //  fprintf(stdout,"] ");
      //}
      break;
    case IPPROTO_UDP:
      udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
      flow.protocol = "UDP";
      flow.srcPort = ntohs(udp->uh_sport);
      flow.dstPort = ntohs(udp->uh_dport);
      break;
    case IPPROTO_ICMP:
      icmp = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
      flow.protocol = "ICMP";
      break;
    case IPPROTO_IP:
      printf("IP ");
      break;
    default:
      return;
  }

  auto flowItr = std::find_if(flows.begin(), flows.end(), flow);
  if (flowItr != flows.end()) {
    // have an existing flow
    auto &f = *flowItr;

    // increment packet counter
    (f.totalPkts)++;

    // increment total bytes
    f.totalBytes += pkthdr->len;

    // udpate duration
    struct timeval currentTimestamp;
    currentTimestamp.tv_sec = pkthdr->ts.tv_sec;
    currentTimestamp.tv_usec = pkthdr->ts.tv_usec;
    timersub(&currentTimestamp, &f.startTime, &f.dur);

    // update direction
    if (flow.protocol == "UDP" && f.isOppositeDirection(flow)) {
      flow.dir = "<->";
    } else if (flow.protocol == "TCP" && f.isOppositeDirection(flow)) {
      flow.dir = "<->";
    }
  } else {
    // brand new flow

    // set start time to current timestamp
    struct timeval startTime;
    startTime.tv_sec = pkthdr->ts.tv_sec;
    startTime.tv_usec = pkthdr->ts.tv_usec;
    flow.startTime = startTime;

    // initialize duration time
    struct timeval dur;
    dur.tv_sec = 0;
    dur.tv_usec = 0;
    flow.dur = dur;

    // initialize direction
    flow.dir = "->";

    // initialize packet counter
    flow.totalPkts = 1;

    // initialize total bytes
    flow.totalBytes = pkthdr->len;

    // initialize the state
    flow.state = "BOB";

    flows.push_back(flow);
  }
}

int main(int argc, char* argv[])
{
  std::string filename;
  std::string interface;
  std::string time;
  std::string time_offset;
  int num = 0; // number of flows to print, default 0 means print all flows
  int timeout_interval = 60;

  if (argc == 1) {
    usage();
  }
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-h") == 0) {
      usage();
    } else if (strcmp(argv[i], "-r") == 0) {
      filename = argv[++i];
    } else if (strcmp(argv[i], "-i") == 0) {
      interface = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0) {
      time = argv[++i];
    } else if (strcmp(argv[i], "-o") == 0) {
      time_offset = argv[++i];
    } else if (strcmp(argv[i], "-N") == 0) {
      num = std::stoi(argv[++i]);
    } else if (strcmp(argv[i], "-S") == 0) {
      timeout_interval = std::stoi(argv[++i]);
    } else {
      usage();
    }
  }

  char errbuf[PCAP_ERRBUF_SIZE]; 
  char filter_exp[] = "ip";      /* filter expression [3] */
  struct bpf_program fp;         /* compiled filter program (expression) */
  bpf_u_int32 net = 0;           /* ip */

  if (filename.size()) {
    /* open capture device */
    pcap_t *pcap = pcap_open_offline(filename.c_str(), errbuf);

    /* compile the filter expression */
    if (pcap_compile(pcap, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(pcap, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
          filter_exp, pcap_geterr(pcap));
      exit(EXIT_FAILURE);
    }

    pcap_loop(pcap, /*all packets*/-1, handlePacket, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(pcap);
  
  } else if (interface.size()) {

  }

  printHeader();
  for (auto &flow : flows) {
    flow.print();
  }


  return 0;
}
