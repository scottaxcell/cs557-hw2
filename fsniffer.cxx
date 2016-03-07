#include <iostream>
#include <vector>

#include <pcap.h>

#include "fsniffer.h"

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

}

int main(int argc, char* argv[])
{
  std::string filename;
  std::string interface;
  std::string time;
  std::string time_offset;
  int num = 0; // number of flows to print, default 0 means print all flows
  int timeout_interval = 60;

  std::vector<flow> flows;

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



  return 0;
}
