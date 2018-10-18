
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "poc.h"

#include <iostream>
#include <string>

using namespace std;


static void my_callback(u_char *,const struct pcap_pkthdr * pkthdr,const u_char * packet) {
    bool ok = handleEthernet(pkthdr, packet);
    if (!ok) {
      cout << "Faile to process pcap packet" << endl;
    }
}

static auto selectDevice() {
  string retval;
  pcap_if_t *alldevs;
  pcap_if_t *dev;
  int inum;
  int i = 0;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    cerr << "Error in pcap_findalldevs: " << errbuf << endl;
    return retval;
  }

  for (dev = alldevs; dev; dev = dev->next) {
    cout << ++ i << " " << dev->name << '(' << (dev->description ? dev->description : "No description available") << ')' << endl;
  }
  if (i == 0) {
    cerr << "No interfaces found! Make sure WinPcap is installed." << endl;
    return retval;
  }

  printf("Enter the interface number (1-%d): ", i);
  scanf("%d", &inum);

  if (inum < 1 || inum > i) {
    printf("\nInterface number out of range.\n");
    pcap_freealldevs(alldevs);
    return retval;
  }
  
  for (dev = alldevs, i = 0; i < inum - 1; dev = dev->next, i++);
  retval = dev->name;

  pcap_freealldevs(alldevs);
  return retval;
}

int main(int argc,char **argv) { 
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t * handle;

  if(argc != 2) {
    fprintf(stdout,"Usage: %s numpackets\n",argv[0]);
    return 1;
  }
  const string dev = selectDevice();
  if(dev.empty()) {
    return 2;
  }

  bpf_u_int32 mask, net;
  if (pcap_lookupnet(dev.c_str(), &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev.c_str());
    net = mask = 0;
  }

  handle = pcap_open_live(dev.c_str(), BUFSIZ, 0, -1, errbuf);
  if (handle == NULL) {
    printf("pcap_open_live(): %s\n", errbuf);
    return 3;
  }

  int cnt = atoi(argv[1]);
  if (cnt == 0) {
    cnt = 100000;
    struct bpf_program fp;
    char * filter_exp = argv[1];
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
      return(2);
    }
  }

  pcap_loop(handle, cnt, my_callback, NULL);
  cout << endl << "Done processing packets" << endl;
 
  return 0;
}
