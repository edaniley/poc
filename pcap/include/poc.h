#ifndef poc_h_included
#define poc_h_included


#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <netinet/if_ether.h> 
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <sys/socket.h>

#include <pcap.h>

bool handleEthernet(const pcap_pkthdr * pkthdr, const u_char * packet);
bool handleIp4(const u_char *buff, u_short buflen);
bool handleTcp(const u_char *buff, u_short buflen);
bool handleUdp(const u_char *buff, u_short buflen);
bool handleIgmp(const u_char *buff, u_short buflen);

#endif
