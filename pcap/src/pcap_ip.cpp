
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "poc.h"

#include <iostream>

using namespace std;


#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

/*
 * Structure of an internet header, naked of options.
 *
 * Stolen from tcpdump source (thanks tcpdump people)
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
// struct my_ip {
// 	u_int8_t	ip_vhl;		/* header length, version */
// #define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
// #define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
// 	u_int8_t	ip_tos;		/* type of service */
// 	u_int16_t	ip_len;		/* total length */
// 	u_int16_t	ip_id;		/* identification */
// 	u_int16_t	ip_off;		/* fragment offset field */
// #define	IP_DF 0x4000			/* dont fragment flag */
// #define	IP_MF 0x2000			/* more fragments flag */
// #define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
// 	u_int8_t	ip_ttl;		/* time to live */
// 	u_int8_t	ip_p;		/* protocol */
// 	u_int16_t	ip_sum;		/* checksum */
// 	struct	in_addr ip_src,ip_dst;	/* source and dest address */
// };

bool handleTcp(const u_char *buff, u_short buflen) {
  bool retval = true;
  (void)buff; (void)buflen;
  cout << "TCP : ..." << endl;
  return retval;
}

bool handleUdp(const u_char *buff, u_short buflen) {
  bool retval = true;
  (void)buff; (void)buflen;
  cout << "UDP : ..." << endl;
  return retval;
}

bool handleIgmp(const u_char *buff, u_short buflen) {
  bool retval = true;
  (void)buff; (void)buflen;
  cout << "IGMP: ..." << endl;
  return retval;
}

bool handleIp4(const u_char *buff, u_short buflen) {
  bool retval = false;          

  if ((size_t)buflen < sizeof(ip)) {
    printf("truncated ip %d", buflen);
    return retval;
  }

  const ip * hdr = (ip*)buff;
  const u_short totlen = ntohs(hdr->ip_len);
  const u_short hdrlen = hdr->ip_hl;
  const u_short version = hdr->ip_v;

  if (version != 4) {
    fprintf(stdout,"Unknown version %d\n",version);
    return retval;
  }

  if(hdrlen < 5 ) {
    fprintf(stdout,"bad-hlen %d \n", hdrlen);
    return retval;
  }

  if( buflen < totlen) {
    printf("\ntruncated IP - %d bytes missing\n",totlen - buflen);
    return retval;
  }

  /* Check to see if we have the first fragment */
  const u_short ip_off = ntohs(hdr->ip_off);
  const u_short frag_off = ip_off & IP_OFFMASK;
  const bool ip_df = ip_off & IP_DF;
  const bool ip_mf = ip_off & IP_MF;

  static const u_int8_t prot_id[] = {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_IGMP, IPPROTO_ICMP};
  static const char * prot_names[] = {"IPPROTO_TCP", "IPPROTO_UDP", "IPPROTO_IGMP}, }IPPROTO_ICMP"};
  const char *prot = "N/A";
  for (size_t i = 0; i < sizeof(prot_id)/sizeof(prot_id[0]); ++ i) {
    if (prot_id[i] == hdr->ip_p) {
      prot = prot_names[i];
      break;
    }
  }
  u_short payload_len = totlen - hdrlen*4;
  const u_char * payload = buff + totlen;
  cout << "IP  : src=" << inet_ntoa(hdr->ip_src) << " dst=" << inet_ntoa(hdr->ip_dst) << " prot=" << prot
        << " ip_ver="<< version << " hdr_len=" << hdrlen
        << " frag_off="<< frag_off << " ip_df=" << ip_df << " ip_mf=" << ip_mf
        << " hdr_size="<< sizeof(*hdr) << " IHL="<< (hdrlen*4)
        << endl;
    
  if (hdr->ip_p == IPPROTO_TCP) {
    retval = handleTcp(payload, payload_len);
  } else if (hdr->ip_p == IPPROTO_UDP) {
    retval = handleUdp(payload, payload_len);
  } else if (hdr->ip_p == IPPROTO_IGMP) {
    retval = handleIgmp(payload, payload_len);
  } else {
  }
  return retval;    
}


bool handleEthernet (const pcap_pkthdr * pkthdr, const u_char * packet) {
  bool retval = false;
  u_int caplen = pkthdr->caplen;
  u_int length = pkthdr->len;
  struct ether_header *eptr;  /* net/ethernet.h */
  u_short ether_type;

  if (caplen < ETHER_HDRLEN) {
      fprintf(stdout,"Packet length less than ethernet header length\n");
      return -1;
  }

  /* lets start with the ether header... */
  eptr = (struct ether_header *) packet;
  ether_type = ntohs(eptr->ether_type);

  cout << "\nETH: src=" <<  ether_ntoa((struct ether_addr*)eptr->ether_shost)
    << " dst=" << ether_ntoa((struct ether_addr*)eptr->ether_dhost)
    << " caplen=" << caplen << " length=" << length << endl;

  if (ether_type == ETHERTYPE_IP) {
    retval  = handleIp4(packet + sizeof(ether_header), pkthdr->len - sizeof( ether_header));
  } else if (ether_type == ETHERTYPE_ARP) {
      cout << "ARP: ..." << endl;
      retval = true;
  } else if (eptr->ether_type == ETHERTYPE_REVARP) {
      cout << "RARP: ..." << endl;
      retval = true;
  } else {
      cout << "ETH: (?)" << endl;
  }
  fprintf(stdout," %d\n",length);
  return retval;
}
