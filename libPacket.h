//Dpak Malla
//mmallad
#ifndef libPacket_h
#define libPacket_h
#include <stdio.h>
#include <pcap.h>

extern void start_capture_packet(u_char *, const struct pcap_pkthdr *, const u_char *) __THROW;
extern u_int capture_tcp_packet(const u_char *) __THROW;
extern void capture_ip_packet(const u_char *) __THROW;
extern void capture_ethernet_packet(const u_char *) __THROW;
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
/*
 * TCP Header Structure
 * */
struct tcp_hdr {
  unsigned short tcp_src_port;   
  unsigned short tcp_dest_port;  
  unsigned int tcp_seq;          
  unsigned int tcp_ack;          
  unsigned char reserved:4;      
  unsigned char tcp_offset:4;   
  unsigned char tcp_flags;       
  #define TCP_FIN   0x01
  #define TCP_SYN   0x02
  #define TCP_RST   0x04
  #define TCP_PUSH  0x08
  #define TCP_ACK   0x10
  #define TCP_URG   0x20
  unsigned short tcp_window;     
  unsigned short tcp_checksum;   
  unsigned short tcp_urgent;    
};
/*
 * Ethernet Header Structure
 * */
struct ether_hdr {
  unsigned char ether_dest_addr[ETHER_ADDR_LEN]; //MAC Destination Address
  unsigned char ether_src_addr[ETHER_ADDR_LEN];  //MAC Source Address
  unsigned short ether_type; //Type 
};
/*
 * IP Header Structure
 * */
struct ip_hdr {
  unsigned char ip_version_and_header_length; 
  unsigned char ip_tos;         
  unsigned short ip_len;         
  unsigned short ip_id;          
  unsigned short ip_frag_offset; 
  unsigned char ip_ttl;          
  unsigned char ip_type;       
  unsigned short ip_checksum;    
  unsigned int ip_src_addr;      
  unsigned int ip_dest_addr;     
};

#endif