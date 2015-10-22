/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );


/* Get Ethernet header */
sr_ethernet_hdr_t * get_eth_hdr (uint8_t* packet);
sr_arp_hdr_t * get_arp_hdr (uint8_t* packet);
sr_ip_hdr_t *get_ip_hdr (uint8_t *packet);
sr_icmp_hdr_t *get_icmp_hdr (uint8_t *packet);

int check_min_len (unsigned int len, int type); 
int verify_ip_checksum (sr_ip_hdr_t *ip_hdr);
int verify_icmp_checksum (sr_icmp_hdr_t *icmp_hdr, int type, int len);
int decrement_and_recalculate (sr_ip_hdr_t *ip_hdr);

struct sr_if* get_router_interface (uint32_t ip, struct sr_instance* sr);

void sr_arphandler (struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);
void sr_iphandler (struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);

void create_ethernet_header (sr_ethernet_hdr_t * eth_hdr, uint8_t * new_packet, uint8_t *src_eth_addr, uint8_t *dest_eth_addr, uint16_t ether_type);
void create_arp_header (sr_arp_hdr_t* arp_hdr, uint8_t* new_packet, struct sr_if *src_iface);
void create_ip_header (sr_ip_hdr_t *ip_hdr, uint8_t* new_packet, uint32_t ip_src, uint32_t ip_dst);
void create_icmp_type3_header (sr_ip_hdr_t *ip_hdr, uint8_t* new_packet, uint8_t type, unsigned int code);

uint8_t* create_arp_reply (struct sr_if* src_iface, struct sr_if* out_iface, sr_ethernet_hdr_t* eth_hdr, sr_arp_hdr_t* arp_hdr, int packet_len);
uint8_t *create_echo_reply (struct sr_if* src_iface, sr_ethernet_hdr_t* eth_hdr, sr_ip_hdr_t* ip_hdr, int packet_len);
uint8_t* create_icmp_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_ip_hdr_t *ip_hdr, uint8_t type, unsigned int code); 

void send_arp_req (sr_arp_hdr_t *arp_hdr, struct sr_arpcache *cache, struct sr_instance* sr);
void send_echo_reply (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void send_icmp_type3_msg (uint8_t * new_packet, struct sr_rt *src_lpm, struct sr_arpcache *sr_cache, struct sr_instance* sr, char* interface, unsigned int len);


/* uint8_t* create_arp_reply  (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_arp_hdr_t* arp_hdr, struct sr_instance *sr, char* interface);*/



#endif /* SR_ROUTER_H */
