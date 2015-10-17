<<<<<<< Updated upstream
uint8_t* create_reply_packet (uint8_t *packet, struct sr_if *if_walker, int packet_len) {
  uint8_t *reply_packet = malloc(packet_len);
=======
 
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
>>>>>>> Stashed changes


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_helper.h"


 uint8_t* create_arp_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_arp_hdr_t* arp_hdr) {
  uint8_t *reply_packet = malloc(packet_len);
 /* Create ethernet header for ARP reply */
  create_ethernet_header (reply_packet, packet, if_walker); 

  sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
  reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
  reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
  reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
  reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
  reply_arp_hdr->ar_op =  htons(arp_op_reply);

  /* Switch sender and receiver hardware and IP address */
  memcpy(reply_arp_hdr->ar_sha, if_walker->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
  reply_arp_hdr->ar_sip =  arp_hdr->ar_tip;
  memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
  return reply_packet;
}

uint8_t* create_echo_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_ip_hdr_t *ip_hdr) {
  uint8_t *reply_packet = malloc(packet_len);
  create_ethernet_header (reply_packet, packet, if_walker); 

  /* Create IP header */
  sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
  memcpy(reply_ip_hdr, ip_hdr, sizeof(sr_ip_hdr_t));
  reply_ip_hdr->ip_src = ip_hdr->ip_dst;
  reply_ip_hdr->ip_dst = ip_hdr->ip_src;


  /* Create ICMP Header */
  sr_icmp_hdr_t *reply_icmp_hdr = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  reply_icmp_hdr->icmp_type = ICMP_ECHO_REQUEST;
  reply_icmp_hdr->icmp_code = 0;
  reply_icmp_hdr->icmp_sum = cksum (ip_hdr, ) 

  return reply_packet;

}


int check_receiver (uint32_t ip, struct sr_instance* sr) {
  int correct_router = 0;
  while (if_walker){
    /* Check if the interface IP matches the receiving router's IP */
    if(if_walker->ip == ip){
      /* The packet is targeted towards the current router */
      correct_router = 1;
      break;
    }
    if_walker = if_walker->next;
  }

  return correct_router;
}



void create_ethernet_header (uint8_t * reply_packet, uint8_t * packet, struct sr_if * if_walker) {
  /* Copy over original ethernet header */
  sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
  memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));

  /* Create ethernet header */
  sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) reply_packet;
  memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(reply_eth_hdr ->ether_shost, if_walker->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
  reply_eth_hdr->ether_type = eth_hdr->ether_type;
}