/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

struct sr_if *if_walker;

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    struct sr_if *if_walker = 0;
    
    /* Add initialization code here! */


} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  sr_ethernet_hdr_t *packet_header;
  sr_ethertype arp_type = ethertype_arp;
  sr_ethertype ip_type = ethertype_ip;
  malloc (packet_header, sizeof(sr_ethernet_hdr_t));
  memcpy(packet_header, (sr_ethernet_hdr_t *) packet, sizeof (sr_ethernet_hdr_t));
  if (packet_header -> ether_type == ip_type) {
    // Request
    sr_arphandler (sr, pakcker, len, interface);

    // Reply

  } else if (packet_header -> ether_type == arp_type) {
    sr_arphandler (sr, pakcker, len, interface);


  }


}/* end sr_ForwardPacket */

void sr_arphandler (struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  sr_arp_hdr *arp_header; 
  arp_header = malloc (sizeof (sr_arp_hdr));
  memcpy (arp_header, (sr_arp_hdr_t *) (packet + size (sr_ethernet_hdr_t)), sizeof (sr_arp_hdr_t));
  if (ntohs(arp_header -> ar_op) == arp_op_request) {
    // Check if the packet's targer is current router
    if (check_receiver()) {
      int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)
      // Create reply packet to send back to sender
      uint8_t *reply_packet = create_reply_packet (packet, if_walker, packet_len); 
      sr_send_packet(sr, reply_packet, packet_len, if_walker->name);
      free(reply_packet);
    } else {
      printf ("Dropping packet: ARP request is not targeted at current router.");
      return; 
    }
  } else if (ntohs(arp_header -> ar_op) == arp_reply) {
    if (check_receiver()) {
       struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));

        if (req){
          struct sr_packet *packet = req->packets;
          while (packet){
            sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) packet->buf;
            memcpy(reply_eth_hdr->ether_dhost, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
            memcpy(reply_eth_hdr->ether_shost, if_walker->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
            reply_eth_hdr->ether_type = eth_hdr->ether_type;

            
            sr_send_packet(sr, packet->buf, packet->len, packet->iface);
          }
          packet = packet->next;
      }
    } else {
      printf ("Dropping packet: ARP request is not targeted at current router.");
    }
  }
}


void sr_iphandler (struct sr_instance* sr,
        uint8_t * packet lent ,
        unsigned int len,
        char* interface/* lent */) 
{

}


uint8_t* create_reply_packet (uint8_t *packet, struct sr_if *if_walker, int packet_len) {
  uint8_t *reply_packet = malloc(packet_len);

  sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
  memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));

  // Create ethernet header 
  sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) reply_packet;
  memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
  memcpy(reply_eth_hdr->ether_shost, if_walker->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
  reply_eth_hdr->ether_type = eth_hdr->ether_type;

  // Create ARP header 
  sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
  reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
  reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
  reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
  reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
  reply_arp_hdr->ar_op =  htons(arp_op_reply);

  // Switch sender and receiver hardware and IP address
  memcpy(reply_arp_hdr->ar_sha, if_walker->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
  reply_arp_hdr->ar_sip =  arp_hdr->ar_tip;
  memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
  return reply_packet;
}

int check_receiver (struct sr_arp_hdr_t* arp_header, struct sr_instance* sr) {
  int correct_router = 0;
  if_walker = sr->if_list;
  while(if_walker){
    // Check if the interface IP matches the receiving router's id 
    if(if_walker->ip == arp_hdr->ar_tip){
      // The packet is targeted towards the current router
      correct_router = 1;
      break;
    }
    if_walker = if_walker->next;
  }

  return correct_router;
}