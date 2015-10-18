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
#include <stdlib.h>
#include <string.h>


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

struct sr_if *if_walker = 0;
uint8_t* create_arp_reply (uint8_t * packet, struct sr_if * if_walker, int packet_len, sr_arp_hdr_t* arp_hdr);
uint8_t* create_icmp_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_ip_hdr_t *ip_hdr, uint8_t type, unsigned int code);
int check_receiver (uint32_t ip, struct sr_instance* sr);
void sr_arphandler (struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);
void sr_iphandler (struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);
void create_ethernet_header (uint8_t * reply_packet, uint8_t * packet, struct sr_if * if_walker);


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

    /* Get Ethernet Header */
  sr_ethernet_hdr_t *eth_hdr;
  eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
  memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));


  uint16_t ethtype = ethertype((uint8_t *)eth_hdr);
  
  if (ethtype == ethertype_ip){
    printf("Received the IP Packet!\n");
    sr_iphandler(sr, packet, len, interface);
  } else if (ethtype == ethertype_arp){
    printf("Received the ARP Packet!\n");
    sr_arphandler(sr, packet, len, interface);
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

  sr_arp_hdr_t *arp_hdr; 
  arp_hdr = malloc (sizeof (sr_arp_hdr_t));
  memcpy (arp_hdr, (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t)), sizeof (sr_arp_hdr_t));
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    /* Check if the packet's target is current router */
    if (check_receiver(arp_hdr->ar_tip, sr)) {
      if_walker = sr->if_list;
      int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      /* Create reply packet to send back to sender */
      uint8_t *reply_packet = create_arp_reply(packet, if_walker, packet_len, arp_hdr);
      sr_send_packet(sr, reply_packet, packet_len, if_walker->name);
      printf("Sent an ARP reply packet\n");
      free(reply_packet);
    } else {
      printf ("Dropping packet: ARP request is not targeted at current router.");
      return; 
    }
  } else if (ntohs(arp_hdr -> ar_op) == arp_op_reply) {
    if_walker = sr->if_list;

    /*  only send an ARP reply if the target IP address is one of your router’s IP addresses.
        In the case of an ARP reply, you should only cache the entry if the target 
        IP address is one of your router’s IP addresses. */ 
    if (check_receiver(arp_hdr->ar_tip, sr)) {
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
        uint8_t * packet,
        unsigned int len,
        char* interface) 
{
  assert(sr);
  assert(packet);
  assert(interface);
  int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  sr_ip_hdr_t *ip_hdr;
  ip_hdr = malloc (sizeof(sr_ip_hdr_t));
  memcpy (ip_hdr, (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t)), sizeof (sr_ip_hdr_t));
  /* It is for me */
  if (check_receiver(ip_hdr->ip_dst, sr)) { 
    uint8_t ip_p = ip_protocol((uint8_t *)ip_hdr); 
    if (ip_p == ip_protocol_icmp) {
      sr_icmp_hdr_t *icmp_hdr;
      icmp_hdr = malloc (sizeof(sr_icmp_hdr_t));
      memcpy (icmp_hdr, (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)), sizeof(sr_icmp_hdr_t));
      /* If it's ICMP echo req, send echo reply */
      if (icmp_hdr->icmp_type == icmp_echo_request) {
        uint8_t *echo_reply = create_icmp_reply (packet, if_walker, packet_len, ip_hdr, echo_reply_type, -1); 
        sr_send_packet (sr, echo_reply, packet_len, if_walker->name); 
        free (echo_reply);
      } else {
        printf ("Not an ICMP echo request! Type unknown.");
      }
    /* If it is TCP / UDP, send ICMP port unreachable */
    } else if (ip_p == ip_protocol_udp || ip_p == ip_protocol_tcp) {
      uint8_t *port_unreachable_reply = create_icmp_reply (packet, if_walker, packet_len, ip_hdr, port_unreachable_type, port_unreachable_code); 
      sr_send_packet (sr, port_unreachable_reply, packet_len, if_walker->name); 
      free (port_unreachable_reply);   
    }

  } else {
    struct sr_rt* rt_walker = 0;
    if (sr->routing_table == 0) {
        /* routing table is empty */
    } else {
        rt_walker = sr->routing_table;
        int no_match = 0;

        while (rt_walker->next) {
            rt_walker = rt_walker->next;
            /* check routing table here */
        }

        if (no_match == 0) {
            /* If there is no match, send ICMP net unreachable */
            uint8_t *net_unreachable_reply = create_icmp_reply(packet, if_walker, packet_len, ip_hdr, dest_net_unreachable_type, dest_net_unreachable_code); 
            sr_send_packet(sr, port_unreachable_reply, packet_len, if_walker->name);
            free (dest_net_unreachable_reply);

        } else {
            /* If there is a match, check ARP cache */
            uint32_t dummy = 0;
            struct sr_arpentry entry = arpcache_lookup(&(sr->cache), dummy);

            if (entry) {
                /* If there is a match in our ARP cache, send frame to next hop */

            } else {
                /* If there is no match in our ARP cache, send ARP request. */
                /* If we don't get any reply after sending 5 request, send ICMP host unreachable */
            }
        }
    }
  }
}


uint8_t* create_arp_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_arp_hdr_t* arp_hdr) {
  uint8_t *reply_packet = malloc(packet_len);
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

uint8_t* create_icmp_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_ip_hdr_t *ip_hdr, uint8_t type, unsigned int code) {
  uint8_t *reply_packet = malloc(packet_len);
  create_ethernet_header (reply_packet, packet, if_walker); 

  /* Create IP header */
  sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
  memcpy(reply_ip_hdr, ip_hdr, sizeof(sr_ip_hdr_t));
  reply_ip_hdr->ip_src = ip_hdr->ip_dst;
  reply_ip_hdr->ip_dst = ip_hdr->ip_src;


  /* Create ICMP Header */
  sr_icmp_hdr_t *reply_icmp_hdr = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  reply_icmp_hdr->icmp_type = type;
  if (code != -1) {
    reply_icmp_hdr->icmp_code = code;
  }
  reply_icmp_hdr->icmp_sum = cksum (reply_icmp_hdr, ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl * 4);
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
