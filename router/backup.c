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

    /* Get ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;

    /* Check for mininum length requirement */
    int min_len = sizeof (sr_ethernet_hdr_t);
    if (len < min_len) {
        fprintf(stderr, "The ethernet header does not satisfy mininum length\n");
        return;
    }

    uint16_t ethtype = ethertype((uint8_t *)eth_hdr);

    if (ethtype == ethertype_ip){ /* IP */    
        printf("Received the IP Packet!\n");
        sr_iphandler(sr, packet, len, interface);
    } else if (ethtype == ethertype_arp){ /* ARP */
        printf("Received the ARP Packet!\n");
        sr_arphandler(sr, packet, len, interface);
    }

} /* end sr_ForwardPacket */

void sr_arphandler (struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    assert(sr);
    assert(packet);
    assert(interface);

    /* Get ARP header */
    sr_arp_hdr_t *arp_hdr; 
    arp_hdr = malloc (sizeof (sr_arp_hdr_t));
    memcpy (arp_hdr, (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t)), sizeof (sr_arp_hdr_t));

    /* Check for mininum length requirement */
    int min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    if (len < min_len) {
        fprintf(stderr, "The ethernet header does not satisfy mininum length \n");
        return;
    }

    struct sr_if *if_walker = sr_get_interface_ip(arp_hdr->ar_tip, sr);
    if (if_walker) {
        if (ntohs(arp_hdr->ar_op) == arp_op_request) {
            printf("ARP Request!\n");
            /* Check if the packet's target is current router */
            int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            /* Create reply packet to send back to sender */
            uint8_t *arp_reply = create_arp_reply(packet, if_walker, packet_len, arp_hdr, sr, interface);
            sr_send_packet(sr, arp_reply, packet_len, if_walker->name);
            printf("Sent an ARP reply packet\n");
            free(arp_reply);
            return;
    
        } else if (ntohs(arp_hdr -> ar_op) == arp_op_reply) {
            /*  only send an ARP reply if the target IP address is one of your router’s IP addresses.
                In the case of an ARP reply, you should only cache the entry if the target 
                IP address is one of your router’s IP addresses. */
            printf("ARP reply!\n");
            struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
            if (req){
                struct sr_packet *packet = req->packets;
                while (packet){
                    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) packet->buf;
                    memcpy(reply_eth_hdr->ether_dhost, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
                    memcpy(reply_eth_hdr->ether_shost, sr_get_interface(sr, packet->iface)->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
                    print_hdrs(packet->buf, packet->len);
                    sr_send_packet(sr, packet->buf, packet->len, packet->iface);
                    packet = packet->next;
                }
                printf("Sent packets from request queue\n");
                sr_arpreq_destroy(&sr->cache, req);
            }
            return;
        }
    } else {
        printf ("Dropping packet: ARP request is not targeted at current router.");
        return; 
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

    /* Get IP header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Check for mininum length  */
    int min_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    if (len < min_len){
        fprintf(stderr, "The IP header does not satisfy mininum length. \n");
        return;
    }

    /* Verify checksum */
    uint8_t original_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint8_t received_cksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    if (original_cksum != received_cksum){
        fprintf(stderr, "IP Header checksum fails.\n");
        return;
    }

    /* Decrement TTL and calculate new checksum */
    ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
    if (ip_hdr->ip_ttl == 0){
        fprintf(stdout, "IP TTL is 0. Abandoning the packet.\n");
        return;
    } else {
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    }

    /* Check if its for me */
    struct sr_if *if_walker = sr_get_interface_ip(ip_hdr->ip_dst, sr); 

    if (if_walker) {
        uint8_t ip_p = ip_protocol((uint8_t *)ip_hdr); 
        if (ip_p == ip_protocol_icmp) {
              /* Get ICMP header */
              sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
         
              /* Sanity Check */
              int minlength = sizeof(sr_ethernet_hdr_t)  + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
              if (len < minlength){
                fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
                return;
              }
         
              uint16_t received_cksum = icmp_hdr->icmp_sum;
              icmp_hdr->icmp_sum = 0;
              uint16_t computed_cksum = cksum(icmp_hdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
              if((received_cksum != computed_cksum)){
                fprintf(stderr, "ICMP Header checksum varies\n");
                return;
              }
              icmp_hdr->icmp_sum = received_cksum;

            /* If it's ICMP echo req, send echo reply */
            if (icmp_hdr->icmp_type == icmp_echo_request) {

                sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;

                /* Make ethernet header */
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, sr_->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

                /* Make IP header */
                /* Now update it */
                uint32_t temp_ip = ip_hdr->ip_src;
                ip_hdr->ip_src = ip_hdr->ip_dst;
                ip_hdr->ip_dst = temp_ip;
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

                /* Make ICMP Header */
                icmp_hdr->icmp_type = echo_reply_type;
                icmp_hdr->icmp_code = 0;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
                print_hdrs(packet, len);
                sr_send_packet(sr, packet, len, if_walker->name);

            } else {
                printf ("ICMP packet of unknown type \n");
                return;
            }
        /* If it is TCP / UDP, send ICMP port unreachable */
        } else if (ip_p == ip_protocol_udp || ip_p == ip_protocol_tcp) {
            printf ("TCP / UDP packet. Port unreachable \n");

            int packet_len  = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *reply_packet = malloc(packet_len);
 
            sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *) malloc(sizeof(sr_icmp_t3_hdr_t));
 
            if (!icmp_hdr) {
                perror("malloc failed");
                return;
            }
 
            int ip_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
 
            /* Copy over original ethernet header */
            sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
            memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));
 
            /* Create ethernet header */
            sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) reply_packet;
            memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
            memcpy(reply_eth_hdr->ether_shost, if_walker->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
            reply_eth_hdr->ether_type = eth_hdr->ether_type;
 
            /* Create IP header */
            sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
            reply_ip_hdr->ip_v = 4;
            reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
            reply_ip_hdr->ip_tos = 0;
            reply_ip_hdr->ip_len = htons(ip_len);
            reply_ip_hdr->ip_id = htons(0);
            reply_ip_hdr->ip_off = htons(IP_DF);
            reply_ip_hdr->ip_ttl = 64;
            reply_ip_hdr->ip_p = ip_protocol_icmp;
            reply_ip_hdr->ip_src = if_walker->ip;
            reply_ip_hdr->ip_dst = htonl(ip_hdr->ip_src);
 
            memset(&(reply_ip_hdr->ip_sum), 0, sizeof(uint16_t));
            uint16_t ip_ck_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));
            reply_ip_hdr->ip_sum = ip_ck_sum;
 
            /* Create ICMP Header */
            sr_icmp_t3_hdr_t * reply_icmp_hdr = (sr_icmp_t3_hdr_t*)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_icmp_hdr->icmp_type = port_unreachable_type;
            reply_icmp_hdr->icmp_code = port_unreachable_code;
            reply_icmp_hdr->unused = 0;
            reply_icmp_hdr->next_mtu = 0;
            memcpy(reply_icmp_hdr->data, (uint8_t *)ip_hdr, ICMP_DATA_SIZE);
 
            memset(&(reply_icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
            uint16_t icmp_ck_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            reply_icmp_hdr->icmp_sum = icmp_ck_sum;
 
            sr_send_packet (sr, reply_packet, packet_len, if_walker->name);
 
            free (reply_packet);

            return; 
        }
    /* Not for me*/ 
    } else {
        /* check routing table, and perform LPM */ 
        struct sr_rt* longest_prefix = routing_lpm (sr, ip_hdr->ip_dst); 
        struct sr_arpcache *sr_cache = &sr->cache;

        if (longest_prefix) {
            printf("There is a LPM.\n");
            struct sr_if *rt_walker = sr_get_interface(sr, longest_prefix->interface);
            /* If there is a match, check ARP cache */
            struct sr_arpentry * arp_entry = sr_arpcache_lookup (sr_cache,  longest_prefix->gw.s_addr); 
            /* If there is a match in our ARP cache, send frame to next hop */
            if (arp_entry){
                printf("There is a match in the ARP cache\n");

                sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
                memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));
                /* Create ethernet header */
                sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)packet;
                memcpy(reply_eth_hdr->ether_dhost, arp_entry->mac, sizeof(unsigned char)*6);
                memcpy(reply_eth_hdr->ether_shost, rt_walker->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
                reply_eth_hdr->ether_type = eth_hdr->ether_type;
                sr_send_packet (sr, packet, len, rt_walker->name); 
                return;

            } else {
                printf("There is no match in our ARP cache\n");
                /* If there is no match in our ARP cache, send ARP request. */
                /* If we don't get any reply after sending 5 request, send ICMP host unreachable */
                struct sr_arpreq * req = sr_arpcache_queuereq(sr_cache, ip_hdr->ip_dst, packet, len, rt_walker->name);
                handle_arpreq(req, sr);
                return;
            }

        /* If there is no match in routing table, send ICMP net unreachable */
        } else {
            int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *reply_packet = malloc(len);

            sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
            memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));

            /* Make ethernet header */
            sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)reply_packet;
            memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(sr_ethernet_hdr_t));
            memcpy(reply_eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(sr_ethernet_hdr_t));
            reply_eth_hdr->ether_type = htons(ethertype_ip);


            /* Make IP header */
            sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
            reply_ip_hdr->ip_v = 4;
            reply_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
            reply_ip_hdr->ip_tos = 0;
            reply_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            reply_ip_hdr->ip_id = htons(0);
            reply_ip_hdr->ip_off = htons(IP_DF);
            reply_ip_hdr->ip_ttl = 64;
            reply_ip_hdr->ip_dst = ip_hdr->ip_src;
            reply_ip_hdr->ip_p = ip_protocol_icmp;
            reply_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
            reply_ip_hdr->ip_sum = 0;
            reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));

            /* Make ICMP Header */
            sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            reply_icmp_hdr->icmp_type = dest_net_unreachable_type;
            reply_icmp_hdr->icmp_code = 0;
            reply_icmp_hdr->unused = 0;
            reply_icmp_hdr->next_mtu = 0;
            reply_icmp_hdr->icmp_sum = 0;
            memcpy(reply_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
            reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
            /*      sr_send_packet(sr, reply_packet, len, sr_get_interface(sr, interface)->name);*/

            struct sr_rt *prefix = routing_lpm(sr, ip_hdr->ip_src);
            if (prefix){
                printf("Found the match in routing table\n");
                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, prefix->gw.s_addr);
                if (entry){
                    printf("Found the ARP in the cache\n");

                    struct sr_if *router_if = sr_get_interface(sr, prefix->interface);

                    reply_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
                    reply_ip_hdr->ip_sum = 0;
                    reply_ip_hdr->ip_sum = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));

                    /* Make ethernet header */
                    memcpy(reply_eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
                    memcpy(reply_eth_hdr->ether_shost, router_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

                    print_hdrs(reply_packet, len);
                    sr_send_packet(sr, reply_packet, len, router_if->name);
                    free(entry);
                } else {
                    printf("ARP Cache miss\n");
                    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), prefix->gw.s_addr, reply_packet, len, prefix->interface);
                    handle_arpreq(req, sr);
                }    
            }
        }
    }
}


uint8_t* create_arp_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_arp_hdr_t* arp_hdr, struct sr_instance *sr, char* interface) {
    uint8_t *reply_packet = malloc(packet_len);

    /* Copy ethernet header */
    sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));

    /* Create ethernet header */
    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *) reply_packet;
    memcpy(reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    reply_eth_hdr->ether_type = eth_hdr->ether_type;

    /* Create ARP header */
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
    reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
    reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
    reply_arp_hdr->ar_op =  htons(arp_op_reply);

    /* Switch sender and receiver hardware and IP address */
    memcpy(reply_arp_hdr->ar_sha, if_walker->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip =  if_walker->ip;
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
    uint32_t temp_ip =  reply_ip_hdr->ip_src;
    reply_ip_hdr->ip_src = ip_hdr->ip_dst;
    reply_ip_hdr->ip_dst = temp_ip;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));


    /* Create ICMP Header */
    sr_icmp_hdr_t *reply_icmp_hdr = (sr_icmp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    reply_icmp_hdr->icmp_type = type;
    reply_icmp_hdr->icmp_code = code;
    reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, packet_len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
    return reply_packet;
}

void create_ethernet_header (uint8_t * new_packet, uint8_t * packet, struct sr_if * if_walker) {
    /* Copy over original ethernet header */
    sr_ethernet_hdr_t *eth_hdr = malloc(sizeof(sr_ethernet_hdr_t));
    memcpy(eth_hdr, (sr_ethernet_hdr_t *) packet, sizeof(sr_ethernet_hdr_t));

    /* Create ethernet header */
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_packet;
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, if_walker->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = eth_hdr->ether_type;
}
