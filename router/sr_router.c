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
    if (check_min_len (len, ETH_HDR)) {
        printf("Ethernet header does not satisfy mininum length requirement \n");
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
    sr_arp_hdr_t *arp_hdr = get_arp_hdr (packet);
    /* Get Ethernet header */
    sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);

    /* Check mininum length */
    if (check_min_len (len, ARP_PACKET)) {
        printf("ARP packet does not satisfy mininum length requirement \n");
        return;
    }

    /* If target interface is not NULL, the packet is for one of the interfaces in our router */
    struct sr_if *target_iface = get_router_interface (arp_hdr->ar_tip, sr);
    if (target_iface) {
        if (ntohs(arp_hdr->ar_op) == arp_op_request) {
            printf("Received ARP Request!\n");
            /* Create reply packet to send back to sender */
            int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            uint8_t *arp_reply = create_arp_reply(sr_get_interface(sr, interface), target_iface, eth_hdr, arp_hdr, packet_len);
            /* uint8_t *arp_reply = create_arp_reply(packet, target_iface, packet_len, arp_hdr, sr, interface);*/
            sr_send_packet(sr, arp_reply, packet_len, target_iface->name);
            printf("Sent an ARP reply packet\n");
            free(arp_reply);
            return;
    
        } else if (ntohs(arp_hdr -> ar_op) == arp_op_reply) {
            /* Cache ARP packet and go through the request queue to send out outstanding packets */
            printf("Received ARP reply!\n");
            send_arp_req (arp_hdr, &(sr->cache), sr);
            return;
        }
    } else {
        printf ("Dropping packet! ARP packet is not targeted at our router.");
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

    /* Get Ethernet header */
    sr_ethernet_hdr_t* eth_hdr = get_eth_hdr(packet);

    /* Get IP header */
    sr_ip_hdr_t * ip_hdr = get_ip_hdr(packet);

    /* Check for mininum length  */
    if (check_min_len (len, IP_PACKET)) {
        printf("IP packet does not satisfy mininum length requirement \n");
        return;
    }

    /* Verify checksum */
    if (verify_ip_checksum (ip_hdr)) {
        printf("IP Header checksum fails\n");
        return;
    } 

    /* Decrement TTL and calculate new checksum */
    if (decrement_and_recalculate (ip_hdr)){
        printf("TTL of IP is 0. Discarding packet ...\n");
        return;
    }

    /* If target interface is not NULL, the packet is for one of the interfaces in our router */
    struct sr_if *target_iface = get_router_interface (ip_hdr->ip_dst, sr);
    if (target_iface) {
        uint8_t ip_p = ip_protocol((uint8_t *)ip_hdr); 
        /* Check if the ip protocol is of type ICMP */
        if (ip_p == ip_protocol_icmp) {
            /* Get ICMP header */
            sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr (packet);
            /* Check for mininum length  */
            if (check_min_len (len, ICMP_PACKET)) {
                printf( "ICMP packet does not satisfy mininum length requirement\n");
                return;
            }
            /* If it's ICMP echo req, send echo reply */
            if (icmp_hdr->icmp_type == icmp_echo_request) {
                /* Verify icmp checksum*/
                if (verify_icmp_checksum (icmp_hdr, ICMP_PACKET, len)){
                    printf( "ICMP checksum fails\n");
                    return; 
                }

                /* Make ethernet header */
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

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
                sr_send_packet(sr, packet, len, interface);
                return;
            } else {
                printf ("ICMP packet of unknown type\n");
                return;
            }
        /* If it is TCP / UDP, send ICMP port unreachable */
        } else if (ip_p == ip_protocol_udp || ip_p == ip_protocol_tcp) {
            /* TODO */
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


/* Get Ethernet header */
sr_ethernet_hdr_t * get_eth_hdr (uint8_t* packet) {
    return (sr_ethernet_hdr_t *) packet; 
}

/* Get ARP header */
sr_arp_hdr_t * get_arp_hdr (uint8_t* packet) {
    return (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
}

/* Get IP header */
sr_ip_hdr_t *get_ip_hdr (uint8_t *packet) {
    return (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
}

sr_icmp_hdr_t *get_icmp_hdr (uint8_t *packet) {
    return (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
}

/* Verify IP checksum */
int verify_ip_checksum (sr_ip_hdr_t *ip_hdr) {
    uint16_t original_cksum = ip_hdr->ip_sum;
    memset(&(ip_hdr->ip_sum), 0, sizeof(uint16_t));
    uint16_t received_cksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    if (original_cksum != received_cksum){
        return 1;
    }
    return 0; 
}

/* Verify ICMP checksum */
int verify_icmp_checksum (sr_icmp_hdr_t *icmp_hdr, int type, int len) {
    if (type == ICMP_PACKET) {
        uint16_t original_cksum = icmp_hdr->icmp_sum;
        memset(&(icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
        uint16_t received_cksum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        if(original_cksum != received_cksum){
            return 1;
        }
        icmp_hdr->icmp_sum = received_cksum;
    } else if (type == ICMP_TYPE3_PACKET) {

    }
    return 0; 
}

/* Decrement TTL and calculate new checksum */
int decrement_and_recalculate (sr_ip_hdr_t *ip_hdr) {
    ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
    if (ip_hdr->ip_ttl == 0){
        return 1;
    } else {
        memset(&(ip_hdr->ip_sum), 0, sizeof(uint16_t));
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    }
    return 0;
}

void create_ethernet_header (sr_ethernet_hdr_t * eth_hdr, uint8_t * new_packet, uint8_t *src_eth_addr, uint8_t *dest_eth_addr) {
    /* Create ethernet header */
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_packet;
    memcpy(new_eth_hdr->ether_shost, src_eth_addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_dhost, dest_eth_addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = eth_hdr->ether_type;
} 

void create_arp_header (sr_arp_hdr_t* arp_hdr, uint8_t* new_packet, uint32_t src_ip, uint32_t dest_ip, unsigned char* sha, unsigned char* tha) {
    /* Create ARP header */
    sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = arp_hdr->ar_pln;
    new_arp_hdr->ar_op =  htons(arp_op_reply);

    /* Switch sender and receiver hardware and IP address */
    memcpy(new_arp_hdr->ar_sha, sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip =  src_ip; 
    memcpy(new_arp_hdr->ar_tha, tha, sizeof(unsigned char)*ETHER_ADDR_LEN);
    new_arp_hdr->ar_tip = dest_ip;
}

void create_ip_header (sr_ip_hdr_t *ip_hdr, uint8_t* new_packet) {
    sr_ip_hdr_t* new_ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t));
    memcpy (new_ip_hdr, ip_hdr, sizeof (sr_ip_hdr_t));
    uint32_t src_ip = ip_hdr->ip_src; 
    new_ip_hdr->ip_src = ip_hdr->ip_dst;
    new_ip_hdr->ip_dst = src_ip;
    memset(&(new_ip_hdr->ip_sum), 0, sizeof(uint16_t));
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
}

void create_icmp_header (uint8_t* new_packet, uint8_t type, unsigned int code, int len) {
    sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t *) (new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_hdr->icmp_type = type; 
    new_icmp_hdr->icmp_code = code;
    memset(&(new_icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
    new_icmp_hdr->icmp_sum = cksum(&(new_icmp_hdr->icmp_sum), len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
}

uint8_t* create_arp_reply (struct sr_if* src_iface, struct sr_if* out_iface, sr_ethernet_hdr_t* eth_hdr, sr_arp_hdr_t* arp_hdr, int packet_len) {
    uint8_t *reply_packet = malloc(arp_reply_len);
    /* Create Ethernet header */
    create_ethernet_header (eth_hdr, reply_packet, (uint8_t*)(src_iface->addr), eth_hdr->ether_shost); 
    /* Create ARP header */
    create_arp_header (arp_hdr, reply_packet, out_iface->ip, arp_hdr->ar_sip, out_iface->addr, arp_hdr->ar_sha); 

/*
    
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
    reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
    reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
    reply_arp_hdr->ar_op =  htons(arp_op_reply);

     Switch sender and receiver hardware and IP address 
    memcpy(reply_arp_hdr->ar_sha, out_iface->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip =  out_iface->ip;
    memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
    reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
*/
    return reply_packet;
}

uint8_t *create_echo_reply (struct sr_if* src_iface, sr_ethernet_hdr_t* eth_hdr, sr_ip_hdr_t* ip_hdr, int packet_len) {
    uint8_t *reply_packet = malloc(echo_reply_len);
    /* Create Ethernet header */
    create_ethernet_header (eth_hdr, reply_packet, (uint8_t*) (src_iface->addr), eth_hdr->ether_shost); 
    /* Create IP header */
    create_ip_header (ip_hdr, reply_packet);
    /* Create ICMP header */
    create_icmp_header (reply_packet, echo_reply_type, echo_reply_code, packet_len);
    return reply_packet;
}


void send_arp_req (sr_arp_hdr_t *arp_hdr, struct sr_arpcache *cache, struct sr_instance* sr) {
    struct sr_arpreq *req = sr_arpcache_insert(cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (req){
        struct sr_packet *req_packet = req->packets;
        while (req_packet) {
            sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *) req_packet->buf;
            memcpy(req_eth_hdr->ether_dhost, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
            memcpy(req_eth_hdr->ether_shost, sr_get_interface(sr, req_packet->iface)->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
            print_hdrs(req_packet->buf, req_packet->len);
            sr_send_packet(sr, req_packet->buf, req_packet->len, req_packet->iface);
            req_packet = req_packet->next;
        }
    }
    printf("Sent packets from request queue\n");
    sr_arpreq_destroy(cache, req);
}


/* Check for mininum length requirement for respective header type */
int check_min_len (unsigned int len, int type) {
    int min_len = 0;
    switch (type) {
        case ETH_HDR:
            min_len = sizeof (sr_ethernet_hdr_t);
            break; 
        case ARP_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
            break; 
        case IP_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
            break; 
        case ICMP_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof (sr_icmp_hdr_t);
            break; 
        case ICMP_TYPE3_PACKET:
            min_len = sizeof (sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof (sr_icmp_t3_hdr_t);
            break; 
    }
    /* Check for mininum length requirement */
    if (len < min_len) {
        printf( "The ethernet header does not satisfy mininum length \n");
        return 1;
    }
    return 0;
}


/* Return an interface if the targer IP belongs to our router */
struct sr_if* get_router_interface (uint32_t ip, struct sr_instance* sr) {
    struct sr_if* curr_iface = sr->if_list;
    while (curr_iface){
        /* Check if the interface IP matches the receiving router's IP */
        if (curr_iface->ip == ip){
            printf("Packet is for me \n");
            /* The packet is targeted towards the current router */
            return curr_iface;
        }
        curr_iface = curr_iface->next;
    }
    return NULL;
} 

