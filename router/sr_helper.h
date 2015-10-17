
#ifndef SR_HELPER_H
#define SR_HELPER_H

#define ICMP_ECHO_REQUEST 0
uint8_t* create_arp_reply (uint8_t * packet, struct sr_if * if_walker, int packet_len, sr_arp_hdr_t* arp_hdr);
uint8_t* create_icmp_reply (uint8_t* packet, struct sr_if* if_walker, int packet_len, sr_ip_hdr_t *ip_hdr);
int check_receiver (uint32_t ip, struct sr_instance* sr);
void sr_arphandler (struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);
void sr_iphandler (struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);
void create_ethernet_header (uint8_t * reply_packet, uint8_t * packet, struct sr_if * if_walker);

#endif /* SR_HELPER_H */