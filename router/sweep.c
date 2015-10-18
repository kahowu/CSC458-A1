
/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpcache *sr_cache = &sr->cache;

    struct sr_arpreq *sr_requests = sr_cache->requests;


    while (sr_requests) {
        struct sr_arpreq *following_requests = sr_requests->next;
        time_t curr_time;
        time(&curr_time);
        double one_sec = 1.0;
        if (difftime(curr_time, sr_requests->sent) >  one_sec){
            if ((sr_requests->times_sent) >= 5) {
                struct sr_packet *packet = sr_requests->packets; 
                while (packet) {
                    struct sr_if *if_walker = sr_get_interface (sr, packet->iface);
                    uint8_t *buf = packet->buf;
                    sr_ip_hdr_t *ip_hdr;
                    ip_hdr = malloc (sizeof(sr_ip_hdr_t));
                    memcpy (ip_hdr, (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)), sizeof (sr_ip_hdr_t));
                    int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
                    uint8_t *host_unreachable_reply = create_icmp_reply (buf, if_walker, packet_len, ip_hdr, dest_host_unreachable_type, dest_host_unreachable_code);
                    sr_send_packet (sr, host_unreachable_reply, packet_len, if_walker->name); 
                    free (host_unreachable_reply);  
                    
                    packet = packet->next;
                }
                sr_arpreq_destroy(sr_cache, sr_requests); 
            }
        } else {
            /* Send arp request */
            struct sr_packet *packet = sr_requests->packets;
            while (packet) {
                struct sr_if *if_walker = sr_get_interface (sr, packet->iface);
                uint8_t *buf = packet->buf;
                sr_arp_hdr_t *arp_hdr; 
                arp_hdr = malloc (sizeof (sr_arp_hdr_t));
                memcpy (arp_hdr, (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)), sizeof (sr_arp_hdr_t));

                int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                uint8_t *request_packet = malloc(packet_len);
                create_ethernet_header (request_packet, buf, if_walker); 

                sr_arp_hdr_t *arp_req_hdr = (sr_arp_hdr_t *)(request_packet + sizeof(sr_ethernet_hdr_t));
                arp_req_hdr->ar_hrd = arp_hdr->ar_hrd;
                arp_req_hdr->ar_pro = arp_hdr->ar_pro;
                arp_req_hdr->ar_hln = arp_hdr->ar_hln;
                arp_req_hdr->ar_pln = arp_hdr->ar_pln;
                arp_req_hdr->ar_op =  htons(arp_op_request);

                memcpy(arp_req_hdr->ar_sha, if_walker->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
                arp_req_hdr->ar_sip =  arp_hdr->ar_tip;
                memcpy(arp_req_hdr->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
                arp_req_hdr->ar_tip = arp_hdr->ar_sip;

                sr_send_packet(sr, request_packet, packet_len, if_walker->name);
                packet = packet->next;
            }

            sr_requests->sent = curr_time;
            sr_requests->times_sent = sr_requests->times_sent + 1;
        }
        sr_requests = following_requests;
    }
}