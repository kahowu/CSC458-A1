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