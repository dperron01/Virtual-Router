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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  time_t timer;
  timer = time(NULL);
  

  if (difftime(timer, req->sent) > 1.0)
  {
    if (req->times_sent >=5)
    {
      /*send icmp unreachable*/
      struct sr_packet* p = req->packets;
      while (p != NULL)
      {
        sr_ethernet_hdr_t* ether = (sr_ethernet_hdr_t*)p;
        sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(p + sizeof(ether));

        printf("sending type 3 code 1\n");

uint8_t buffer[sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
            sr_ethernet_hdr_t* hdr1 = (sr_ethernet_hdr_t*)buffer;
            sr_ip_hdr_t* hdr2 = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t* hdr3 = (sr_icmp_t3_hdr_t*)(buffer + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
        int i;
        /*set ethernet header*/
        for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
          hdr1->ether_dhost[i] = ether->ether_shost[i];
          hdr1->ether_shost[i] = ether->ether_dhost[i];
        }
        hdr1->ether_type = htons(ethertype_ip);

        /*set ip header*/
          struct sr_if* table = sr_get_interface( sr , req->packets->iface);
            /*set ip header*/
           hdr2->ip_p  = htons(1);
           hdr2->ip_v = 4;
           hdr2->ip_hl = 5;
           hdr2->ip_tos = ip_hdr->ip_tos ;
           hdr2->ip_len = htons(24);
           hdr2->ip_id  = ip_hdr->ip_id;
           hdr2->ip_off  = ip_hdr->ip_off;
           hdr2->ip_ttl  = 64;
           hdr2->ip_p  = 1;
           hdr2->ip_src  = table->ip;
           hdr2->ip_dst  = ip_hdr->ip_src;
           hdr2->ip_sum = htons(0);
           hdr2->ip_sum = cksum(hdr2, hdr2->ip_hl*4);
           print_hdr_ip((uint8_t*)hdr2);
           /*set icmp header*/

       /*set icmp header*/
       hdr3->icmp_type = 3;
       hdr3->icmp_code = 1;
       hdr3->icmp_sum = 0;
                  hdr3->unused = 0;


       hdr3->icmp_sum = cksum(hdr3, sizeof(sr_icmp_t3_hdr_t));
       

       sr_send_packet(sr, buffer, sizeof(buffer), (const char*)table);


        p = p->next;
      }


      /*--------------*/
      sr_arpreq_destroy(&sr->cache, req);
    }
    else
    {
      /*Send arp request*/
        struct sr_if* table = sr_get_interface( sr , req->packets->iface);
        printf("Printing table->addr \n");
        
        uint8_t buffer[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)buffer;
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));

        /*fill ethernet header*/
        int i;
        for (i = 0; i < ETHER_ADDR_LEN; i++)
        {
          eth_hdr->ether_dhost[i] = htons(65535);
          eth_hdr->ether_shost[i] = table->addr[i];
          arp_hdr->ar_sha[i] = eth_hdr->ether_shost[i];
          arp_hdr->ar_tha[i] = eth_hdr->ether_dhost[i];
        }
        eth_hdr->ether_type = htons(ethertype_arp);

        /*fill arp header*/
        arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
        arp_hdr->ar_pro = htons(ethertype_ip);
        arp_hdr->ar_hln = 6;
        arp_hdr->ar_pln = 4;
        arp_hdr->ar_op = htons(arp_op_request);
        arp_hdr->ar_sip = table->ip; 
        arp_hdr->ar_tip = req->ip;

        
        
        sr_send_packet(sr, buffer, sizeof(buffer), (const char*)table);
        
      
      /*-----------------*/
      req->sent = timer;
      req->times_sent++;
    }
  }
  
}

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
    
    /* TODO: (opt) Add initialization code here */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);
  print_hdrs( packet, len);
  uint16_t ethtype = ethertype(packet);


  /* TODO: Add forwarding logic here */


  /*Packet is of type ARP
  Find out if is a request or a reply
  OPCODE: 1 means request
  OPCODE: 2 means reply*/
  if (ethtype == ethertype_arp)
  {

    
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* Receievd Request */
    if (ntohs(arp_hdr->ar_op) == 1)
    {
      
    
      struct sr_if* node = sr->if_list;

      /*Check if target IP is in one of our interfaces */
      while (node != NULL)
      {
        /*Target IP is one of our interfaces */
        if (node->ip == arp_hdr->ar_tip )
        {
          /*send arp reply*/
          /*Ethernet header*/
          char buffer[sizeof(struct sr_arp_hdr) + sizeof(struct sr_ethernet_hdr)];
          struct sr_ethernet_hdr* ethReply = (struct sr_ethernet_hdr*)buffer;  /*packet*/
          struct sr_arp_hdr* arpReply = (struct sr_arp_hdr*)(buffer + sizeof(struct sr_ethernet_hdr));  /*ARP header*/
          
          /*Set ARP header fields*/
          arpReply->ar_hrd = htons(arp_hrd_ethernet);
          arpReply->ar_pro = htons(2048);
          arpReply->ar_hln = arp_hdr->ar_hln;
          arpReply->ar_pln = arp_hdr->ar_pln;;
          arpReply->ar_op = htons(arp_op_reply);
          arpReply->ar_sip = node->ip; 
          arpReply->ar_tip = arp_hdr->ar_sip;

          /*set ethernet header fields*/
          ethReply->ether_type = htons(ethertype_arp);

          /*Assignt source and target address to ethernet and arp headers*/
          int i;
          for (i = 0; i < ETHER_ADDR_LEN; i++)
          {
            arpReply->ar_sha[i] = node->addr[i]; /*source hardware set to matching interface ethernet address*/
            ethReply->ether_shost[i] = node->addr[i];
            arpReply->ar_tha[i] = arp_hdr->ar_sha[i];
            ethReply->ether_dhost[i] = arp_hdr->ar_sha[i];
          }
         
         sr_send_packet(sr, (uint8_t*)buffer, sizeof(buffer), (const char*) node);

         break;
        }
        
        node = node->next;
        
      }
    
    }
    else if (ntohs(arp_hdr->ar_op) == 2)
    {
     
      /*ARP REPLY LOGIC*/
      struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      if (req != NULL)
      {
        struct sr_packet* p = req->packets;
        while (p!=NULL)
        {
         
          

          sr_ethernet_hdr_t* hdr = (sr_ethernet_hdr_t*)p->buf;
          int i;
          for (i = 0; i < ETHER_ADDR_LEN; i++)
          {
            hdr->ether_dhost[i] = arp_hdr->ar_sha[i];
          }

          sr_send_packet(sr, p->buf, p->len, p->iface);

          p = p->next;
        }

      }


      /*              */
    }

  }  
  /*check if IP request*/
  else if (ethtype == ethertype_ip)
  {
    /*printf("It's IP\n");*/
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t check = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_sum = check;
    if (len >= sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) && check == checksum )
    {
      /*printf("good check sum\n");*/
      /*check to see if destination is our interface*/
      struct sr_if* node = sr->if_list;
      while (node != NULL && node->ip != ip_hdr->ip_dst)
      {
        node = node->next;

      }
      
      if (node != NULL) /* Destination was one of our IPs */
      {
        /*printf("found node\n");*/
        /*check to see if ICMP ECHO*/
        if (ntohl(ip_hdr->ip_p) == ip_protocol_icmp)
        {
          sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(struct sr_ip_hdr));
          if (ntohs(icmp_hdr->icmp_code) == 8)  /*Is an echo request*/
          {
            /*send response*/
            sr_ethernet_hdr_t* ether = (sr_ethernet_hdr_t*)packet;

            /*printf("sending echo response\n");*/

            uint8_t buffer[sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
            sr_ethernet_hdr_t* hdr1 = (sr_ethernet_hdr_t*)buffer;
            sr_ip_hdr_t* hdr2 = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t* hdr3 = (sr_icmp_t3_hdr_t*)(buffer+sizeof(hdr1)+sizeof(hdr2));
            int i;
            /*set ethernet header*/
            for (i = 0; i < ETHER_ADDR_LEN; i++)
            {
              hdr1->ether_dhost[i] = ether->ether_shost[i];
              hdr1->ether_shost[i] = ether->ether_dhost[i];
            }
            hdr1->ether_type = htons(ethertype_ip);

            /*set ip header*/
            hdr2->ip_tos = ip_hdr->ip_tos ;
           hdr2->ip_len  = ip_hdr->ip_len;
           hdr2->ip_id  = ip_hdr->ip_id;
           hdr2->ip_off  = ip_hdr->ip_off;
           hdr2->ip_ttl  = htons(64);;
           hdr2->ip_p  = ip_hdr->ip_p;
           hdr2->ip_src  = ip_hdr->ip_dst;
           hdr2->ip_dst  = ip_hdr->ip_src;
           hdr2->ip_sum = htons(0);
           hdr2->ip_sum = cksum(hdr2, hdr2->ip_hl*4);

           /*set icmp header*/
           hdr3->icmp_type = htons(0);
           hdr3->icmp_code = htons(0);
           hdr3->icmp_sum = 0;

           for (i = 0; i < ICMP_DATA_SIZE; i++)
           {
            hdr3->data[i] = icmp_hdr->data[i];
           }

           hdr3->icmp_sum = cksum(hdr3, sizeof(sr_icmp_t3_hdr_t));

           sr_send_packet(sr, buffer, sizeof(buffer), interface);




          }  
        } /*Was a different type of protocol. Possibly udp or tcp*/
        else if (ntohl(ip_hdr->ip_p) == 6 || ntohl(ip_hdr->ip_p) == 17)
        {
          /*is TCP/UDP
            Send unreachable*/

                                /*send response*/
            sr_ethernet_hdr_t* ether = (sr_ethernet_hdr_t*)packet;

            /*printf("sending unreachable  type 3 code 0\n");*/

            uint8_t buffer[sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
            sr_ethernet_hdr_t* hdr1 = (sr_ethernet_hdr_t*)buffer;
            sr_ip_hdr_t* hdr2 = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t* hdr3 = (sr_icmp_t3_hdr_t*)(buffer+sizeof(hdr1)+sizeof(hdr2));
            int i;
            /*set ethernet header*/
            for (i = 0; i < ETHER_ADDR_LEN; i++)
            {
              hdr1->ether_dhost[i] = ether->ether_shost[i];
              hdr1->ether_shost[i] = ether->ether_dhost[i];
            }
            hdr1->ether_type = htons(ethertype_ip);

            uint32_t ips = sr_get_interface(sr, interface)->ip;
            /*set ip header*/
           hdr2->ip_p  = htons(1);
           hdr2->ip_v = 4;
           hdr2->ip_hl = 5;
           hdr2->ip_tos = ip_hdr->ip_tos ;
           hdr2->ip_len = htons(24);
           hdr2->ip_id  = ip_hdr->ip_id;
           hdr2->ip_off  = ip_hdr->ip_off;
           hdr2->ip_ttl  = 64;
           hdr2->ip_p  = 1;
           hdr2->ip_src  = ips;
           hdr2->ip_dst  = ip_hdr->ip_src;
           hdr2->ip_sum = htons(0);
           hdr2->ip_sum = cksum(hdr2, hdr2->ip_hl*4);

           /*set icmp header*/
           hdr3->icmp_type = 3;
           hdr3->icmp_code = 3;
           hdr3->icmp_sum = 0;


           hdr3->icmp_sum = cksum(hdr3, sizeof(sr_icmp_t3_hdr_t));

           sr_send_packet(sr, buffer, sizeof(buffer), interface);

        }
        /*else ignore*/
      }
      else  /*Destination was headed elsewhere. Check routing table.*/
      {
        /*printf("elsewhere\n");*/
        /*decrement ttl*/
        uint8_t ttl = ip_hdr->ip_ttl;
        ttl -= 1;
        /*printf("new ttl = %u\n ", ttl);*/
        if (ttl == 0)
        {
                      sr_ethernet_hdr_t* ether = (sr_ethernet_hdr_t*)packet;

            

            uint8_t buffer[sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
            sr_ethernet_hdr_t* hdr1 = (sr_ethernet_hdr_t*)buffer;
            sr_ip_hdr_t* hdr2 = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t* hdr3 = (sr_icmp_t3_hdr_t*)(buffer + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
            int i;
            /*set ethernet header*/
            for (i = 0; i < ETHER_ADDR_LEN; i++)
            {
              hdr1->ether_dhost[i] = ether->ether_shost[i];
              hdr1->ether_shost[i] = ether->ether_dhost[i];
            }
            hdr1->ether_type = htons(ethertype_ip);

            uint32_t ips = sr_get_interface(sr, interface)->ip;
            /*set ip header*/
           hdr2->ip_p  = htons(1);
           hdr2->ip_v = 4;
           hdr2->ip_hl = 5;
           hdr2->ip_tos = ip_hdr->ip_tos ;
           hdr2->ip_len = htons(56);
           hdr2->ip_id  = ip_hdr->ip_id;
           hdr2->ip_off  = ip_hdr->ip_off;
           hdr2->ip_ttl  = 64;
           hdr2->ip_p  = 1;
           hdr2->ip_src  = ips;
           hdr2->ip_dst  = ip_hdr->ip_src;
           hdr2->ip_sum = htons(0);
           hdr2->ip_sum = cksum(hdr2, hdr2->ip_hl*4);
           
           /*set icmp header*/
           
           hdr3->icmp_type = 11;
           hdr3->icmp_code = 0;
           hdr3->icmp_sum = 0;
           hdr3->unused = 0;
           for (i=0; i < ICMP_DATA_SIZE; i++)
           {
            hdr3->data[i] = packet[i];
           }







           

           hdr3->icmp_sum = cksum(hdr3, sizeof(sr_icmp_t3_hdr_t));
           
           sr_send_packet(sr, buffer, sizeof(buffer), interface);
           return;
        }
       /* printf("TTL: %d %d\n", ttl, ip_hdr->ip_ttl);*/
        ip_hdr->ip_ttl -= 1;
        /*recompute checksum*/
        ip_hdr->ip_sum = htons(0);
       
       /* printf(" %d ", ip_hdr->ip_hl);*/
        uint16_t sums = cksum(ip_hdr, ip_hdr->ip_hl*4);
       /* printf("%d %d %d\n", sums, ntohs(sums), htons(sums));*/
        ip_hdr->ip_sum = sums;
       
        /*go through routing table*/
        struct sr_rt* table = sr->routing_table;
        int max = 0;
        int score = 0;
        unsigned long divi;
        unsigned long destip;
        unsigned long rtip;
        unsigned check;
        struct sr_rt* best;
        unsigned track;
        /*find matching interface by using longest prefix matching*/
        while (table != NULL)
        {
          divi = 2147483648;
          score = 0;
          track = 1;
          rtip = ntohl(table->dest.s_addr);
          destip = ntohl(ip_hdr->ip_dst);
          check = ntohl(table->mask.s_addr);
          rtip = check & rtip; /*apply subnet mask*/
          /*printf("MASK: %lu %lu\n", check & rtip, rtip);*/
          while (divi != 0 && track <= 99)
          {
            if (rtip/divi == destip/divi)
            {
              score+=1;
              track+=1;
              rtip = rtip%divi;
              destip = destip%divi;
            }
            else
            {
              score = 0;
              break;
            }
            divi = divi/2;
          }
          if (score > max)
          {
            best = table;
            max = score;
          }
          table = table->next;
        }
        if (max == 0)
        {
                      /*send response*/
            sr_ethernet_hdr_t* ether = (sr_ethernet_hdr_t*)packet;

           /* printf("sending unreachable  type 3 code 0\n");*/

uint8_t buffer[sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t)];
            sr_ethernet_hdr_t* hdr1 = (sr_ethernet_hdr_t*)buffer;
            sr_ip_hdr_t* hdr2 = (sr_ip_hdr_t*)(buffer + sizeof(sr_ethernet_hdr_t));
            sr_icmp_t3_hdr_t* hdr3 = (sr_icmp_t3_hdr_t*)(buffer + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
            int i;
            /*set ethernet header*/
            for (i = 0; i < ETHER_ADDR_LEN; i++)
            {
              hdr1->ether_dhost[i] = ether->ether_shost[i];
              hdr1->ether_shost[i] = ether->ether_dhost[i];
            }
            hdr1->ether_type = htons(ethertype_ip);

            uint32_t ips = sr_get_interface(sr, interface)->ip;
            /*set ip header*/
           hdr2->ip_p  = htons(1);
           hdr2->ip_v = 4;
           hdr2->ip_hl = 5;
           hdr2->ip_tos = ip_hdr->ip_tos ;
           hdr2->ip_len = htons(24);
           hdr2->ip_id  = ip_hdr->ip_id;
           hdr2->ip_off  = ip_hdr->ip_off;
           hdr2->ip_ttl  = 64;
           hdr2->ip_p  = 1;
           hdr2->ip_src  = ips;
           hdr2->ip_dst  = ip_hdr->ip_src;
           hdr2->ip_sum = htons(0);
           hdr2->ip_sum = cksum(hdr2, hdr2->ip_hl*4);
           /*print_hdr_ip((uint8_t*)hdr2);*/
           /*set icmp header*/

           /*set icmp header*/
           hdr3->icmp_type = 3;
           hdr3->icmp_code = 0;
           hdr3->icmp_sum = 0;

                      hdr3->unused = 0;
           for (i=0; i < ICMP_DATA_SIZE; i++)
           {
            hdr3->data[i] = packet[i];
           }


           hdr3->icmp_sum = cksum(hdr3, sizeof(sr_icmp_t3_hdr_t));

           sr_send_packet(sr, buffer, sizeof(buffer), interface);
        }
        else
        {
         /* printf("best %u\n", ntohl(best->dest.s_addr));*/
        /*We now have the proper interface to send packet*/
        /*Check if ip in arpcache*/
        struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, best->dest.s_addr);
      /*  printf("interface %s\n", best->interface);*/

        if (entry != NULL)  /*Valid entry*/
        {
         /* printf("not null\n"); */
          /*send packet*/
          struct sr_if* interface = sr_get_interface(sr, best->interface);
          sr_ethernet_hdr_t* hdr = (sr_ethernet_hdr_t*)packet;
          int i;
          for (i = 0; i < ETHER_ADDR_LEN; i++)
          {
            hdr->ether_shost[i] = interface->addr[i];
            hdr->ether_dhost[i] = entry->mac[i];
          }
          sr_send_packet(sr, packet, len, (char*)interface);

          free(entry);

        }
        else /*Not in aprcache*/
        {
          /*send arp request*/
        /*  printf("null\n"); */
          struct sr_if* interface = sr_get_interface(sr, best->interface);
         
          sr_ethernet_hdr_t* hdr = (sr_ethernet_hdr_t*)packet;
          int i;
          for (i = 0; i < ETHER_ADDR_LEN; i++)
          {
            hdr->ether_shost[i] = interface->addr[i];
          }
          
          struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, best->dest.s_addr, packet, len, (char*)interface  );
          handle_arpreq(sr, req);
          /*add to arpcache*/

        }
        }

        


      }

      
    }
    else
    {
     /* printf("bad check sum\n"); */
      /*printf("%d %d %d %d", checksum, htons(checksum), ntohs(checksum), check );*/
    }

  }

}/* -- sr_handlepacket -- */

