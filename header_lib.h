#include <stdint.h>
#include <netinet/in.h>

#define ETHER_ALEN 6
#define SIZE_ETHERNET 14
#define ETHERTYPE_IP 0x8000
#define IP_TCP 6


struct sniff_ethernet {
    uint8_t ether_dhost[ETHER_ALEN];
    uint8_t ether_shost[ETHER_ALEN];
    uint16_t ether_type;
};


struct sniff_ip_hdr {
    uint8_t ip_hl:4;
    uint8_t ip_v:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct sniff_tcp_hdr {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_x2:4;
    uint8_t th_off:4;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};
