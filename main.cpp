#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>


#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

/* Ethernet Header */
struct sniff_ethernet {
    u_char ether_shost[ETHER_ADDR_LEN]; // src MAC address
    u_char ether_dhost[ETHER_ADDR_LEN]; // dst MAC address
    u_short ether_type;
};

#define IP_HL(ip) (((ip)->ip_vhl) &0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >>4)

/* IP Header */
struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos;          // type of service
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;         // offset
#define IP_RF 0x8000        // reserved fragment flag
#define IP_DF 0x4000        // dont fragment flag
#define IP_MF 0x2000        // more fragment flag
#define IP_OFFMASK 0x1fff   // mask
    u_char ip_ttl;          // time to live
    u_char ip_p;            // ip protocol type
    u_short ip_sum;        // checksum
    struct in_addr ip_src; // src ip address
    struct in_addr ip_dst; // dst ip address
};

typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;   // src port
    u_short th_dport;   // dst port
    tcp_seq th_seq;     // sequential number
    tcp_seq th_ack;
    u_char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     // window
    u_short th_sum;     // checksum
    u_short th_urp;     // urgent pointer
};

struct sniff_ethernet *eth;
struct sniff_ip *ip;
struct sniff_tcp *tcp;
char* payload;

u_int size_ip;
u_int size_tcp;

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }



    while (true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        eth = (struct sniff_ethernet *)packet;
        printf("src Mac: %02x:%02x:%02x:%02x:%02x:%02x \n",
               eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
               eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]
              );
        printf("dst Mac: %02x:%02x:%02x:%02x:%02x:%02x \n",
               eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
               eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]
              );
        ip = (struct sniff_ip *)(packet+SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        printf("src IP: %s\n", inet_ntoa(ip->ip_src));
        printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
        tcp = (struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
        size_tcp = TH_OFF(tcp)*4;
        payload=(char *)(packet+SIZE_ETHERNET+size_ip+ size_tcp);
        int payload_len=ntohs(ip->ip_len) - (size_tcp + size_ip);
        printf("src Port : %d\n", ntohs(tcp->th_sport));
        printf("dst Port : %d\n", ntohs(tcp->th_dport));
        printf("payload length = %d\n", payload_len);
        for(int i=0; i<16; i++){
                printf("%x", payload[i]);
            }
            printf("\n================================================\n");
    }

}
