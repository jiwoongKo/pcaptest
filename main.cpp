#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include "header_lib.h"


struct sniff_ip_hdr* iph;           /* ip 헤더 */
struct sniff_tcp_hdr* tcph;         /* tcp 헤더 */
struct sniff_ethernet *ethernet;    /* 이더넷 헤더 */
char *payload; 
u_int size_ip;
u_int size_tcp;
uint16_t ether_type;

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
    usage();
    return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
    }


  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n============%u bytes captured============\n", header->caplen);

    int i, payload_len;

    /* 이더넷 헤더 */
    ethernet = (struct sniff_ethernet*)(packet);
    printf("MAC src address : ");
    for(i = 0; i < ETHER_ALEN; i++){                 /* 이더넷 어드레스 반복되는것 for문으로 처리 */
        printf("%02x ", ethernet->ether_shost[i]);
    }
    printf("\nMac dst address : ");
    for(i = 0; i < ETHER_ALEN; i++){
        printf("%02x ", ethernet->ether_dhost[i]);
    }
    printf("\n");
     
    /* 프로토콜 타입 변환 */
    ether_type = ntohs(ethernet->ether_type);
    
      
      
    /* ether_type -> 0x0800인지 확인 */
    if (ether_type != ETHERTYPE_IP){
        continue;
    }
    
    /* 설정한 ip 헤더를 통해 packet 출발, 도착 address 출력 */
    iph = (struct sniff_ip_hdr*)(packet + SIZE_ETHERNET);
    printf("==================IP Packet=============\n");
    printf("src IP : %s\n", inet_ntoa(iph->ip_src));
    printf("dst IP : %s\n", inet_ntoa(iph->ip_dst));

    /* TCP 패킷이 아니라면 continue */
    if (iph->ip_p != IP_TCP){
        continue;
    }

    size_ip = (iph->ip_hl)*4;
    /* tcp 데이터 출력 */
    tcph = (struct sniff_tcp_hdr *)(packet + SIZE_ETHERNET + size_ip);
    printf("src Port : %d\n ", ntohs(tcph->th_sport));
    printf("dst Port : %d\n ", ntohs(tcph->th_dport));

    
    size_tcp = (tcph->th_off)*4;
    /* 페이로드 데이터 범위 설정 */
    payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    payload_len = ntohs(iph->ip_len) - (size_ip + size_tcp);
    if(payload_len == 0) printf("No payload data");
    
    /* 기존에는 페이로드 데이터가 16 이하에서는 구분을 안해놔서 없는 데이터 출력 하는것까지 보완 */
    (payload_len > 16 ? payload_len = 16 : payload_len);
    for(i = 0; i < payload_len; i++){
            printf("%02x ", payload[i]);    /* 페이로드 데이터 출력 */
    }
    printf("\n");

   }

     pcap_close(handle);
     return 0;
}
