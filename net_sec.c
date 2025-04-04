#include <pcap.h> // 필요한 헤더파일 include
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

// Ethernet header – 이더넷의 구조를 나타내는 구조체 선언
struct ethheader {
    u_char ether_dhost[6]; // unsinged_char ether_dhost[6]과 동일한 문장
    u_char ether_shost[6];
    u_short ether_type;
};

// IP Header 
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
    u_char tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

#define SIZE_ETHERNET 14

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + SIZE_ETHERNET);
    int ip_header_len = ip->iph_ihl * 4;

    if (ip->iph_protocol != IPPROTO_TCP) return;

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = ((tcp->tcp_offx2 & 0xf0) >> 4) * 4;

    const u_char *payload = (u_char *)tcp + tcp_header_len;
    int payload_len = header->caplen - (SIZE_ETHERNET + ip_header_len + tcp_header_len);

    printf("Ethernet: src MAC %02X:%02X:%02X:%02X:%02X:%02X, dst MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
        eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
        eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
        eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
        eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("IP: src %s, dst %s\n",
        inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));

    printf("TCP: src port %d, dst port %d\n",
        ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));

    if (payload_len > 0) {
        printf("Message: ");
        for (int i = 0; i < payload_len && i < 32; i++) {
            if (isprint(payload[i])) putchar(payload[i]);
            else putchar('.');
        }
        printf("\n");
    }

    printf("\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    // 인터페이스 이름을 실제 시스템에 맞게 수정
    const char *dev = "enp0s3";

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    pcap_loop(handle, 0, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
