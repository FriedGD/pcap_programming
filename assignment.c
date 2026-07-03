#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<netinet/ether.h>
#include"Sniffing_Spoofing/C_spoof/myheader.h"

void packet_capture(unsigned char* user, const struct pcap_pkthdr* header, const unsigned char* packet){
    struct ethheader *eth = (struct ethheader*)packet;
    struct ipheader* ip = (struct ipheader*)((char*)packet+sizeof(struct ethheader));
    struct tcpheader* tcp = (struct tcpheader*)((char*)ip + ip->iph_ihl*4);
    char* payload = (char*)tcp + TH_OFF(tcp)*4;
    int payload_len = header->len - (payload - (char*)packet);


    printf("==========CAPTURED PACKET==========\n");
    
    printf("[L]Source MAC = %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("[L]Destination MAC = %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    printf("[N]Source IP = %s\n", inet_ntoa(ip->iph_sourceip));
    printf("[N]Destination IP = %s\n", inet_ntoa(ip->iph_destip));

    printf("[T]Source Port = %d\n", ntohs(tcp->tcp_sport));
    printf("[T]Destination Port = %d\n", ntohs(tcp->tcp_dport));

    if(payload_len > 0)
    {
        printf("[A]HTTP Message:\n");

        fwrite(payload, 1, payload_len, stdout);
    }

    printf("\n");
}

int main(){
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);
}