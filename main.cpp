#include <pcap.h>
#include <stdio.h>

#include "pkt.h"

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

        Pkt pkt(packet);
        if(pkt.isHttp()){
            //print mac address
            printf("\nMAC\n");
            printf("Source MAC      : ");
            pkt.printMac(pkt.ethhdr->ether_shost);
            printf("Destination MAC : ");
            pkt.printMac(pkt.ethhdr->ether_dhost);

            //print ip address
            printf("\nIP\n");
            printf("Source IP       : ");
            pkt.printIp(&pkt.iphdr->ip_src);
            printf("Destination IP  : ");
            pkt.printIp(&pkt.iphdr->ip_dst);

            //print tcp port
            printf("\nTCP\n");
            printf("Source Port     : ");
            pkt.printTcp(pkt.tcphdr->th_sport);
            printf("Destination Port: ");
            pkt.printTcp(pkt.tcphdr->th_dport);

            //print tcp data
            printf("\nTCP DATA\n");
            pkt.printTcpData();
        }

    }

    pcap_close(handle);
    return 0;
}
