#include "pkt.h"

Pkt::Pkt(const u_char *_pkt){
    this->pkt = _pkt;
    this->ethhdr = (struct libnet_ethernet_hdr *)pkt;
}

Pkt::~Pkt(){

}

bool Pkt::isIp(){
    if(ntohs(ethhdr->ether_type) == ETHERTYPE_IP) {
        this->iphdr = (struct libnet_ipv4_hdr *)(pkt + ETH_HDR_LEN);
        return true;
    }
    return false;
}

bool Pkt::isTcp(){
    if(isIp()){
        if(iphdr->ip_p == IPPROTO_TCP){
            this->tcphdr = (struct libnet_tcp_hdr *)(pkt + ETH_HDR_LEN + 4*(iphdr->ip_hl));
            return true;
        }
    }
    return false;
}

bool Pkt::isHttp(){
    if(isTcp()){
        if(ntohs(tcphdr->th_dport) == TCP_PORT_HTTP || ntohs(tcphdr->th_sport) == TCP_PORT_HTTP){
            return true;
        }
    }
    return false;
}

void Pkt::printMac(uint8_t* mac) {
    int i;
    for (i=0;i<6;i++){
        printf("%02x", mac[i]);
        if (i != 5) printf(":");
        if (i == 5) printf("\n");
    }
}

void Pkt::printIp(struct in_addr *ip){
    char buf[16]={0,};
    inet_ntop(AF_INET, ip, buf, sizeof(buf));
    printf("%s\n", buf);
}

void Pkt::printTcp(uint16_t tcp){
    printf("%d\n", ntohs(tcp));
}

void Pkt::printTcpData(){
    int offset = ETH_HDR_LEN+(iphdr->ip_hl<<2)+(tcphdr->th_off<<2);
    size_t len = ntohs(iphdr->ip_len)-(iphdr->ip_hl<<2)-(tcphdr->th_off<<2);
    const u_char* data = pkt + offset;
    write(1, data, len);
}
