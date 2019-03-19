#pragma once
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LIBNET_LIL_ENDIAN   1
#pragma pack(push, 1)
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#pragma pack(pop)

#define ETH_HDR_LEN   14
#define TCP_PORT_HTTP 80

class Pkt {
private:
    const u_char* pkt;
public:
    struct libnet_ethernet_hdr *ethhdr;
    struct libnet_ipv4_hdr *iphdr;
    struct libnet_tcp_hdr *tcphdr;

    Pkt(const u_char* _pkt);
    ~Pkt();

    bool isIp();
    bool isTcp();
    bool isHttp();

    void printMac(uint8_t* mac);
    void printIp(struct in_addr *ip);
    void printTcp(uint16_t tcp);
    void printTcpData();
};
