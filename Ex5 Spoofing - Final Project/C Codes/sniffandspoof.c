#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET sizeof(struct ethhdr)

/* Spoofed packet containing only IP and ICMP headers */
struct spoofed_packet
{
    struct ip iph;
    struct icmp icmph;
};

/*
 * checksum function given in HW3
 */
unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while (size > 1)
    {
        cksum += *buffer++;
        size  -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(char*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
	{
	
	
	static int count = 1;                   /* packet counter */
	int s;	// socket
	const int on = 1;

	/* declare pointers to packet headers */
	const struct ether_header *ethernet = (struct ether_header*)(packet);
	const struct ip *iph;              /* The IP header */
	const struct icmp *icmph;            /* The ICMP header */
	struct sockaddr_in dst;

	int size_ip;

	/* Define/Compute ip header offset */
	iph = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = iph->ip_hl*4;	// size of ip header

	if (iph->ip_p != IPPROTO_ICMP || size_ip < 20) {  // disregard other packets
		return;
	}

	/* Define/Compute icmp header offset */
	icmph = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);

	/* Print source and destination IP addresses */
	printf("%d) ICMP Sniffing source: from--%s\n", count, inet_ntoa(iph->ip_src) );
  printf("   ICMP Sniffing destination: to--%s\n\n", inet_ntoa(iph->ip_dst) );

	/* Construct the spoof packet and allocate memory with the lengh of the datagram */
	char buf[htons(iph->ip_len)];
	struct spoofed_packet *spoof = (struct spoofed_packet *) buf;

	/* Initialize the structure spoof by copying everything in request packet to spoof packet*/
	memcpy(buf, iph, htons(iph->ip_len));
	/* Modify ip header */

	//  Swap the destination ip address and source ip address
	(spoof->iph).ip_src = iph->ip_dst;
	(spoof->iph).ip_dst = iph->ip_src;

	//  Recompute the checksum, we can leave it to 0 here since RAW socket will compute it for us.
	(spoof->iph).ip_sum = 0;

	/* Modify icmp header */

	// Set the spoofed packet as echo-reply
	(spoof->icmph).icmp_type = ICMP_ECHOREPLY;
	// Always set code to 0
	(spoof->icmph).icmp_code = 0;
    //  Initialize icmp checksum to 0
	(spoof->icmph).icmp_cksum = 0;
	(spoof->icmph).icmp_cksum = checksum((unsigned short *) &(spoof->icmph), sizeof(spoof->icmph));
	//  Print the spoofed packet information
	printf("Spoofed packet src is %s\n",inet_ntoa((spoof->iph).ip_src));
	printf("Spoofed packet dest is %s\n\n",inet_ntoa((spoof->iph).ip_dst));

	memset(&dst, 0, sizeof(dst));
    	dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = (spoof->iph).ip_dst.s_addr;

	/* Create RAW socket */
	if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        printf("socket() error");
		return;
	}

	/* Socket options, tell the kernel we provide the IP structure */
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		printf("setsockopt() for IP_HDRINCL error");
		return;
	}

	if(sendto(s, buf, sizeof(buf), 0, (struct sockaddr *) &dst, sizeof(dst)) < 0) {
		printf("sendto() error");
	}

 	 printf("Spoofed Packet sent successfully\n");
	//close(s);	// free resource

	//free(buf);
	count++;
	}
	
int main()
	{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;

	// ICMP packets
	char filter_exp[] = "icmp";
	
	bpf_u_int32 net;
	// Step 1: Open live pcap session on NIC with name eth3
	//Students needs to change "eth3" to the name
	//found on their own machines (using ifconfig). - enp0s3
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
	// Step 2: Compile filter_exp into BPF pseudo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	// Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
	//Close the handle
	}
	
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
