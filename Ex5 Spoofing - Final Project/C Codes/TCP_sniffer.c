#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
// #include<netinet/tcp.h>	//Provides declarations for tcp header

/* Ethernet header */
struct ethheader
{
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       //IP header length
        iph_ver : 4;                 //IP version
    unsigned char iph_tos;           //Type of service
    unsigned short int iph_len;      //IP Packet length (data + header)
    unsigned short int iph_ident;    //Identification
    unsigned short int iph_flag : 3, //Fragmentation flags
        iph_offset : 13;             //Flags offset
    unsigned char iph_ttl;           //Time to Live
    unsigned char iph_protocol;      //Protocol type
    unsigned short int iph_chksum;   //IP datagram checksum
    struct in_addr iph_sourceip;     //Source IP address
    struct in_addr iph_destip;       //Destination IP address
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

	unsigned short iphdrlen;
	
	
	//iphdrlen = ip->ihl*4;
	
	//struct tcphdr *tcph=(struct tcphdr*)(packet + sizeof(struct ethheader) + iphdrlen);

        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));

        //printf("         Source Port : %u\n", ntohs(tcph->source));
        //printf("         Destination Port : %u\n", ntohs(tcph->dest));
	

        /* determine protocol */
        switch (ip->iph_protocol)
        {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n\n");
            return;
        default:
            printf("   Protocol: others\n\n");
            return;
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    
    // TCP packets with dest port 10-100
    char filter_exp[] = "tcp dst portrange 10-100";
    
    // TCP packets port 23
    //char filter_exp[] = "tcp port 23";
    
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF pseudo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); //Close the handle
    return 0;
}
