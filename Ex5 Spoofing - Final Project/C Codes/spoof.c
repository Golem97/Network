#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

/*
checksum funtion given in HW3
(required for ICMP protocol)
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

int main(int argc, char **argv)
{
    struct ip ip;
    struct udphdr udp;
    struct icmp icmp;
    int sd;
    const int on = 1;
    struct sockaddr_in sin;
    u_char *packet;

    // Allocate memory for the packet
    packet = (u_char *)malloc(60);

    //IP Layer header

    //	IP header length is 20 bytes, so we need to stuff (20 / 4 = 5 here)
    ip.ip_hl = 0x5;
    //	ipv4
    ip.ip_v = 0x4;
    //	Type of Service
    ip.ip_tos = 0x0;
    // Total packet length (htons(60)
    ip.ip_len = 60;
    //	ID
    ip.ip_id = 0;
    //	Fragment packet (0x0 since we don't want any fragmentation)
    ip.ip_off = 0x0;
    //	Time to live
    ip.ip_ttl = 64;
    //	Upper layer (Layer 3) protocol number:
    ip.ip_p = IPPROTO_ICMP;
    //	Set the checksum value to zero
    ip.ip_sum = 0x0;
    //	Source IP address, doesn't have to be one of the assigned address to one of our VM
    ip.ip_src.s_addr = inet_addr("10.0.2.7");
    //  Destination IP address:
    ip.ip_dst.s_addr = inet_addr("192.168.95.100");
    //	The function gets the IP header and its length in parameters and returns us as 16-bit checksum value for the header
    ip.ip_sum = checksum((unsigned short *)&ip, sizeof(ip));
    // memcpy copies the IP header at the beggining of our packet
    memcpy(packet, &ip, sizeof(ip));

    //ICMP header construct

    //	Icmp type 8 for echo request:
    icmp.icmp_type = ICMP_ECHO;
    //  Code 0. Echo Request.
    icmp.icmp_code = 0;
    //ID. random number:
    icmp.icmp_id = htons(50179);
    //Using htons to transform to big endian
    icmp.icmp_seq = htons(0x0);
    //	Set the checksum value to zero 
    icmp.icmp_cksum = 0;

    icmp.icmp_cksum = htons(0x8336);
    //	We append the ICMP header to the packet at offset 20
    memcpy(packet + 20, &icmp, 8);
    
    //	Now thath the packet has been created we will create our raw socket and inject it into the network.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("raw socket");
        exit(1);
    }
    // Using setsockopt function to tell the kernel that we've also prepared the IP header
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }
    //	We need to specify a destination where to send the raw datagram
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;
    
    /*We cannot use send function for this since the socket is not a "connected"
    type of socket. So we will use the sendto function to tell where to send the raw IP datagram.*/
    if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin,
               sizeof(struct sockaddr)) < 0)
    {
        perror("sendto");
        exit(1);
    }

    return 0;
}

