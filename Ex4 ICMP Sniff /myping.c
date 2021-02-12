#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#define PACKETSIZE	64
struct packet
{
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

int pid=-1;
struct protoent *proto=NULL;

/*--------------------------------------------------------------------*/
/*--- checksum - standard 1s complement checksum                   ---*/
/*--------------------------------------------------------------------*/
unsigned short checksum(void *b, int len)
{	unsigned short *buf = b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/*--------------------------------------------------------------------*/
/*--- listener - separate process to listen for and collect messages--*/
/*--------------------------------------------------------------------*/
void listener(void)
{	int sd;
    struct sockaddr_in addr;
    unsigned char buf[1024];

    sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if ( sd < 0 )
    {
        perror("socket");
        exit(0);
    }
    for (;;)
    {
        int bytes, len=sizeof(addr);

        bzero(buf, sizeof(buf));
        bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &len);
        if ( bytes > 0 ){
            int i;
            struct iphdr *ip = buf;
            struct icmphdr *icmp = buf+ip->ihl*4;

            printf("----------------\n");
            for ( i = 0; i < bytes; i++ )
            {
                if ( !(i & 15) ) printf("\n%X:  ", i);
                printf("%X ", ((unsigned char*)buf)[i]);
            }
            printf("\n");
            printf("IPv%d: hdr-size=%d pkt-size=%d protocol=%d TTL=%d src=%s ",
                   ip->version, ip->ihl*4, ntohs(ip->tot_len), ip->protocol,
                   ip->ttl, inet_ntoa(ip->saddr));
            printf("dst=%s\n", inet_ntoa(ip->daddr));
            if ( icmp->un.echo.id == pid )
            {
                printf("ICMP: type[%d/%d] checksum[%d] id[%d] seq[%d]\n",
                       icmp->type, icmp->code, ntohs(icmp->checksum),
                       icmp->un.echo.id, icmp->un.echo.sequence);
            }
        }
        else
            perror("recvfrom");
    }
    exit(0);
}

/*--------------------------------------------------------------------*/
/*--- ping - Create message and send it.                           ---*/
/*--------------------------------------------------------------------*/
void ping(struct sockaddr_in *addr)
{	const int ttl=255;
    int i, sd, counter=1;
    struct packet pckt;
    struct sockaddr_in r_addr;

    sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if ( sd < 0 )
    {
        perror("socket not open");
        return;
    }
    // update ip_ttl
    if ( setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
        perror("Set TTL option");

    if ( fcntl(sd, F_SETFL, O_NONBLOCK) != 0 )
        perror("Request nonblocking I/O");

    // for (;;)
    // {
    int len=sizeof(r_addr);


    //print time milliseconds
    struct timeval stop, start;
    gettimeofday(&start, NULL);
    printf("message %d\n", counter);
    if ( recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &len) > 0 ){
        printf("sucsses got message\n");
        gettimeofday(&stop, NULL);
        printf("RTT %lu ms\n", (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec);
        printf("RTT %lu Ms\n", ((stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec)/1000);

    }
    //init pckt buffer
    bzero(&pckt, sizeof(pckt));
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = pid;
    //packet message counter
    for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
        pckt.msg[i] = i+'0';
    pckt.msg[i] = 0;
    pckt.hdr.un.echo.sequence = counter++;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    if ( sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0 )
        perror("sendto");
    else {
        struct timeval stop, start;
        gettimeofday(&start, NULL);
        printf("sucsses send to\n");
        gettimeofday(&stop, NULL);
        double mili=  (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;
        double micro=  mili*1000;
        printf("RTT %0.1lf mili\n", mili);
        printf("RTT %0.1lf micro\n", micro);



    }
    sleep(1);
    // }
}

/*--------------------------------------------------------------------*/
/*--- main - look up host and start ping processes.                ---*/
/*--------------------------------------------------------------------*/

int main(int count, char *str[])
{
    struct hostent *hname;
    struct sockaddr_in addr;

    if ( count != 2 )
    {
        printf("unUse %s adress\n", str[0]);
        exit(0);
    }
    if ( count > 1 )
    {
        pid = getpid();
        proto = getprotobyname("ICMP");
        hname = gethostbyname(str[1]);
        bzero(&addr, sizeof(addr));
        addr.sin_family = hname->h_addrtype;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = *(long*)hname->h_addr;
        if (fork() == 0 )
            listener();
        else
            ping(&addr);
        wait(0);
    }
    else
        printf("usage: myping <hostname>\n");
    return 0;
}
