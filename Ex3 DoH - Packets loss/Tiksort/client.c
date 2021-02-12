#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#define SIZE 1024
// function send file
void send_file(FILE *fp, int sockfd){
        int n;
        char data[SIZE] = {0};
        while(fgets(data, SIZE, fp) != NULL) {
                if (send(sockfd, data, sizeof(data), 0) == -1) {
                        perror("[-]Error in sending file.");
                        exit(1);
                }
                bzero(data, SIZE);
        }
}

int main(){
        //varibels
        char *ip = "127.0.0.1";
        int port = 8080;
        int con;
        int sockfd;
        struct sockaddr_in server_addr;
        FILE *fp;
        char *filename = "1mb.txt";

        //time
        clock_t t;
        //for algo
        socklen_t len;
        char algo[256];
        //open socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        //check open socket
        if(sockfd == -1) {
                perror("[-]Error in socket");
                exit(1);
        }
        printf("[+]Server socket created successfully.\n");

        //type algo
        len = sizeof(algo);
        if (getsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, algo, &len) != 0)
        {
                perror("getsockopt");
                return -1;
        }
        printf("Current: %s\n", algo);



        server_addr.sin_family = AF_INET;
        server_addr.sin_port = port;
        server_addr.sin_addr.s_addr = inet_addr(ip);
        // connect to server
        con = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
        if(con == -1) {
                perror("[-]Error in socket");
                exit(1);
        }
        printf("[+]Connected to Server.\n");

        fp = fopen(filename, "r");
        if (fp == NULL) {
          perror("[-]Error in reading file.");
          exit(1);
        }

        t = clock();

        for(int i=1; i<=5; i++) {
                send_file(fp, sockfd);
                printf("[+]File %d data sent successfully.\n",i);
        }
        t = clock() - t;
        double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
        printf("send file took %f seconds to execute \n", time_taken);

        strcpy(algo, "reno");
        len = strlen(algo);
        //set new
        if (setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, algo, len) != 0)
        {
                perror("setsockopt");
                return -1;
        }
        printf("New: %s\n", algo);

        t = clock();
        
        for(int i=1; i<=5; i++) {
                send_file(fp, sockfd);
                printf("[+]File %d data sent successfully.\n",i);
        }
        t = clock() - t;
        time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
        printf("send file took %f seconds to execute \n", time_taken);
        printf("[+]Closing the connection.\n");
        close(sockfd);

        return 0;
}
