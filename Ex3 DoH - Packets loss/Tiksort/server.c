#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#define SIZE 1024
//write to file
void write_file(int sockfd){
        int n;
        FILE *fp;
        char *filename = "recv.txt";
        char buffer[SIZE];

        fp = fopen(filename, "w");
        while (1) {
                n = recv(sockfd, buffer, SIZE, 0);
                if (n <= 0) {
                        break;
                        return;
                }
                fprintf(fp, "%s", buffer);
                bzero(buffer, SIZE);
        }
        return;
}


int main(){
        char *ip = "127.0.0.1";
        int port = 8080;
        int con;

        int sockfd, new_sock;
        struct sockaddr_in server_addr, new_addr;
        socklen_t addr_size;
        char buffer[SIZE];
        //time
        clock_t t;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0) {
                perror("[-]Error in socket");
                exit(1);
        }
        printf("[+]Server socket created successfully.\n");

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = port;
        server_addr.sin_addr.s_addr = inet_addr(ip);

        con = bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
        if(con < 0) {
                perror("[-]Error in bind");
                exit(1);
        }
        printf("[+]Binding successfull.\n");
        for(int i=1; i<=5; i++) {
                t = clock();
                if(listen(sockfd, 10) == 0) {
                        printf("[+]Listening....\n");
                }else{
                        perror("[-]Error in listening");
                        exit(1);
                }

                addr_size = sizeof(new_addr);
                new_sock = accept(sockfd, (struct sockaddr*)&new_addr, &addr_size);
                write_file(new_sock);

                t = clock() - t;
                double time_taken = ((double)t)/CLOCKS_PER_SEC;   // in seconds
                printf("Write file took %f seconds to accept \n", time_taken);

        }
        printf("[+]Data written in the file successfully.\n");
        return 0;
}
