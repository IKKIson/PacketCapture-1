#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "stdhdr.h"
//#include "main.h"
#include <net/ethernet.h>

FILE *fp;
   
void fatal(char *message) {
   char error_message[100];

   strcpy(error_message, "[!!] Fatal Error ");
   strncat(error_message, message, 83);
   perror(error_message);
   exit(-1);
}
void dump(const unsigned char *data_buffer, const unsigned int length) {
   unsigned char byte;
   unsigned int i, j;
   for(i=0; i < length; i++) {
      byte = data_buffer[i];
      printf("%02x ", data_buffer[i]);  // display byte in hex
      fprintf(fp,"%02x ", data_buffer[i]);  // display byte in hex
      if(((i%16)==15) || (i==length-1)) {
         for(j=0; j < 15-(i%16); j++){
            printf("   ");
            fprintf(fp,"   ");}
         printf("| "); //boundary between nuber and character
         fprintf(fp,"| ");
         for(j=(i-(i%16)); j <= i; j++) {  // display printable bytes from line
            byte = data_buffer[j];
            if((byte > 31) && (byte < 127)){ //printable data
               printf("%c", byte);
               fprintf(fp,"%c", byte);
}	
            else{//not printable data
               printf(".");
               fprintf(fp,".");
		}
         }
         printf("\n"); // end of the dump line (each line 16 bytes)
         fprintf(fp,"\n"); // end of the dump line (each line 16 bytes)
      } // end if
   } // end for
}
             
int main(void) {
   int i, recv_length, sockfd; //recv_length = total payload length/sockfd = using for socket
   struct sockaddr saddr; 
   struct sockaddr_in source;
   struct sockaddr_in destination;
   struct in_addr in;
   unsigned char *buffer=(unsigned char *)malloc(MAX_BUFFER_SIZE);
   struct ether_header *etherh;
   int packetnum=1;
   unsigned short iphdrlen;
   struct iphdr *iph;
   struct tcphdr *tcph;

   if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)//create socket
      fatal("in socket");// socket creating error //give su permission
   fp = fopen("tellog.txt","w"); //open file/ if file doesn't exist, create file
while(1){
      recv_length = recv(sockfd, buffer, 8000, 0); //receive packet from socket to buffer
   //   etherh=(struct ether_header*)buffer;
      iph = (struct iphdr*)(buffer);//ip payload
      tcph = (struct tcphdr*)(buffer+20);//tcp payload
      memset(&source, 0, sizeof(source));//initialize struct
	source.sin_addr.s_addr=iph->saddr;
      memset(&destination, 0, sizeof(destination));//initialize struct
	destination.sin_addr.s_addr=iph->daddr; 
	printf("\n-----------------------------------------------\n");
	fprintf(fp,"\n-----------------------------------------------\n");
	printf("no.%d\n",packetnum);//order of packet
	fprintf(fp,"no.%d\n",packetnum);
	packetnum++;
      printf("Source IP : %s\n",inet_ntoa(source.sin_addr));//print source IP
      fprintf(fp,"Source IP : %s\n",inet_ntoa(source.sin_addr));
      printf("Destination IP : %s\n",inet_ntoa(destination.sin_addr));//print destination IP
      fprintf(fp,"Destination IP : %s\n",inet_ntoa(destination.sin_addr));
      printf("Source PORT : %d\n", ntohs(tcph->source));//print source prot
      fprintf(fp,"Source PORT : %d\n", ntohs(tcph->source));
      printf("Destination PORT : %d\n", ntohs(tcph->dest));//print Destination port
      fprintf(fp,"Destination PORT : %d\n", ntohs(tcph->dest));
      dump(buffer+20+20, recv_length-20-20);//print telnet payload
}
close(sockfd);//close socket
fclose(fp);//close file
return 0;
}
