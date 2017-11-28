#include <stdio.h> //For standard things
#include <stdlib.h>    //malloc
#include <string.h>    //memset

#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header


#include <sys/socket.h>
#include <arpa/inet.h>
#include  <unistd.h>
#include  <netinet/in.h>
#include  <sys/ioctl.h> 
#include  <sys/types.h>

//Define
#define MAX_BUFFER_SIZE 65536


//함수
void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);//log.txt파일로 출력함. 
void print_tcp_packet(unsigned char* , int);//log.txt파일로 출력함
void print_tcp_packet_cmd(unsigned char*, int);//cmd창에 출력
void print_udp_packet(unsigned char * , int);//log.txt파일로 출력함
void print_icmp_packet(unsigned char* , int);//log.txt파일로 출력함
void PrintData (unsigned char* , int);//log.txt파일로 출
void PrintDataCmd (unsigned char* , int);//cmd창에 출력
void print_icmp_packet_cmd(unsigned char *Buffer, int Size);
void PrintHelp();
void PrintMain();
//void ClearReadBuffer();//버퍼 없애기.

//전역변수
FILE *logfile;
int sock_raw;
