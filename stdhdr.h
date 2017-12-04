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

//PrintCaptureForm()함수의 flag값
#define FORM_TCP 1
#define FORM_UDP 2
#define FORM_FTP 3
#define FORM_HTTP 4
#define FORM_IGMP 5  //todo: 지우는거 결정
#define FORM_ICMP 6 //todo: 지우는거 결정
#define FORM_IP 7
#define FORM_DATA 8
#define FORM_TELNET 9
#define FORM_DNS 10
#define FORM_ERROR -1



//함수

//TODO: ProcessPacket 지울지 고려
void ProcessPacket(unsigned char* , int);

void PrintIpHeader(unsigned char* , int);//log.txt파일로 출력함. 
void PrintIpHeaderCmd(unsigned char *, int);//cmd창에 출력

void PrintTcpPacket(unsigned char* , int);//log.txt파일로 출력함
void PrintTcpPacketCmd(unsigned char*, int);//cmd창에 출력

void PrintUdpPacket(unsigned char * , int);//log.txt파일로 출력함
void PrintUdpPacketCmd(unsigned char *, int);//cmd창에 출력

void PrintIcmpPacket(unsigned char* , int);//log.txt파일로 출력함
void PrintIcmpPacketCmd(unsigned char *, int);//cmd창에 출력

void PrintData (unsigned char* , int);//log.txt파일로 출력
void PrintDataCmd (unsigned char* , int);//cmd창에 출력

void PrintFtpPacketCmd(unsigned char*, int);//log.txt파일로 출력
void PrintFtpPacket(unsigned char*, int);//cmd창에 출력

void PrintHttpPacketCmd(unsigned char*, int);//log.txt파일로 출력
void PrintHttpPacket(unsigned char*, int);//cmd창에 출력

void PrintHelp();//도움말출력 함수
void PrintMain();//메인문 출력
//void ClearReadBuffer();//버퍼 없애기.

int PrintCaptureForm(unsigned char*, int, int); //cmd 창에 출력하기 위한 폼


//전역변수
FILE *logfile;
int sock_raw;
