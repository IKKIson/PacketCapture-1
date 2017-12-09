#include <stdio.h> //For standard things
#include <stdlib.h>    //malloc
#include <string.h>    //memset

#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header

#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h> 
#include <sys/types.h>
#include <stdarg.h>


//Packet Capture for DataLink layer ETH_ALL_P
#include <linux/if.h>
#include <linux/if_ether.h>


//Define
#define MAX_BUFFER_SIZE 65536

#define TRUE    1
#define FALSE   0


#ifndef _CaptureForm_
//PrintCaptureForm()함수의 flag값
#define FORM_FTP 1
#define FORM_HTTP 2
#define FORM_TELNET 3
#define FORM_DNS 4
#define FORM_ERROR -1
#endif


//함수
void PrintIpHeader(unsigned char* , int, FILE *);

void PrintTcpPacket(unsigned char* , int, FILE *);

void PrintUdpPacket(unsigned char * , int, FILE *);

void PrintData (unsigned char* , int, FILE *);

////////////// dev : Jang ////////////
void PrintFtpPacket(unsigned char*, int, FILE *);//ftp packet print 
void PrintFtpData(unsigned char*, int, FILE *); //ftp data print
///////////// end : Jang /////////////

void PrintHttpPacket(unsigned char*, int, FILE *);
void PrintTelnetPacket(unsigned char*,int, FILE *);

void PrintHelp();//도움말출력 함수
void PrintMain();//메인문 출력
//void ClearReadBuffer();//버퍼 없애기.

int PrintCaptureForm(int); // --- English.. --- someone adding me

//Chang Promisc Mode in Program
int SetPromiscMode(int );

void OpenFile();//open file
void CloseFile();//close file

//전역변수
int sock_raw;
//int sock_raw_udp;
FILE *logFtp; // FTP file
FILE *logHttp; // HTTP file
FILE *logDns; // DNS file
FILE *logTelnet; // TELNET file

static int http=0,ftp=0,dns=0,telnet=0,tcp=0,udp=0,others=0,total=0,i,j;
struct sockaddr_in source,dest;
