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

#ifndef _CaptureForm_
//PrintCaptureForm()함수의 flag값
#define FORM_FTP 1
#define FORM_HTTP 2
#define FORM_TELNET 3
#define FORM_DNS 4
#define FORM_ERROR -1
#endif


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

////////////// dev : Jang ////////////
void PrintFtpPacketCmd(unsigned char*, int);//log.txt파일로 출력
void PrintFtpPacket(unsigned char*, int);//cmd창에 출력

void PrintFtpDataCmd(unsigned char*, int); //cmd output
void PrintFtpData(unsigned char*, int); //log.txt
///////////// end : Jang /////////////

void PrintHttpPacketCmd(unsigned char*, int);//cmd 출력
void PrintHttpPacket(unsigned char*, int);//log.txt에 출력

void PrintHelp();//도움말출력 함수
void PrintMain();//메인문 출력
//void ClearReadBuffer();//버퍼 없애기.

int PrintCaptureForm(int); // --- English.. --- someone adding me


void OpenFile();//open file
void CloseFile();//close file
int GetNewPacket(int *, int *);

//전역변수
FILE *logfile;
int sock_raw_tcp;
int sock_raw_udp;
FILE *logFtp; //for FTP file
FILE *logHttp; //for HTTP file
FILE *logDns; //for DNS file
FILE *logTelnet; // TELNET file

static int http=0,ftp=0,dns=0,telnet=0,tcp=0,udp=0,others=0,total=0,i,j;
struct sockaddr_in source,dest;
