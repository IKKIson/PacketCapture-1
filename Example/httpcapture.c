#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#define TRUE    1
#define FALSE   0

// 에러 메시지 출력 후 프로그램을 종료하는 함수
void Error(const char *, ...);
// 네트워크 디바이스를 promiscous 모드로 변경하는 함수
int SetPromiscMode(int);
// dumpcode by ohara
void dumpcode(unsigned char *buff, int len);

int main(int argc, char *argv[])
{
        int SniffSock, Len;
        char RecvPacket[1500];

        struct tcphdr *TCPHeader;
        struct iphdr *IPHeader;
        struct in_addr SrcAddr, DstAddr;

	// SOCK_PACKET 타입의 소켓 디스크립터 생성
        if((SniffSock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1)
                Error("making socket error\n");

	// 네트워크 디바이스를 promiscous 모드로 변경
        if(!SetPromiscMode(SniffSock))
                Error("set promiscous mode error\n");

	// IP와 TCP 헤더의 시작 포인터를 얻음
        IPHeader = (struct iphdr *)(RecvPacket+14);
        TCPHeader = (struct tcphdr *)(RecvPacket+14+20);

        while(TRUE){
		// 소켓 디스크립터를 통해 패킷을 받아옴
                if((Len = read(SniffSock, RecvPacket, 1500)) > 0){
                        SrcAddr.s_addr = IPHeader->saddr;
                        DstAddr.s_addr = IPHeader->daddr;

			// 송신자, 수신자 정보 출력
                        printf("%s:%d -> ", inet_ntoa(SrcAddr), ntohs(TCPHeader->source));
                        printf("%s:%d\n", inet_ntoa(DstAddr), ntohs(TCPHeader->dest));
                        
			// 패킷 내용 출력
                        dumpcode(RecvPacket+14+20+20, Len-14-20-20);
			printf("\n");
                }

        }

        close(SniffSock);
        return 0;
}

//에러처리
void Error(const char *szMsg, ...)
{
        va_list vl;
        char szOutput[1024];

        va_start(vl, szMsg);
        vsprintf(szOutput, szMsg, vl);
        va_end(vl);

        fprintf(stderr, szOutput);
        exit(-1);
}

//소스코드 내에서 모드 전환
int SetPromiscMode(int Sockfd)
{
        struct ifreq IfInfo;

        strcpy(IfInfo.ifr_ifrn.ifrn_name, "eth0");
        if(ioctl(Sockfd, SIOCGIFFLAGS, &IfInfo) < 0)
                return FALSE;

        IfInfo.ifr_ifru.ifru_flags ^= IFF_PROMISC;
        if(ioctl(Sockfd, SIOCSIFFLAGS, &IfInfo) < 0)
                return FALSE;

        return TRUE;
}

//페이로드값 출력
void printchar(unsigned char c)
{
        if(isprint(c))
                printf("%c",c);
        else
                printf(".");
}

//16진수 별로 출력(2종류)
void dumpcode(unsigned char *buff, int len)
{
        int i;
        for(i=0;i<len;i++)
        {
                if(i%16==0)
                        printf("0x%04x  ", i);
                printf("%02x ",buff[i]);
                if(i%16-15==0)
                {
                        int j;
                        printf("  ");
                        for(j=i-15;j<=i;j++)
                                printchar(buff[j]);
                        printf("\n");
                }
        }
        if(i%16!=0)
        {
                int j;
                int spaces=(len-i+16-i%16)*3+2;
                for(j=0;j<spaces;j++)
                        printf(" ");
                for(j=i-i%16;j<len;j++)
                        printchar(buff[j]);
        }
        printf("\n");
}