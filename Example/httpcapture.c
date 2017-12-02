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

// ���� �޽��� ��� �� ���α׷��� �����ϴ� �Լ�
void Error(const char *, ...);
// ��Ʈ��ũ ����̽��� promiscous ���� �����ϴ� �Լ�
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

	// SOCK_PACKET Ÿ���� ���� ��ũ���� ����
        if((SniffSock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1)
                Error("making socket error\n");

	// ��Ʈ��ũ ����̽��� promiscous ���� ����
        if(!SetPromiscMode(SniffSock))
                Error("set promiscous mode error\n");

	// IP�� TCP ����� ���� �����͸� ����
        IPHeader = (struct iphdr *)(RecvPacket+14);
        TCPHeader = (struct tcphdr *)(RecvPacket+14+20);

        while(TRUE){
		// ���� ��ũ���͸� ���� ��Ŷ�� �޾ƿ�
                if((Len = read(SniffSock, RecvPacket, 1500)) > 0){
                        SrcAddr.s_addr = IPHeader->saddr;
                        DstAddr.s_addr = IPHeader->daddr;

			// �۽���, ������ ���� ���
                        printf("%s:%d -> ", inet_ntoa(SrcAddr), ntohs(TCPHeader->source));
                        printf("%s:%d\n", inet_ntoa(DstAddr), ntohs(TCPHeader->dest));
                        
			// ��Ŷ ���� ���
                        dumpcode(RecvPacket+14+20+20, Len-14-20-20);
			printf("\n");
                }

        }

        close(SniffSock);
        return 0;
}

//����ó��
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

//�ҽ��ڵ� ������ ��� ��ȯ
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

//���̷ε尪 ���
void printchar(unsigned char c)
{
        if(isprint(c))
                printf("%c",c);
        else
                printf(".");
}

//16���� ���� ���(2����)
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