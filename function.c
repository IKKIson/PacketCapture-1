#include "stdhdr.h"



int PrintCaptureForm(int flag){

	char choice;

    int saddr_size , data_size; //socket address size, data size
    struct sockaddr saddr; //소켓 주소를 표현하는 구조체 saddr변수 선언
    struct in_addr in; //IPv4 인터넷 주소관련 구조체 변수 선un
    unsigned char *buffer = (unsigned char *)malloc(MAX_BUFFER_SIZE); //MAX_BUFFER_SIE만큼의 크기를 가진 unsigned char형 buffer 포인터를 할당

    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;


	//file open
	OpenFile(); //open .txt file

	//raw socket을 만듬 
	//IPv4인터넷 프로토콜, raw socket으로, TCP프로토콜이 사용됨.
	if(flag == FORM_HTTP || flag == FORM_TELNET || flag == FORM_FTP ){// if tcp protocol
		sock_raw_tcp = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
		if(sock_raw_tcp < 0){ //raw_socket 오류 처리
		 printf("TCP Socket Error\n");
		 return FORM_ERROR;
		}
	} else if(flag == FORM_DNS){ //if udp protocol
		sock_raw_udp = socket(AF_INET, SOCK_RAW , IPPROTO_UDP);
		if(sock_raw_udp < 0){
			printf("UDP Socket Error\n");
			return FORM_ERROR;
		}
	} else {
		printf("PrintCaptureFrom() flag error\n");
		return FORM_ERROR;
	}


	saddr_size = sizeof(saddr);//input socket struct size in saddr_size
	printf("saddr_size : %d",saddr_size);//TODO : Can I Delete????

    //Receive a packet
    data_size = recvfrom(sock_raw_tcp , buffer , MAX_BUFFER_SIZE , 0 , &saddr , &saddr_size);
    if(data_size < 0 ){ //occure recvfrom error
        printf("PrintCaptureForm() Recvfrom error , failed to get packets\n");
        return FORM_ERROR;
	}

    switch (iph->protocol){ //Check the Protocol and do accordingly...
        case 6:  //TCP Protocol
			if(flag == FORM_FTP){
///////////////////dev : Jang /////////////////////
			    //PrintTcpPacket(buffer , saddr_size);
				//iprintf("start ProcessPacket()PrintCaptureForm\n");
				//fprintf(logFtp,"start ProcessPacket()PrintCaptureForm\n");
				PrintFtpPacketCmd(buffer,saddr_size);
				PrintFtpPacket(buffer,saddr_size);
///////////////////end : Jang /////////////////////
				++ftp;
			} else if(flag == FORM_HTTP){



				++http;
			} else if(flag == FORM_TELNET){

				++telnet;
			}
			++tcp;
            break;
         
		case 17: //UDP Protocol
			if(flag == FORM_DNS){
				PrintUdpPacket(buffer , saddr_size);
			}
			++dns;
			++udp;
            break;
        default: //Some Other Protocol like ARP etc.
            ++others;
			break;
	}

	choice = fgetc(stdin);
	printf("TCP : %d   UDP : %d   HTTP : %d   FTP : %d   TELNET : %d   DNS : %d   Others : %d   Total : %d\n",tcp, udp, http, ftp, telnet, dns, others, total);


	CloseFile(); //close .txt file

	if(flag == FORM_DNS){// UDP
		close(sock_raw_udp); //close udp raw socket
	} else if(flag == FORM_HTTP || flag == FORM_FTP || flag == FORM_TELNET) { //TCP
		close(sock_raw_tcp); //close tcp raw socket
	} else { // 
		printf("PrintCaptureForm() close() error\n");
		return FORM_ERROR;
	}
	system("clear");//화면 지움
	return 0;
}



//IP function
void PrintIpHeader(unsigned char* buffer, int size){

    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}
void PrintIpHeaderCmd(unsigned char* buffer, int size){
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",ntohs(iph->id));
    //printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph->check));
    printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

//Tcp function
void PrintTcpPacket(unsigned char* buffer, int size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
             
    fprintf(logfile,"\n\n***********************TCP Packet*************************\n");    
         
    PrintIpHeader(buffer,size);
         
    fprintf(logfile,"\n");
    fprintf(logfile,"TCP Header\n");
    fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile,"\n");
    fprintf(logfile,"                        DATA Dump                         ");
    fprintf(logfile,"\n");
         
    fprintf(logfile,"IP Header\n");
    PrintData(buffer,iphdrlen);
         
    fprintf(logfile,"TCP Header\n");
    PrintData(buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile,"I WANNA Data Payload\n");  
    PrintData(buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4) );
                         
    fprintf(logfile,"\n###########################################################");
}
void PrintTcpPacketCmd(unsigned char* buffer, int size){
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);

    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("\n");
    printf("                        DATA Dump                         ");
    printf("\n");
         
    printf("IP Header\n");
    PrintDataCmd(buffer,iphdrlen);
         
    printf("TCP Header\n");
    PrintDataCmd(buffer+iphdrlen,tcph->doff*4);
         
    printf("Data Payload\n");  
    PrintDataCmd(buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4) );
                         
    printf("\n###########################################################");
}
 
//Udp function
void PrintUdpPacket(unsigned char *buffer , int size)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen);
     
    fprintf(logfile,"\n\n***********************UDP Packet*************************\n");
     
    PrintIpHeader(buffer,size);           
     
    fprintf(logfile,"\nUDP Header\n");
    fprintf(logfile,"   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    PrintData(buffer , iphdrlen);
         
    fprintf(logfile,"UDP Header\n");
    PrintData(buffer+iphdrlen , sizeof udph);
         
    fprintf(logfile,"Data Payload\n");  
    PrintData(buffer + iphdrlen + sizeof udph ,( size - sizeof udph - iph->ihl * 4 ));
     
    fprintf(logfile,"\n###########################################################");
}
void PrintUdpPacketCmd(unsigned char *buffer , int size){
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen);
     
    printf("\n\n***********************UDP Packet*************************\n");
     
    PrintIpHeader(buffer,size);           
     
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    printf("\n");
    printf("IP Header\n");
    PrintData(buffer , iphdrlen);
         
    printf("UDP Header\n");
    PrintData(buffer+iphdrlen , sizeof udph);
         
    printf("Data Payload\n");  
    PrintData(buffer + iphdrlen + sizeof udph ,( size - sizeof udph - iph->ihl * 4 ));
     
    printf("\n###########################################################");
}


//////////////// Dev : Jang ////////////////
//TODO : 구현해야 함.
//Ftp function
/* ftp */
void PrintFtpPacketCmd(unsigned char*buffer, int size){
	printf("PrintFtpPacketCmd() function start\n");
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)buffer;
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
	

	printf("buffer : %s , size : %d\n", buffer, size);
	printf("\n");
	PrintDataCmd(buffer,size);

	//Data Payload//
	printf("FTP Data Payload\n");
	PrintFtpDataCmd(buffer + iphdrlen + tcph->doff*4, (size - tcph->doff*4-iph->ihl*4) );
}

void PrintFtpPacket(unsigned char* buffer, int size){
	fprintf(logFtp,"PrintFtpPacket() function start \n");
	

    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
	
	fprintf(logFtp,"buffer : %s , size : %d\n", buffer, size);
    fprintf(logFtp,"FTP Data Payload\n");  
    PrintFtpData(buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4));

}

void PrintFtpDataCmd(unsigned char* data, int size){

	printf("PrintFtpDataCmd() function start\n");
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else 
					printf(" ");
					printf("."); //otherwise print a dot

            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra spaces
             
            printf("         ");
             
            for (j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}

void PrintFtpData(unsigned char* data, int size){

	fprintf(logFtp,"==================start=================\n");
	fprintf(logFtp,"PrintFtpDataCmd() function start\n");
	for(i=0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			//fprintf(logFtp,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logFtp,"%c",(unsigned char)data[j]); //if its a number or alphabet
				 
				else fprintf(logFtp," "); //otherwise print a dot
			}
			//fprintf(logFtp,"\n");
		} 
		 
		if(i%16==0) fprintf(logFtp," ");
			//fprintf(logFtp," %02X",(unsigned int)data[i]);
				 
		if( i==size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logFtp," "); //extra spaces
			 
			fprintf(logFtp,"+++++++++");
			 
			for (j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logFtp,"%c",(unsigned char)data[j]);
				else fprintf(logFtp," ");
			}
			fprintf(logFtp,"\n");
		}
	}
	fprintf(logFtp,"=============================end============\n");
}

////////////////////// End : Jang /////////////////////////////


//Http function
void PrintHttpPacketCmd(unsigned char* buffer, int size){
	
}
void PrintHttpPacket(unsigned char* buffer, int size){
}

//Data function
void PrintData (unsigned char* data , int size)
{
     
	fprintf(logfile,"PrintData() start \n");
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        } 
         
        if(i%16==0) fprintf(logfile,"   ");
            fprintf(logfile," %02X",(unsigned int)data[i]);
                 
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
             
            fprintf(logfile,"         ");
             
            for (j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}
void PrintDataCmd (unsigned char* data , int size)
{
	printf("data : %s and size: %d\n",data, size);
     
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra spaces
             
            printf("         ");
             
            for (j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
}

//////////////////////// e t c  function////////////////////////
void OpenFile(){
    //file open
    logfile=fopen("log.txt","w"); //log.txt파일을 write로 연다.
    if(logfile==NULL) //파일 열기 오류시 
		printf("Unable to create file."); //오류 메시지 출력

	logFtp = fopen("logFtp.txt","w");
	if(logFtp == NULL)
		printf("FTP file open error\n");

	logHttp = fopen("logHttp.txt","w");
	if(logHttp == NULL)
		printf("HTTP file open error\n");

	logDns = fopen("logDns.txt","w");
	if(logDns == NULL)
		printf("DNS file open error\n");

	logTelnet = fopen("logTelnet.txt","w");
	if(logTelnet == NULL)
		printf("TELENT file open error\n");
}

void CloseFile(){
	//file close
//	close(logFtp);
//	close(logHttp);
//	close(logDns);
//	close(logTelnet);
//	close(logfile);
}

void PrintHelp(){
	printf("m 누르고 패킷 전송해봅세. 그 후에 t 누른 후 패킷 보면 됨.\n");
}

// ETC function
void PrintMain(){
	printf("------------------------\n");
	printf("PacketCapture Program\n");
	printf("------------------------\n");
	printf("q : exit program\b");
	printf("f : FTP capture\n");
	printf("h : HTTP capture\n");
	printf("t : TELNET capture\n");
	printf("d : DNS capture\n");
	printf("? : help\n");
	printf("------------------------\n");
	printf("option : ");

}

//버퍼 없애기
//void ClearReadBuffer(){
//	if(stdin->_cnt){
//		while(getchar() != '\n');
//	}
//}

