#include "stdhdr.h"

static int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;

//TODO: 삭제할지 고려.
void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            //PrintIcmpPacket(buffer,size);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            //PrintTcpPacket(buffer , size);
			printf("start ProcessPacket()PrintCaptureForm\n");
			fprintf(logfile,"start ProcessPacket()PrintCaptureForm\n");
			PrintFtpPacketCmd(buffer,size);
			PrintFtpPacket(buffer,size);
            break;
         
		case 17: //UDP Protocol
            ++udp;
            PrintUdpPacket(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
}

// ETC function
void PrintMain(){
	printf("------------------------\n");
	printf("PacketCapture Program\n");
	printf("------------------------\n");
	printf("q : exit program\b");
	printf("t : tcp capture\n");
	printf("u : udp capture\n");
	printf("f : ftp capture\n");
	printf("h : http capture\n");
	printf("i : ip capture\n");
	printf("d : data capture\n");
	printf("m : trans tcp packet Test\n");
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

void PrintHelp(){
	printf("m 누르고 패킷 전송해봅세. 그 후에 t 누른 후 패킷 보면 됨.\n");
}


int PrintCaptureForm(unsigned char *buffer, int data_size, int flag){

	//TODO: 자식 프로세스로 따로 출력할지 고려해봐야 함. 실시간으로 출력하면서 케맨드 입력이 가능하게 만들어야 함.
	char choice;
	int updateCount=0;
	int logFtp;
	int logHttp;
	int logDns;
	int logTelnet;

	//file open
	if(flag == FORM_FTP){ // FTP FILE OPEN
		logFtp = fopen("logFtp.txt","w");
		if(logFtp == -1){
			printf("FTP file open error\n");
			return FORM_ERROR;
		}
	} else if(flag == FORM_HTTP){// HTTP FILE OPEN
		logHttp = fopen("logHttp.txt","w");
		if(logHttp == -1){
			printf("HTTP file open error\n");
			return FORM_ERROR;
		}
	} else if(flag == FORM_DNS){ // DNS FILE OPEN
		logDns = fopen("logDns.txt","w");
		if(logDns == -1){
			printf("DNS file open error\n");
			return FORM_ERROR;
		}
	} else if(flag == FORM_TELNET){ // TELNET FILE OPEN
		logTelnet = fopen("logTelnet.txt","w");
		if(logTelnet == -1){
			printf("TELENT file open error\n");
			return FORM_ERROR;
		}
	}

	choice = fgetc(stdin);
	//ClearReadBuffer();
	while(choice != 'q') {
		system("clear");
		printf("press any key, then update.\nq : quit\n");
		printf("%d times update\n",updateCount);
		if(choice == 'q')
			break;
		switch(flag) {
			case FORM_TCP:
				PrintTcpPacketCmd(buffer,data_size);
				break;
			case FORM_UDP:
				PrintUdpPacketCmd(buffer,data_size);
				break;
			case FORM_ICMP:
				PrintIcmpPacketCmd(buffer,data_size);
				break;
			case FORM_FTP:
				printf("start FORM_FTP in PrintCaptureForm\n");
				PrintFtpPacketCmd(buffer,data_size);
				PrintFtpPacket(buffer,data_size);
				break;
			case FORM_HTTP:
				PrintHttpPacketCmd(buffer,data_size);
				break;
			case FORM_IP:
				PrintIpHeaderCmd(buffer,data_size);
				break;
			case FORM_DATA:
				PrintDataCmd(buffer,data_size);
				break;

		default:
				return FORM_ERROR;
			break;
		}

		updateCount++;
		choice = fgetc(stdin);
	}

	
	//file close
	if(flag == FORM_FTP){ //FTP close file
		close(logFtp);
	} else if (flag == FORM_HTTP){ //HTTP close file
		close(logHttp);
	} else if (flag == FORM_DNS){ //DNS close file
		close(logDns);
	} else if (flag == FORM_TELNET){ //TELNET close file
		close(logTelnet);
	}




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

//Icmp function 
//TODO: Icmp 구현해야되나 고려
void PrintIcmpPacket(unsigned char *buffer, int size){
}
void PrintIcmpPacketCmd(unsigned char* buffer , int size){
}

void WriteIcmpPacketFile(unsigned char *buffer, int size){

    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen);
             
    fprintf(logfile,"\n\n***********************ICMP Packet*************************\n");   
     
    PrintIpHeader(buffer , size);
             
    fprintf(logfile,"\n");
         
    fprintf(logfile,"ICMP Header\n");
    fprintf(logfile,"   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11) 
        fprintf(logfile,"  (TTL Expired)\n");
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) 
        fprintf(logfile,"  (ICMP Echo Reply)\n");
    fprintf(logfile,"   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile,"   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile,"   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile,"\n");
 
    fprintf(logfile,"IP Header\n");
    PrintData(buffer,iphdrlen);
         
    fprintf(logfile,"UDP Header\n");
    PrintData(buffer + iphdrlen , sizeof icmph);
         
    fprintf(logfile,"Data Payload\n");  
    PrintData(buffer + iphdrlen + sizeof icmph , (size - sizeof icmph - iph->ihl * 4));
    fprintf(logfile,"\n###########################################################");
     
}
//TODO : 구현해야 함.
//Ftp function
///////////////////////////////************/////////////////
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
	fprintf(logfile,"PrintFtpPacket() function start \n");
	

    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
	
	fprintf(logfile,"buffer : %s , size : %d\n", buffer, size);
    fprintf(logfile,"FTP Data Payload\n");  
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

	fprintf(logfile,"==================start=================\n");
	fprintf(logfile,"PrintFtpDataCmd() function start\n");
	for(i=0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			//fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
				 
				else fprintf(logfile,""); //otherwise print a dot
			}
			//fprintf(logfile,"\n");
		} 
		 
		if(i%16==0) fprintf(logfile,"");
			//fprintf(logfile," %02X",(unsigned int)data[i]);
				 
		if( i==size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfile,""); //extra spaces
			 
			fprintf(logfile,"+++++++++");
			 
			for (j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
				else fprintf(logfile,"");
			}
			fprintf(logfile,"\n");
		}
	}
	fprintf(logfile,"=============================end============\n");
}

//////////////////////**********//////////////////////////////
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

