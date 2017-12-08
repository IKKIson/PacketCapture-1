#include "stdhdr.h"



int PrintCaptureForm(int flag){

	pid_t pid;

	int fd[2];
	char buf[255];
	int len, status;
	int pipeFlag = 1;



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
	printf("staring... if you don't want to packet capture anymore then you have to press key 'q' and enter \n");

	switch(pid = fork()){
		case -1://error
			perror("fock error");
			exit(1);
			CloseFile();
			break;
		case 0://child process
			while(1){
				saddr_size = sizeof saddr;//input socket struct size in saddr_size
			    //Receive a packet
			    data_size = recvfrom(sock_raw_tcp , buffer , MAX_BUFFER_SIZE , 0 , &saddr , &saddr_size);
			    if(data_size < 0 ){ //occure recvfrom error
			        printf("PrintCaptureForm() Recvfrom error , failed to get packets\n");
			        return FORM_ERROR;
				}
				iph = (struct iphdr*)buffer;
		
				//TODO: You Can add code in switch
			    switch (iph->protocol){ //Check the Protocol and do accordingly...
			        case 6:  //TCP Protocol
						++tcp;
						if(flag == FORM_FTP){
							++ftp;
			///////////////////dev : Jang /////////////////////
							
							PrintIpHeader(buffer,data_size,logFtp);
							printf("\n");
							fprintf(logFtp,"\n");
							PrintFtpPacket(buffer,data_size, logFtp);
		
							
			///////////////////end : Jang ////////////////////
							printf("ftp : %d\n",ftp);
							fprintf(logFtp,"ftp : %d\n",ftp);
						} else if(flag == FORM_HTTP){
			
							++http;
						} else if(flag == FORM_TELNET){
			
							++telnet;
						}
			            break;
			         
					case 17: //UDP Protocol
						if(flag == FORM_DNS){
							PrintUdpPacket(buffer , data_size, logDns);
						}
						++dns;
						++udp;
			            break;
			        default: //Some Other Protocol like ARP etc.
			            ++others;
						break;
				}
			}

			break;
		default ://parent process
			{
				char choice;
				while(1){
					choice = fgetc(stdin);
					if(choice == 'q'){
						if((kill(pid, SIGKILL)) < 0){ //kill child process
							printf("-back-\n");
							sleep(1);
						}else {
							printf("-back-\n");
							sleep(1);
						}
						break;
						}
					
				}
			}
			break;
	}

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
void PrintIpHeader(unsigned char* buffer, int size, FILE *logfile){

    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf("\n");
    fprintf(logfile,"\n");

    printf("IP Header\n");
    fprintf(logfile,"IP Header\n");

    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);

    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);

    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);

    printf("   |-IP Total Length   : %d  Bytes(size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(size of Packet)\n",ntohs(iph->tot_len));

    printf("   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));

    //printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);

    //printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);

    //printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    //fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);

    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);

    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);

    printf("   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));

    printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));

    printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

}

//Tcp function
void PrintTcpPacket(unsigned char* buffer, int size, FILE *logfile)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
             
    fprintf(logfile,"\n\n***********************TCP Packet*************************\n");    
    printf("\n\n***********************TCP Packet*************************\n");    
         
         
    PrintIpHeader(buffer,size, logfile);
         
    fprintf(logfile,"\n");
    printf("\n");

    fprintf(logfile,"TCP Header\n");
    printf("TCP Header\n");

    fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));

    fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));

    fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));

    fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));

    fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);

    //fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);

    //fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    //printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);

    fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);

    fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);

    fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);

    fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);

    fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);

    fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);

    fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window));
    printf("   |-Window         : %d\n",ntohs(tcph->window));

    fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
    printf("   |-Checksum       : %d\n",ntohs(tcph->check));

    fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);

    fprintf(logfile,"\n");
    printf("\n");

    fprintf(logfile,"                        DATA Dump                         ");
    printf("                        DATA Dump                         ");

    fprintf(logfile,"\n");
    printf("\n");
         
    fprintf(logfile,"IP Header\n");
    printf("IP Header\n");

    PrintData(buffer,iphdrlen, logfile);
         
    fprintf(logfile,"TCP Header\n");
    printf("TCP Header\n");

    PrintData(buffer+iphdrlen,tcph->doff*4, logfile);
         
    fprintf(logfile,"I WANNA Data Payload\n");  
    printf("I WANNA Data Payload\n");  

    PrintData(buffer + iphdrlen + tcph->doff*4 , (size - tcph->doff*4-iph->ihl*4), logfile);
                         
    fprintf(logfile,"\n###########################################################\n");
    printf("\n###########################################################\n");
}
 
//Udp function
void PrintUdpPacket(unsigned char *buffer , int size, FILE *logfile)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)buffer;
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen);
     
    fprintf(logfile,"\n\n***********************UDP Packet*************************\n");
    printf("\n\n***********************UDP Packet*************************\n");
     
    PrintIpHeader(buffer,size, logfile);           
     
    fprintf(logfile,"\nUDP Header\n");
    printf("\nUDP Header\n");

    fprintf(logfile,"   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));

    fprintf(logfile,"   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));

    fprintf(logfile,"   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));

    fprintf(logfile,"   |-UDP Checksum     : %d\n" , ntohs(udph->check));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile,"\n");
    printf("\n");

    fprintf(logfile,"IP Header\n");
    printf("IP Header\n");

    PrintData(buffer , iphdrlen, logfile);
         
    fprintf(logfile,"UDP Header\n");
    printf("UDP Header\n");

    PrintData(buffer+iphdrlen , sizeof udph, logfile);
         
    fprintf(logfile,"Data Payload\n");  
    printf("Data Payload\n");  

    PrintData(buffer + iphdrlen + sizeof udph ,( size - sizeof udph - iph->ihl * 4 ), logfile);
     
    fprintf(logfile,"\n###########################################################");
    printf("\n###########################################################");
}

//////////////// Dev : Jang ////////////////
//TODO : 구현해야 함.
//Ftp function
/* ftp */
void PrintFtpPacket(unsigned char*buffer, int size, FILE *logfile){

	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr *)buffer;
	iphdrlen = iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);

    fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
    printf("   |-Source Port      : %u\n",ntohs(tcph->source));

    fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    printf("   |-Destination Port : %u\n",ntohs(tcph->dest));

	//Data Payload//
	printf("FTP Data Payload\n");
    fprintf(logfile,"FTP Data Payload\n");  

	PrintFtpData(buffer + iphdrlen + tcph->doff*4, (size - tcph->doff*4-iph->ihl*4), logfile );
	

	printf("---------------------\n");
	fprintf(logfile,"---------------------\n");
}


void PrintFtpData(unsigned char* data, int size, FILE *logfile){

	int flag =0;
     
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
//            fprintf(logfile,"         ");
//            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128){
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
					flag= 1;
				}

                 
                else {
//					fprintf(logfile,"."); //otherwise print a dot
//					printf("."); //otherwise print a dot
				}
            }
			if(flag == 1) {
				printf("\n");
				fprintf(logfile,"\n");
				flag = 0;
			}
//            fprintf(logfile,"\n");
//            printf("\n");
        } 
         
        if(i%16==0) {
//			fprintf(logfile,"   ");
//			printf("   ");
		}
		//edd
		if((unsigned int)data[i] != 0){
	        fprintf(logfile," %02X",(unsigned int)data[i]);
	        printf(" %02X",(unsigned int)data[i]);
		}
                 
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) {
//				fprintf(logfile,"   "); //extra spaces
//				printf("   "); //extra spaces
			}
             
//            fprintf(logfile,"         ");
//            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) {
					fprintf(logfile,"%c",(unsigned char)data[j]);
					printf("%c",(unsigned char)data[j]);
					printf("\n");
				}
                else {
//					fprintf(logfile,".");
//					printf(".");
				}
            }
            fprintf(logfile,"\n");
            printf("\n");
        }
    }
}
////////////////////// End : Jang /////////////////////////////


//Http function
void PrintHttpPacket(unsigned char* buffer, int size, FILE *logfile){
}

//Data function
void PrintData (unsigned char* data , int size, FILE *logfile)
{
     
	fprintf(logfile,"PrintData() start \n");
	printf("PrintData() start \n");
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128){
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
				} 
                else {
					fprintf(logfile,"."); //otherwise print a dot
					printf("."); //otherwise print a dot
				}            }
            fprintf(logfile,"\n");
            printf("\n");
        } 
         
        if(i%16==0) {
			fprintf(logfile,"   ");
			printf("   ");
		}
                 
        fprintf(logfile," %02X",(unsigned int)data[i]);
        printf(" %02X",(unsigned int)data[i]);

        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++){
				fprintf(logfile,"   "); //extra spaces
				printf("   "); //extra spaces
			}
             
            fprintf(logfile,"         ");
            printf("         ");
             
            for (j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) {
					fprintf(logfile,"%c",(unsigned char)data[j]);
					printf("%c",(unsigned char)data[j]);
				}
                else {
					fprintf(logfile,".");
					printf(".");

				}
				            }
            fprintf(logfile,"\n");
            printf("\n");
        }
    }
}

//////////////////////// e t c  function////////////////////////
void OpenFile(){
	

    //file open
	logFtp = fopen("logFtp.txt","w");
	if(logFtp == NULL){
		printf("FTP file open error\n");
		exit(1);
	}

	logHttp = fopen("logHttp.txt","w");
	if(logHttp == NULL){
		printf("HTTP file open error\n");
		exit(1);
	}

	logDns = fopen("logDns.txt","w");
	if(logDns == NULL){
		printf("DNS file open error\n");
		exit(1);
	}

	logTelnet = fopen("logTelnet.txt","w");
	if(logTelnet == NULL){
		printf("TELENT file open error\n");
		exit(1);
	}
}

void CloseFile(){
	//file close
	fclose(logFtp);
	fclose(logHttp);
	fclose(logDns);
	fclose(logTelnet);
}

void PrintHelp(){
	printf("m 누르고 패킷 전송해봅세. 그 후에 t 누른 후 패킷 보면 됨.\n");
}

// ETC function
void PrintMain(){
	printf("------------------------\n");
	printf("PacketCapture Program\n");
	printf("------------------------\n");
	printf("q : exit program\n");
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

