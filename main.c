#include "stdhdr.h"
 
int main()
{
	char optionChoice; //옵션 선택 변수선언

    int saddr_size , data_size;
    struct sockaddr saddr; //소켓 주소를 표현하는 구조체 saddr변수 선언
    struct in_addr in; //IPv4 인터넷 주소관련 구조체 in변수 선
    unsigned char *buffer = (unsigned char *)malloc(MAX_BUFFER_SIZE); //MAX_BUFFER_SIE만큼의 크기를 가진 unsigned char형 buffer 포인터를 할당
	
     
    logfile=fopen("log.txt","w"); //log.txt파일을 write로 연다.
    if(logfile==NULL) //파일 열기 오류시 
		printf("Unable to create file."); //오류 메시지 출력
	
	//raw socket을 만듬 
	//IPv4인터넷 프로토콜, raw socket으로, TCP프로토콜이 사용됨.
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0) //raw_socket 오류 처리
    {
        printf("Socket Error\n");
        return 1;
    }

	system("clear");
	PrintMain(); //화면표시 틀 출력
    while(1)
    {
		
		optionChoice = fgetc(stdin); //선택 옵션을 키보드로 받아옴
		//ClearReadBuffer(); //버퍼 비움
		switch(optionChoice){//입력값에 따라 분기
			case 'q': //종료
				close(sock_raw); //sock_raw file discriptor를 닫는다.
				system("clear");
				exit(1);
				break;
			case 't': //tcp 조회
				if(PrintCaptureForm(buffer, data_size, FORM_TCP) == FORM_ERROR){
					printf("PrintCaptureFrom() form flag error\n");
				}
				break;
			case 'u': //udp 조회
				if(PrintCaptureForm(buffer, data_size, FORM_UDP) == FORM_ERROR){
					printf("PrintCaptureFrom() form flag error\n");
				}
				break;
			case 'f': //ftp 조회
				if(PrintCaptureForm(buffer, data_size, FORM_FTP) == FORM_ERROR){
					printf("PrintCaptureFrom() form flag error\n");
				} 
				break;
			case 'h': //http 조회
				if(PrintCaptureForm(buffer, data_size, FORM_HTTP) == FORM_ERROR){
					printf("PrintCaptureFrom() form flag error\n");
				} 
				break;
			case '?': //도움말
				PrintHelp();
				sleep(4);
				break;
			case 'm': //TODO : 코드의미 정확히 판단 후 지우던가 해야할듯.
				//TODO : 지워야할지 고려<<<<<<<<<<<<<<<<<<<<<<<<<<<
		        saddr_size = sizeof(saddr);
				printf("saddr_size : %d",saddr_size);
		        //Receive a packet
		        data_size = recvfrom(sock_raw , buffer , MAX_BUFFER_SIZE , 0 , &saddr , &saddr_size);
		
		        if(data_size <0 )
		        {
		            printf("Recvfrom error , failed to get packets\n");
		            break;
		        }
		        //Now process the packet
		        ProcessPacket(buffer , data_size);
				//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
				sleep(1);
				break;
			default : //다른 키 눌렀을 시
				break;
		}		
		system("clear");
		PrintMain(); //화면표시 틀 출력

    }

    close(sock_raw); //sock_raw file discriptor를 닫는다.
	system("clear");//화면 지움
    return 0;
}
