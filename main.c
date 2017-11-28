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

    while(1)
    {
		system("clear");
		PrintMain(); //화면표시 틀 출력
		
		optionChoice = fgetc(stdin); //선택 옵션을 키보드로 받아옴
		//ClearReadBuffer(); //버퍼 비움
		switch(optionChoice){//입력값에 따라 분기
			case 'q': //종료
				close(sock_raw); //sock_raw file discriptor를 닫는다.
				system("clear");
				exit(1);
				break;
			case 't': //tcp 조회
				{
					char ch; //자식 프로세스로 따로따로 출력할지 고려해봐야 됨. 실시간 출력하면서 커맨드 입력가능하게 만들어야 됨.
					while(1){
						sleep(1);
						ch = fgetc(stdin);
						if (ch == 'q')
							break;
						PrintTcpPacketCmd(buffer,data_size);
					}
				}
				break;
			case 'u': //udp 조회

				break;
			case 'f': //ftp 조회

				break;
			case 'h': //http 조회

				break;
			case '?': //도움말
				PrintHelp();
				break;
			default : //다른 키 눌렀을 시
				break;
		}

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
    }

    close(sock_raw); //sock_raw file discriptor를 닫는다.
	system("clear");//화면 지움
    return 0;
}
