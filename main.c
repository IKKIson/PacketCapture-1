#include "stdhdr.h"
 

int main(void)
{
	char optionChoice; //옵션 선택 변수선언

	//SCREEN OPTION
    while(1)
    {
		
		//screen
		system("clear");
		PrintMain(); //화면표시 틀 출력
		optionChoice = fgetc(stdin); //선택 옵션을 키보드로 받아옴

		switch(optionChoice){//입력값에 따라 분기
			case 'q': //종료
				close(sock_raw); //sock_raw file discriptor를 닫는다.
				system("clear");
				exit(1);
				break;
					
			case 'f': //ftp 조회
////////////////////// dev : Jang ////////////////////
				if(PrintCaptureForm(FORM_FTP) == FORM_ERROR){
					printf("PrintCaptureFrom() ftp form flag error\n");
				} 
////////////////////// end : Jang ///////////////////
				break;
	
			case 'h': //http 조회
				if(PrintCaptureForm(FORM_HTTP) == FORM_ERROR){
					printf("PrintCaptureFrom() http form flag error\n");
				} 
				break;

			case 't': //telent 
				if(PrintCaptureForm(FORM_TELNET) == FORM_ERROR){
					printf("PrintCaptureForm() telnet form flag error\n");
				}
				break;

			case 'd': //dns
				if(PrintCaptureForm(FORM_DNS) == FORM_ERROR){
					printf("PrintCaptureForm() DNS form flag error\n");
				}
				break;
			default : //다른 키 눌렀을 시 skip
				break;
		}		
		system("clear");
		PrintMain(); //화면표시 틀 출력
    }
	


	return 0; 
}
