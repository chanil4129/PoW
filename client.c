#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>


#define BUFMAX 1024

void errProc(const char*);

char *IP_ADDR="127.0.0.1";
char *PORT="8080";

int main(void){
    char data[BUFMAX];
    char difficulty[BUFMAX];
    int client_socket,readLen;
    char buff[BUFMAX];
    struct sockaddr_in destAddr;
    socklen_t addrLen;

    // 사용자 입력
    printf("ID or name : ");
    fgets(data, sizeof(data), stdin);
    data[strlen(data)-1] = '\0';
    printf("Challenge difficulty : ");
    fgets(difficulty, sizeof(difficulty), stdin);
    difficulty[strlen(difficulty)-1] = '\0';
    
    // 서버에 보낼 데이터
    sprintf(buff,"%s%s",difficulty,data);

    // 소켓 생성
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// 주소 구조체 초기화
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_addr.s_addr = inet_addr(IP_ADDR);    
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(atoi(PORT));
    addrLen = sizeof(destAddr);

	// 서버에 연결 요청
    if(connect(client_socket,(struct sockaddr *)&destAddr,addrLen)==-1){
        close(client_socket);
        errProc("connect");
    }

	// 암호화된 값과 난이도를 서버에 전송
    send(client_socket, buff, readLen - 1, 0);
    
    readLen=recv(client_socket,buff,BUFMAX,0);
    buff[readLen]='\0';
    printf("%s\n",buff);

    close(client_socket);
    return 0;
}

// 에러 처리
void errProc(const char* str)
{
    fprintf(stderr,"%s: %s \n", str, strerror(errno));
    exit(1);
}