#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>


#define BUFMAX 1024


char *IP_ADDR="127.0.0.1";
int PORT=8080;

void errProc(const char*);
int tokenize(char *input, char *argv[]);
void hexStrToBinary(const char *str, unsigned char *binary, int len);

int main(void){
    char data[BUFMAX];
    char difficulty[BUFMAX];
    int client_socket,readLen;
    char buff[BUFMAX];
    struct sockaddr_in destAddr;
    socklen_t addrLen;
    int block_argc;
    char *block_argv[7];
    unsigned char prev_hash[SHA256_DIGEST_LENGTH+1];
    unsigned char hash[SHA256_DIGEST_LENGTH+1];

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
    client_socket = socket(AF_INET, SOCK_STREAM, 0);

	// 주소 구조체 초기화
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_addr.s_addr = inet_addr(IP_ADDR);    
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(PORT);
    addrLen = sizeof(destAddr);

	// 서버에 연결 요청
    if(connect(client_socket,(struct sockaddr *)&destAddr,addrLen)==-1){
        close(client_socket);
        errProc("connect");
    }

	// 암호화된 값과 난이도를 서버에 전송
    send(client_socket, buff, strlen(buff), 0);
    
    readLen=recv(client_socket,buff,BUFMAX,0);
    buff[readLen]='\0';
    block_argc=tokenize(buff,block_argv);

    if(block_argc!=7){
        errProc("data transmit");
    }

    hexStrToBinary(block_argv[4], prev_hash, SHA256_DIGEST_LENGTH);
	hexStrToBinary(block_argv[5], hash, SHA256_DIGEST_LENGTH);
    
    // 블록 정보 출력
    printf("pow run time : %s seconds\n", block_argv[0]);
    printf("index : %s\n",block_argv[1]);
    printf("timestamp : %s\n",block_argv[2]);
    printf("data : %s\n",block_argv[3] );
    printf("prev_hash : ");
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",prev_hash);
    }
    printf("\n");
    printf("hash : ");
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        printf("%02x",prev_hash[i]);
    }
    printf("nonce : %s\n",block_argv[6]);
    printf("\n");

    close(client_socket);
    return 0;
}

int tokenize(char *input, char *argv[])
{
	char *ptr = NULL;
	int argc = 0;
	ptr = strtok(input, " ");

	while (ptr != NULL){
		argv[argc++] = ptr;
		ptr = strtok(NULL, " ");
	}

	return argc;
}

void hexStrToBinary(const char *str, unsigned char *binary, int len) {
    for(int i = 0; i < len; i++) {
        sscanf(str + (i * 2), "%02hhx", &binary[i]);
    }
}

// 에러 처리
void errProc(const char* str)
{
    fprintf(stderr,"%s: %s \n", str, strerror(errno));
    exit(1);
}