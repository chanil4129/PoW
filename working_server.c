#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <openssl/sha.h>

#define BUFMAX 1024

typedef struct Block {
    int index;
    long timestamp;
    char data[256];
    unsigned char prev_hash[64];
    unsigned char hash[64];
    int nonce;
} Block;

void errProc(const char*);
void get_nonce(unsigned char *, unsigned char *);
void proof_of_work(Block *block, int difficulty);
void getHash(char *input,unsigned char *output);
int tokenize(char *input, char *argv[]);

int main(int argc, char** argv)
{
	int mySock,readLen, nRecv, res;
	int clntSd;
	unsigned char buff[BUFSIZ];
    unsigned char result[BUFSIZ];
	char * strAddr;
	struct sockaddr_in srcAddr, destAddr;
	socklen_t addrLen;

	if(argc != 2) {
		fprintf(stderr,"Usage: %s Port",argv[0]);
		return 0;  
	}	
	mySock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(mySock == -1) errProc("socket");	
	memset(&srcAddr, 0, sizeof(srcAddr));

	// 서버 주소 및 포트 할당
	srcAddr.sin_addr.s_addr = htonl(INADDR_ANY);	
	srcAddr.sin_family = AF_INET;
	srcAddr.sin_port = htons(atoi(argv[1]));

	// 서버 소켓 바인드
	res = bind(mySock,(struct sockaddr *) &srcAddr,sizeof(srcAddr));	
	if(res == -1) errProc("bind");
	// 서버 listen
	if(listen(mySock,5)<0) errProc("listen");
	addrLen = sizeof(destAddr);
	// 클라이언트 요청 accept
	while(1)
	{
		clntSd=accept(mySock,(struct sockaddr *)&destAddr,&addrLen);
		if(clntSd==-1){
			errProc("accept");
		}
		printf("client %s:%d is connected...\n",inet_ntoa(destAddr.sin_addr),ntohs(destAddr.sin_port));
		// 클라이언트 request 처리 후, response 보내기
        nRecv=recv(clntSd,buff,sizeof(buff)-1,0);
        buff[nRecv]='\0';

        get_nonce(buff,result);

        send(clntSd,result,strlen(result),0);
		
		printf("Clent(%d): is disconnected\n",ntohs(destAddr.sin_port));
		close(clntSd);
	}
    close(mySock);	
	return 0;
}

void get_nonce(unsigned char *send_data,unsigned char *recv_data){
    Block block;
    int difficulty;
    int block_index;
    int send_data_argc;
    char *send_data_argv[7];
    
    send_data_argc=tokenize(send_data,send_data_argv);

    if(send_data_argc!=7){
        errProc("data leak");
    }

    // 받은 데이터 처리
    difficulty=atoi(send_data_argv[0]);
    block.index=atoi(send_data_argv[1]);
    block.timestamp=atol(send_data_argv[2]);
    strcpy(block.data,send_data_argv[3]);
    strcpy(block.hash,send_data_argv[4]);
    strcpy(block.hash,send_data_argv[5]);
    block.nonce=atoi(send_data_argv[6]);

    proof_of_work(&block,difficulty);

    sprintf(recv_data,"%d",block.nonce);
}

// 작업증명
void proof_of_work(Block *block, int difficulty) {
    char target[64] = {0};
    for (int i = 0; i < difficulty; i++) {
        target[i] = '0';
    }
    while (strncmp(block->hash, target, difficulty) != 0) {
        block->nonce++;
        char block_string[1024];
        sprintf(block_string, "%d%ld%s%s%d", block->index, block->timestamp, block->data, block->prev_hash, block->nonce);
        getHash(block_string, block->hash);
    }
}

void getHash(char *input,unsigned char *output){
    //입력 데이터의 길이
    size_t input_len=sizeof(input)-1;

    //SHA256 해시 계산
    SHA256(input,input_len,output);
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


void errProc(const char* str)
{
	fprintf(stderr,"%s: %s \n", str, strerror(errno));
	exit(1);
}
