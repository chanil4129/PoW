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
#include <pthread.h>

#define BUFMAX 1024

typedef struct Block {
    int index;
    long timestamp;
    char data[BUFMAX];
    unsigned char prev_hash[SHA256_DIGEST_LENGTH+1];
    unsigned char hash[SHA256_DIGEST_LENGTH+1];
    char nonce[100];
} Block;
pthread_t canceled_thread;
pthread_mutex_t lock;
int threading=0;

void errProc(const char*);
void get_nonce(unsigned char *, unsigned char *);
void proof_of_work(Block *block, int difficulty);
void getHash(char *input,unsigned char *output);
int tokenize(char *input, char *argv[]);
void hexStrToBinary(const char *str, unsigned char *binary, int len);
void binaryToHexStr(const unsigned char *binary, char *str, int len);
void *connection_handler(void *socket_desc);
void nonce_plus(char *nonce);


int main(int argc, char** argv)
{
	int mySock,readLen, res;
	int clntSd;
	unsigned char buff[BUFSIZ];
    unsigned char result[BUFSIZ];
	char * strAddr;
	struct sockaddr_in srcAddr, destAddr;
	socklen_t addrLen;
	pthread_t thread_id;

	// mutex 초기화
    if(pthread_mutex_init(&lock, NULL) != 0) {
        printf("mutex init failed\n");
        exit(1);
    }

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
	while(1){
		clntSd=accept(mySock,(struct sockaddr *)&destAddr,&addrLen);
		if(clntSd==-1){
			errProc("accept");
		}
		printf("main_server %s:%d is connected...\n",inet_ntoa(destAddr.sin_addr),ntohs(destAddr.sin_port));

		int *new_sock;
		new_sock=malloc(sizeof(int));
		*new_sock=clntSd;

		if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) new_sock) < 0){
            errProc("could not create thread");
        }

	}

    if(clntSd<0){
		errProc("accept failed");
	}	
	pthread_mutex_destroy(&lock);
	return 0;
}

void *connection_handler(void *socket_desc){
	int client_sock = *(int*)socket_desc;
    int read_size;
	char result[BUFSIZ];
    unsigned char client_message[BUFSIZ];
        
    //Receive
    while( (read_size = recv(client_sock , client_message , BUFMAX , 0)) > 0 ){
        // 클라이언트 request 처리 후, response 보내기
		if(read_size<0){
			errProc("recieve");
		}
        client_message[read_size]='\0';

		if(!strcmp(client_message,"O")){
			printf("working stop\n");
			if(pthread_cancel(canceled_thread)!=0){
				errProc("thread_cancel");
				exit(1);
			}
			strcpy(result,"O");
			pthread_mutex_lock(&lock);
			threading=0;
			pthread_mutex_unlock(&lock);
		}
		else {
			printf("working start\n");
			pthread_mutex_lock(&lock);
			threading=1;
			canceled_thread=pthread_self();
			pthread_mutex_unlock(&lock);
			get_nonce(client_message,result);
		}
        send(client_sock,result,strlen(result),0);
		while(1){
				
		}
    }
     
    if(read_size == 0){
        puts("Client disconnected\n\n");
        fflush(stdout);
    } 
	else if(read_size == -1){
        errProc("recv");
    }
         
    free(socket_desc);
	pthread_mutex_lock(&lock);
	threading=0;
	pthread_mutex_unlock(&lock);
     
    return 0;
}

void get_nonce(unsigned char *send_data,unsigned char *recv_data){
    Block block;
    int difficulty;
    int block_index;
    int send_data_argc;
    char *send_data_argv[7];
	char hash_str_buff[SHA256_DIGEST_LENGTH*2+1];

    
    send_data_argc=tokenize(send_data,send_data_argv);

    if(send_data_argc!=6){
        errProc("data leak");
    }

    // 받은 데이터 처리
    difficulty=atoi(send_data_argv[0]);
    block.index=atoi(send_data_argv[1]);
    block.timestamp=atol(send_data_argv[2]);
    strcpy(block.data,send_data_argv[3]);
	hexStrToBinary(send_data_argv[4], block.prev_hash, SHA256_DIGEST_LENGTH);
	sscanf(send_data_argv[5],"%s",block.nonce);

    proof_of_work(&block,difficulty);

	binaryToHexStr(block.hash, hash_str_buff, SHA256_DIGEST_LENGTH);
    hash_str_buff[SHA256_DIGEST_LENGTH*2]=0x00;
    sprintf(recv_data,"%s %s",block.nonce, hash_str_buff);
	printf("nonce : %s\n",block.nonce);
}

void hexStrToBinary(const char *str, unsigned char *binary, int len) {
    for(int i = 0; i < len; i++) {
        sscanf(str + (i * 2), "%02hhx", &binary[i]);
    }
}

void binaryToHexStr(const unsigned char *binary, char *str, int len) {
    for(int i = 0; i < len; i++) {
        sprintf(str + (i * 2), "%02x", binary[i]);
    }
}

// 작업증명
void proof_of_work(Block *block, int difficulty) {
    char hash_str_buff[SHA256_DIGEST_LENGTH*2+1];
    char prev_hash_str_buff[SHA256_DIGEST_LENGTH*2+1];
    char target[difficulty + 1];

    for(int i = 0; i < difficulty; i++) {
        target[i] = '0';
    }
    target[difficulty] = '\0'; // null-terminate the target string

	strcpy(block->nonce,"10000000000000000000000000000000000000000");

    do {
        nonce_plus(block->nonce);
        char block_string[BUFSIZ];
        binaryToHexStr(block->prev_hash, prev_hash_str_buff, SHA256_DIGEST_LENGTH);
        snprintf(block_string, sizeof(block_string), "%d%ld%s%s%s", block->index, block->timestamp, block->data, prev_hash_str_buff, block->nonce);
        getHash(block_string, block->hash);
        binaryToHexStr(block->hash, hash_str_buff, SHA256_DIGEST_LENGTH);
		//DEBUG
		// for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        //     printf("%02x",block->hash[i]);
        // }
        // printf("\n");
		// printf("%s\n",block->nonce);
    } while(strncmp(hash_str_buff, target, difficulty) != 0);
	//DEBUG
}

void getHash(char *input,unsigned char *output){
    //입력 데이터의 길이
    size_t input_len=strlen(input);

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

void nonce_plus(char *nonce) {
    int len = strlen(nonce);
    int carry = 1;
    for (int i = len - 1; i >= 0; --i) {
        int digit = nonce[i] - '0' + carry;
        if (digit > 9) {
            carry = 1;
            digit = 0;
        } else {
            carry = 0;
        }
        nonce[i] = '0' + digit;
    }
    if (carry) {
        memmove(nonce + 1, nonce, len + 1);
        nonce[0] = '1';
    }
}


void errProc(const char* str)
{
	fprintf(stderr,"%s: %s \n", str, strerror(errno));
	exit(1);
}
