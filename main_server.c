#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <openssl/sha.h>
#include <errno.h>
#include <time.h>

#define BUFMAX 1024
#define PORT "8080"
#define MAX_CLIENTS 5

typedef struct Block {
    int index;
    long timestamp;
    char data[256];
    unsigned char prev_hash[64];
    unsigned char hash[64];
    int nonce;
} Block;

Block block[MAX_CLIENTS];
int block_number=0;

void errProc(const char *str);
void *connection_handler(void *socket_desc);
void communicate_working_server(unsigned char *send_data, unsigned char *recv_data);
Block create_block(int index, const char *data, const unsigned char *prev_hash);
void getHash(char *input,unsigned char *output);

int main(void){
    int server_sock, client_sock, c;
    struct sockaddr_in server , client;
    pthread_t thread_id;
     
    // 소켓 생성
    server_sock = socket(AF_INET , SOCK_STREAM , 0);
    if (server_sock == -1){
        errProc("Could not create socket");
    }
     
    // 주소 구조체 초기화
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( atoi(PORT) );
     
    //Bind
    if( bind(server_sock,(struct sockaddr *)&server , sizeof(server)) < 0){
        errProc("bind failed. Error");
    }
    puts("bind done");
     
    //Listen
    listen(server_sock , MAX_CLIENTS);
     
    //Accept
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
    while( (client_sock = accept(server_sock, (struct sockaddr *)&client, (socklen_t*)&c)) ){
        puts("Connection accepted");
         
        int *new_sock;
        new_sock = malloc(1);
        *new_sock = client_sock;
         
        if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) new_sock) < 0){
            errProc("could not create thread");
        }
         
        puts("Handler assigned");
    }
     
    if (client_sock < 0){
        errProc("accept failed");
    }
     
    return 0;
}

void *connection_handler(void *socket_desc){
    int client_sock = *(int*)socket_desc;
    int read_size;
    unsigned char client_message[BUFMAX];
    unsigned char result[BUFMAX];
    char data[BUFMAX];
    char block_info[BUFSIZ];
    struct timespec begin,end;

    
    //Receive
    while( (read_size = recv(client_sock , client_message , BUFMAX , 0)) > 0 )
    {
        // 받은 데이터의 data만 추출
        strncpy(data,client_message+1,sizeof(BUFMAX));

        // 블록 생성
        block[block_number]=create_block(block_number,data,block[block_number-1].hash);
        block_number++; // 블록 개수 추가

        // 난이도 + 전송할 블록 데이터
        strncpy(block_info,client_message,1);
        sprintf(block_info,"%c %d %ld %s %s %s %d",client_message[0],block[block_number-1].index, block[block_number-1].timestamp, block[block_number-1].data, block[block_number-1].prev_hash,block[block_number-1].hash, block[block_number-1].nonce);

        // 워킹서버에 데이터 전송 및 데이터 받기
        clock_gettime(CLOCK_MONOTONIC, &begin);; // 타이머 시작
        communicate_working_server(block_info,result);
        clock_gettime(CLOCK_MONOTONIC, &end); // 타이머 종료

        // 시간 출력
        printf("%f seconds\n", (end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1000000000.0);

        //클라이언트에게 데이터 전송
        write(client_sock , result , strlen(client_message));
    }
     
    if(read_size == 0){
        puts("Client disconnected");
        fflush(stdout);
    } else if(read_size == -1){
        errProc("recv");
    }
         
    free(socket_desc);
     
    return 0;
}

// 블록 생성
Block create_block(int index, const char *data, const unsigned char *prev_hash) {
    Block block;
    block.index = index;
    block.timestamp = time(NULL);
    strncpy(block.data, data, sizeof(block.data));
    strncpy(block.prev_hash, prev_hash, sizeof(block.prev_hash));
    block.nonce = 0;
    char block_string[1024];
    sprintf(block_string, "%d%ld%s%s%d", block.index, block.timestamp, block.data, block.prev_hash, block.nonce);
    getHash(block_string, block.hash);
    return block;
}

void getHash(char *input,unsigned char *output){
    //입력 데이터의 길이
    size_t input_len=sizeof(input)-1;

    //SHA256 해시 계산
    SHA256(input,input_len,output);
}

void communicate_working_server(unsigned char *send_data, unsigned char *recv_data){
    //working_server에게 데이터 전송 및 데이터 받기(수정 필요)
}

void errProc(const char* str){
    perror(str);
    exit(1);
}
