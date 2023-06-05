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
#define MAIN_SERVER_PORT 8080
#define MAX_CLIENTS 5
#define MAX_BLOCK 1024
#define WORKING_SERVER_MAX 1
#define WORKING_SERVER_PORT 8081

typedef struct Block {
    int index;
    long timestamp;
    char data[BUFMAX];
    unsigned char prev_hash[SHA256_DIGEST_LENGTH+1];
    unsigned char hash[SHA256_DIGEST_LENGTH+1];
    int nonce;
} Block;

Block block[MAX_BLOCK];
int block_number=0;
char *working_server_ip[]={"127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1"}; // 변경 필요
int thread_finished=0;

void errProc(const char *str);
void *connection_handler(void *socket_desc);
int communicate_working_server(unsigned char *send_data, unsigned char *recv_data,int working_number);
Block create_block(int index, const char *data, const unsigned char *prev_hash);
void getHash(char *input,unsigned char *output);
void *working_server_communication_thread(void *arg);
int tokenize(char *input, char *argv[]);
void binaryToHexStr(const unsigned char *binary, char *str, int len);

int main(void){
    int server_sock, client_sock, c;
    struct sockaddr_in server , client;
    pthread_t thread_id;

    // 0번 블록 초기화(dummy block)
    block[0].index=0;
    block[0].timestamp=0;
    strcpy(block[0].data,"0");
    strcpy(block[0].prev_hash,"0");
    strcpy(block[0].hash,"0");
    block[0].nonce=0;
    block_number++;

     
    // 소켓 생성
    server_sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
    if (server_sock == -1){
        errProc("Could not create socket");
    }
     
    // 주소 구조체 초기화
    memset(&server,0,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons( MAIN_SERVER_PORT );
     
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
        new_sock = malloc(sizeof(int));
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
    unsigned char pow_nonce[BUFMAX];
    char data[BUFMAX];
    unsigned char block_info[BUFSIZ];
    struct timespec begin,end;
    int working_number;
    double runtime;
    char prev_hash_str_buff[SHA256_DIGEST_LENGTH*2+1];
    char hash_str_buff[SHA256_DIGEST_LENGTH*2+1];
        
    //Receive
    while( (read_size = recv(client_sock , client_message , BUFMAX , 0)) > 0 )
    {
        // 받은 데이터의 data만 추출
        strncpy(data,client_message+1,strlen(client_message)-1);

        // 블록 생성
        block[block_number]=create_block(block_number,data,block[block_number-1].hash);
        block_number++; // 블록 개수 추가

        // 난이도 + 전송할 블록 데이터
        strncpy(block_info,client_message,1);
        snprintf(block_info,sizeof(block_info),"%c %d %ld %s %s %s %d",client_message[0],block[block_number-1].index, block[block_number-1].timestamp, block[block_number-1].data, block[block_number-1].prev_hash,block[block_number-1].hash, block[block_number-1].nonce);

        binaryToHexStr(block[block_number-1].prev_hash, prev_hash_str_buff, SHA256_DIGEST_LENGTH);
        binaryToHexStr(block[block_number-1].hash, hash_str_buff, SHA256_DIGEST_LENGTH);

        //DEBUG
        // printf("%c\n%d\n%ld\n%s\n%s\n%s\n%d",client_message[0],block[block_number-1].index, block[block_number-1].timestamp, block[block_number-1].data, prev_hash_str_buff,hash_str_buff, block[block_number-1].nonce);
        // printf("%s\n",block_info);

        // working서버에 데이터 전송 및 데이터 받기
        working_number=0;
        clock_gettime(CLOCK_MONOTONIC, &begin); // 타이머 시작
        while(communicate_working_server(block_info,pow_nonce,working_number)){ // working 서버가 일하고 있으면 다른 working 서버 찾아서 일 시키기
            working_number++;
            if(working_number>=WORKING_SERVER_MAX){
                printf("working_server busy...\n");
                working_number=0;
            }
            printf("working_server_communicate...\n");
        }
        clock_gettime(CLOCK_MONOTONIC, &end); // 타이머 종료

        // nonce값 넣기
        block->nonce=atoi(pow_nonce);

        // 시간 출력
        runtime=(end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1000000000.0;
        printf("pow run time : %f seconds\n", runtime);

        // 블록 정보 출력
        printf("index : %d\n",block[block_number-1].index);
        printf("timestamp : %ld\n",block[block_number-1].timestamp);
        printf("data : %s\n", block[block_number-1].data);
        printf("prev_hash : ");
        for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
            printf("%02x",block[block_number-1].prev_hash[i]);
        }
        printf("\n");
        printf("hash : ");
        for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
            printf("%02x",block[block_number-1].hash[i]);
        }
        printf("\n");
        printf("nonce : %d\n",block[block_number-1].nonce);
        printf("\n");

        snprintf(block_info,sizeof(block_info),"%f %d %ld %s %s %s %d",runtime,block[block_number-1].index,block[block_number-1].timestamp,block[block_number-1].data,prev_hash_str_buff,hash_str_buff,block[block_number-1].nonce);

        //클라이언트에게 데이터 전송
        write(client_sock , block_info , strlen(block_info));
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
    char block_string[BUFSIZ];
    snprintf(block_string,sizeof(block_string), "%d%ld%s%s%d", block.index, block.timestamp, block.data, block.prev_hash, block.nonce);
    getHash(block_string, block.hash);
    return block;
}

void binaryToHexStr(const unsigned char *binary, char *str, int len) {
    for(int i = 0; i < len; i++) {
        sprintf(str + (i * 2), "%02x", binary[i]);
    }
}

void getHash(char *input,unsigned char *output){
    //입력 데이터의 길이
    size_t input_len=sizeof(input)-1;

    //SHA256 해시 계산
    SHA256(input,input_len,output);
}

// working 서버가 일하고 있는지 확인
void *working_server_communication_thread(void *arg){
    int *working_number=(int*)arg; // 어떤 working_server를 선택하는지 정하기 위한 변수
    int sockfd;
    struct sockaddr_in serv_addr;
    char *send_buffer="O";
    char recv_buffer[BUFMAX];

    // 소켓 생성
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket");
        pthread_exit((void *)1);
    }

    // working 서버 주소 초기화
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(working_server_ip[*working_number]);
    serv_addr.sin_port = htons(WORKING_SERVER_PORT);

    // working 서버에 연결
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("connect");
        pthread_exit((void *)1);
    }

    
    // working 서버가 일하고 있는지 확인
    send(sockfd, send_buffer, strlen(send_buffer), 0);

    int recv_len = recv(sockfd, recv_buffer, BUFMAX, 0);
    recv_buffer[recv_len] = '\0';

    thread_finished=1;
    

    close(sockfd);
    return NULL;
}

void *working_server_data_exchange_thread(void *arg){
    char *thread_info=(char*)arg;
    int thread_info_argc;
    char *thread_info_argv[8];
    char send_data[BUFSIZ];
    char pow_result[BUFMAX];
    int sockfd;
    struct sockaddr_in serv_addr;
    
    thread_info_argc=tokenize(thread_info,thread_info_argv);
    if(thread_info_argc!=8){
        errProc("thread data transmit");
    }

    // 소켓 생성
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket");
        pthread_exit((void *)1);
    }

    // working 서버 주소 초기화
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(working_server_ip[atoi(thread_info_argv[0])]);
    serv_addr.sin_port = htons(WORKING_SERVER_PORT);

    // working 서버에 연결
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("connect");
        pthread_exit((void *)1);
    }

    snprintf(send_data,sizeof(send_data),"%s %s %s %s %s %s %s",thread_info_argv[1],thread_info_argv[2],thread_info_argv[3],thread_info_argv[4],thread_info_argv[5],thread_info_argv[6],thread_info_argv[7]);
    //DEBUG
    printf("send_data : %s",send_data);

    while(1){
        send(sockfd, send_data, strlen(send_data), 0);

        int recv_len = recv(sockfd, pow_result, BUFMAX, 0);
        pow_result[recv_len] = '\0';
    }

    close(sockfd);
    pthread_exit((void*)pow_result);
}

int communicate_working_server(unsigned char *send_data, unsigned char *recv_data, int working_number){
    pthread_t communication_thread;
    pthread_t data_exchange_thread;
    char thread_info[BUFMAX];
    char *return_data;
    int wait_time=5;

    // working 서버 일하는지 확인
    if(pthread_create(&communication_thread, NULL, working_server_communication_thread, &working_number) < 0){
        perror("could not create thread");
        exit(1);
    }

    //DEBUG
    // printf("%s\n",send_data);

    // communication_thread 완료를 최대 wait_time 초 동안 대기
    thread_finished=0;
    for(int i = 0; i < wait_time; i++){
        sleep(1);
        if(thread_finished){
            // working 서버 pow
            sprintf(thread_info,"%d %s",working_number,send_data);

            //DEBUG
            printf("thread_info : %s\n",thread_info);

            if(pthread_create(&data_exchange_thread, NULL, working_server_data_exchange_thread, &thread_info) < 0){
                perror("could not create thread");
                exit(1);
            }
    
            // 쓰레드가 종료될 때까지 기다림
            if(pthread_join(data_exchange_thread, (void**)&return_data) != 0){
                strcpy(recv_data,return_data);
            }

            return 0;
        }
    }

    // 5초가 지나면 다른 working 서버 찾기
    return 1;
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

void errProc(const char* str){
    perror(str);
    exit(1);
}
