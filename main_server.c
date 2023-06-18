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
#define WORKING_SERVER_MAX 3

typedef struct Block {
    int index;
    long timestamp;
    char data[BUFMAX];
    unsigned char prev_hash[SHA256_DIGEST_LENGTH+1];
    unsigned char hash[SHA256_DIGEST_LENGTH+1];
    char nonce[100];
} Block;

Block block[MAX_BLOCK];
int block_number=0;
char *working_server_ip[]={"127.0.0.1","203.253.25.13","203.253.25.17"}; // 변경 필요
int working_server_port[]={8081,8082,8083};
int thread_finished=0;
pthread_t data_exchange_thread[WORKING_SERVER_MAX];
int cancel_thread_num;
pthread_mutex_t lock;
char pow_result[BUFMAX];
char to_working_server_message[BUFSIZ];



void errProc(const char *str);
void *connection_handler(void *socket_desc);
void communicate_working_server(int working_number);
void canceled_working_server(int working_number);
void block_init(int index, const char *data);
void getHash(char *input,unsigned char *output);
void *working_server_canceld_thread(void *arg);
void *working_server_data_exchange_thread(void *arg);
int tokenize(char *input, char *argv[]);
void binaryToHexStr(const unsigned char *binary, char *str, int len);
void hexStrToBinary(const char *str, unsigned char *binary, int len);

int main(void){
    int server_sock, client_sock, c;
    struct sockaddr_in server , client;
    pthread_t thread_id;

    // 0번 블록 초기화(dummy block)
    block[0].index=0;
    block[0].timestamp=0;
    strcpy(block[0].data,"0");
    for(int i=0;i<SHA256_DIGEST_LENGTH+1;i++){
        block[0].prev_hash[i]=0x00;
        block[0].hash[i]=0x00;
    }
    strcpy(block[0].nonce,"0");
    block_number++;

    // mutex 초기화
    if(pthread_mutex_init(&lock, NULL) != 0) {
        printf("mutex init failed\n");
        exit(1);
    }

     
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
    puts("Waiting for incoming connections...\n");
    c = sizeof(struct sockaddr_in);
    while( (client_sock = accept(server_sock, (struct sockaddr *)&client, (socklen_t*)&c)) ){
         
        int *new_sock;
        new_sock = malloc(sizeof(int));
        *new_sock = client_sock;
         
        if( pthread_create( &thread_id , NULL ,  connection_handler , (void*) new_sock) < 0){
            errProc("could not create thread");
        }
         
    }
     
    if (client_sock < 0){
        errProc("accept failed");
    }
    
    pthread_mutex_destroy(&lock);
     
    return 0;
}

void *connection_handler(void *socket_desc){
    int client_sock = *(int*)socket_desc;
    int read_size;
    unsigned char client_message[BUFMAX];
    unsigned char working_recv_buff[BUFMAX];
    char data[BUFMAX];
    unsigned char block_info[BUFSIZ];
    struct timespec begin,end;
    int working_number;
    double runtime;
    char prev_hash_str_buff[SHA256_DIGEST_LENGTH*2+1];
    char hash_str_buff[SHA256_DIGEST_LENGTH*2+1];
    int working_data_argc;
    char *working_data_argv[2];
        
    //Receive
    while( (read_size = recv(client_sock , client_message , BUFMAX , 0)) > 0 ){
        // 받은 데이터의 data만 추출
        strncpy(data,client_message+1,strlen(client_message)-1);

        //client message
        printf("(Client data)\n");
        printf("ID or name : %s\n",data);
        printf("difficulty : %c\n\n",client_message[0]);

        // 블록 생성
        block_init(block_number,data);
        block_number++; // 블록 개수 추가

        binaryToHexStr(block[block_number-1].prev_hash, prev_hash_str_buff, SHA256_DIGEST_LENGTH);
        prev_hash_str_buff[SHA256_DIGEST_LENGTH*2]=0x00;

        // 난이도 + 전송할 블록 데이터
        snprintf(block_info,sizeof(block_info),"%c %d %ld %s %s %s",client_message[0],block[block_number-1].index, block[block_number-1].timestamp, block[block_number-1].data, prev_hash_str_buff, block[block_number-1].nonce);

        strcpy(to_working_server_message,block_info);

        // working서버에 데이터 전송 및 데이터 받기
        thread_finished=0;
        clock_gettime(CLOCK_MONOTONIC, &begin); // 타이머 시작
        for(int i=0;i<WORKING_SERVER_MAX;i++){
            communicate_working_server(i);
        }
        
        // 스레드 관리(완료가 되면 스레드 종료 및 working 서버에 데이터 보내서 working 서버의 스레드도 종료)
        while(1){
            pthread_mutex_lock(&lock);
            if(thread_finished){
                strcpy(working_recv_buff,pow_result);
                for(int i=0;i<WORKING_SERVER_MAX;i++){
                    if(pthread_cancel(data_exchange_thread[i])!=0){
                        errProc("thread_cancel");
                        exit(1);
                    }
                    canceled_working_server(i);
                }
                pthread_mutex_unlock(&lock);
                break;
            }
            pthread_mutex_unlock(&lock);
        }

        clock_gettime(CLOCK_MONOTONIC, &end); // 타이머 종료

        //working_server 데이터 받기
        working_data_argc=tokenize(working_recv_buff,working_data_argv);

        if(working_data_argc!=2){
            errProc("data leak");
        }

        // nonce값 update
        sscanf(working_data_argv[0],"%s",block[block_number-1].nonce);

        // hash값 update
        hexStrToBinary(working_data_argv[1],block[block_number-1].hash,SHA256_DIGEST_LENGTH);

        // 시간 출력
        runtime=(end.tv_sec - begin.tv_sec) + (end.tv_nsec - begin.tv_nsec) / 1000000000.0;
        printf("(result)\n");
        printf("pow run time : %f seconds\n", runtime);

        // 블록 정보 출력
        printf("block_number : %d\n",block[block_number-1].index);
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
        printf("nonce : %s\n",block[block_number-1].nonce);

        // block_info update
        binaryToHexStr(block[block_number-1].hash, hash_str_buff, SHA256_DIGEST_LENGTH);
        hash_str_buff[SHA256_DIGEST_LENGTH*2]=0x00;

        snprintf(block_info,sizeof(block_info),"%f %d %ld %s %s %s %s",runtime,block[block_number-1].index,block[block_number-1].timestamp,block[block_number-1].data,prev_hash_str_buff,hash_str_buff,block[block_number-1].nonce);

        //클라이언트에게 데이터 전송
        write(client_sock , block_info , strlen(block_info));
    }
     
    if(read_size == 0){
        puts("Client disconnected\n\n");
        fflush(stdout);
    } else if(read_size == -1){
        errProc("recv");
    }
         
    free(socket_desc);
     
    return 0;
}

// 블록 생성
void block_init(int index, const char *data) {
    char prev_hash_str_buff[SHA256_DIGEST_LENGTH*2+1];

    block[index].index = index;
    block[index].timestamp = time(NULL);
    strncpy(block[index].data, data, sizeof(block[index].data));
    for(int i=0;i<SHA256_DIGEST_LENGTH+1;i++){
        block[index].prev_hash[i]=block[index-1].hash[i];
    }
    strcpy(block[index].nonce,"0");
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

void getHash(char *input,unsigned char *output){
    //입력 데이터의 길이
    size_t input_len=sizeof(input)-1;

    //SHA256 해시 계산
    SHA256(input,input_len,output);
}

// 워킹 서버의 스레드를 종료시키기 위한 핸들러
void *working_server_canceld_thread(void *arg){
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
    memset(&serv_addr,0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(working_server_ip[*working_number]);
    serv_addr.sin_port = htons(working_server_port[*working_number]);

    // working 서버에 연결
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("connect222");
        pthread_exit((void *)1);
    }

    
    // working 서버가 일하고 있는지 확인
    send(sockfd, send_buffer, strlen(send_buffer), 0);

    int recv_len = recv(sockfd, recv_buffer, BUFMAX, 0);
    recv_buffer[recv_len] = '\0';

    free(working_number);

    close(sockfd);
    return NULL;
}

// 워킹 서버에게 블록, 난이도 데이터를 전송하기 위한 핸들러
void *working_server_data_exchange_thread(void *arg){
    char *thread_info=(char*)arg;
    int thread_info_argc;
    char *thread_info_argv[8];
    char send_data[BUFSIZ];
    int sockfd;
    struct sockaddr_in serv_addr;
    
    thread_info_argc=tokenize(thread_info,thread_info_argv);

    if(thread_info_argc!=7){
        errProc("thread data transmit");
    }

    // 소켓 생성
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket");
        pthread_exit((void *)1);
    }

    // working 서버 주소 초기화
    memset(&serv_addr,0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(working_server_ip[atoi(thread_info_argv[0])]);
    serv_addr.sin_port = htons(working_server_port[atoi(thread_info_argv[0])]);

    // working 서버에 연결
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("connect_working..");
        pthread_exit((void *)1);
    }

    snprintf(send_data,sizeof(send_data),"%s %s %s %s %s %s",thread_info_argv[1],thread_info_argv[2],thread_info_argv[3],thread_info_argv[4],thread_info_argv[5],thread_info_argv[6]);

    send(sockfd, send_data, strlen(send_data), 0);

    int recv_len = recv(sockfd, pow_result, BUFMAX, 0);
    pow_result[recv_len] = '\0';

    close(sockfd);
    free(thread_info);
    pthread_mutex_lock(&lock);
    cancel_thread_num=atoi(thread_info_argv[0]);
    pthread_mutex_unlock(&lock);
    thread_finished=1;
    while(1){

    }
}

// 워킹 서버에게 블록, 난이도 데이터를 전송하기 위한 스레드 생성
void communicate_working_server(int working_number){
    char *thread_info=malloc(BUFMAX*sizeof(char));

    sprintf(thread_info,"%d %s",working_number,to_working_server_message);

    if(pthread_create(&data_exchange_thread[working_number], NULL, working_server_data_exchange_thread, thread_info) < 0){
        perror("could not create thread");
        free(thread_info);
        exit(1);
    }
}

//워킹 서버의 스레드를 종료시키기 위한 스레드 생성
void canceled_working_server(int working_number){
    pthread_t communication_thread;
    int *working_number_alloc=malloc(sizeof(int));
    *working_number_alloc=working_number;

    if(pthread_create(&communication_thread, NULL, working_server_canceld_thread, working_number_alloc) < 0){
        perror("could not create thread");
        exit(1);
    }
}

// 문자열을 토큰으로 분리
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
