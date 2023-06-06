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
#define WORKING_SERVER_MAX 2
#define WORKING_SERVER_PORT 8081

typedef struct Block {
    int index;
    long timestamp;
    char data[BUFMAX];
    unsigned char prev_hash[SHA256_DIGEST_LENGTH+1];
    unsigned char hash[SHA256_DIGEST_LENGTH+1];
    unsigned long long nonce;
} Block;

Block block[MAX_BLOCK];
int block_number=0;
char *working_server_ip[]={"127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1"}; // 변경 필요
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
void create_block(int index, const char *data);
void getHash(char *input,unsigned char *output);
void *working_server_canceld_thread(void *arg);
void *working_server_data_exchange_thread(void *arg);
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
    for(int i=0;i<SHA256_DIGEST_LENGTH+1;i++){
        block[0].prev_hash[i]=0x00;
        block[0].hash[i]=0x00;
    }
    block[0].nonce=0;
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
    
    pthread_mutex_destroy(&lock);
     
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

    //DEBUG
    // int send_data_argc;
    // char *send_data_argv[7];
        
    //Receive
    while( (read_size = recv(client_sock , client_message , BUFMAX , 0)) > 0 ){
        //DEBUG
        printf("client_message: %s\n",client_message);

        // 받은 데이터의 data만 추출
        strncpy(data,client_message+1,strlen(client_message)-1);

        // 블록 생성
        create_block(block_number,data);
        block_number++; // 블록 개수 추가

        binaryToHexStr(block[block_number-1].prev_hash, prev_hash_str_buff, SHA256_DIGEST_LENGTH);
        binaryToHexStr(block[block_number-1].hash, hash_str_buff, SHA256_DIGEST_LENGTH);
        prev_hash_str_buff[SHA256_DIGEST_LENGTH]=0x00;
        hash_str_buff[SHA256_DIGEST_LENGTH]=0x00;

        // 난이도 + 전송할 블록 데이터
        snprintf(block_info,sizeof(block_info),"%c %d %ld %s %s %s %lld",client_message[0],block[block_number-1].index, block[block_number-1].timestamp, block[block_number-1].data, prev_hash_str_buff,hash_str_buff, block[block_number-1].nonce);
        //DEBUG
        // printf("block_info_size : %ld\n",strlen(block_info));
        // printf("////////////\n%c\n%d\n%ld\n%s\n//////////////\n",client_message[0],block[block_number-1].index, block[block_number-1].timestamp, block[block_number-1].data);
        // for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        //     printf("%02x",block[block_number-1].prev_hash[i]);
        // }
        // printf("\n");
        // for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        //     printf("%02x",block[block_number-1].hash[i]);
        // }
        // printf("\n");
        // printf("#############################\n");

        strcpy(to_working_server_message,block_info);

        //DEBUG
        // send_data_argc=tokenize(block_info,send_data_argv);
        // printf("MMMMMMMMM: %d\n",send_data_argc);
        // printf("send_data_argv : %ld\n",strlen(send_data_argv[4]));

        //DEBUG
        // printf("%c\n%d\n%ld\n%s\n%s\n%s\n%lld",client_message[0],block[block_number-1].index, block[block_number-1].timestamp, block[block_number-1].data, prev_hash_str_buff,hash_str_buff, block[block_number-1].nonce);
        // printf("strlen(block_info) : %ld\n",strlen(block_info));

        // //DEBUG
        // for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        //     printf("%02x",block[1].hash[i]);
        // }
        // printf("\n");

        // working서버에 데이터 전송 및 데이터 받기
        thread_finished=0;
        //DEBUG
        printf("thread_finished : %d\n",thread_finished);
        clock_gettime(CLOCK_MONOTONIC, &begin); // 타이머 시작
        for(int i=0;i<WORKING_SERVER_MAX;i++){
            communicate_working_server(i);
        }
        
        while(1){
            pthread_mutex_lock(&lock);
            if(thread_finished){
                //DEBUG
                printf("working_server_END\n");
                strcpy(pow_nonce,pow_result);
                //DEBUG
                printf("result : %s\n",pow_result);
                for(int i=0;i<WORKING_SERVER_MAX;i++){
                    printf("i : %d\n",i);
                    if(i==cancel_thread_num){
                        continue;
                    }
                    //DEBUG
                    printf("cancel_thread_num : %d\n",cancel_thread_num);
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

        // nonce값 넣기
        block[block_number-1].nonce=atoll(pow_nonce);

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
        printf("nonce : %lld\n",block[block_number-1].nonce);
        printf("\n");

        snprintf(block_info,sizeof(block_info),"%f %d %ld %s %s %s %lld",runtime,block[block_number-1].index,block[block_number-1].timestamp,block[block_number-1].data,prev_hash_str_buff,hash_str_buff,block[block_number-1].nonce);

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
void create_block(int index, const char *data) {
    char prev_hash_str_buff[SHA256_DIGEST_LENGTH*2+1];

    block[index].index = index;
    block[index].timestamp = time(NULL);
    strncpy(block[index].data, data, sizeof(block[index].data));
    binaryToHexStr(block[index-1].hash, prev_hash_str_buff, SHA256_DIGEST_LENGTH);
    prev_hash_str_buff[SHA256_DIGEST_LENGTH]=0x00;
    block[index].nonce = 0;
    char block_string[BUFSIZ];
    snprintf(block_string,sizeof(block_string), "%d%ld%s%s%lld", block[index].index, block[index].timestamp, block[index].data, prev_hash_str_buff, block[index].nonce);
    getHash(block_string, block[index].hash);
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

void *working_server_canceld_thread(void *arg){
    int *working_number=(int*)arg; // 어떤 working_server를 선택하는지 정하기 위한 변수
    int sockfd;
    struct sockaddr_in serv_addr;
    char *send_buffer="O";
    char recv_buffer[BUFMAX];

    //DEBUG
    printf("working_number : %d\n",*working_number);
    printf("working_server_canceld_thread\n");

    // 소켓 생성
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        perror("socket");
        pthread_exit((void *)1);
    }

    // working 서버 주소 초기화
    memset(&serv_addr,0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(working_server_ip[*working_number]);
    serv_addr.sin_port = htons(WORKING_SERVER_PORT+*working_number);

    // working 서버에 연결
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("connect");
        pthread_exit((void *)1);
    }

    
    // working 서버가 일하고 있는지 확인
    send(sockfd, send_buffer, strlen(send_buffer), 0);

    printf("send????\n");

    int recv_len = recv(sockfd, recv_buffer, BUFMAX, 0);
    recv_buffer[recv_len] = '\0';

    //DEBUG
    printf("cancel finish");

    free(working_number);

    close(sockfd);
    return NULL;
}

void *working_server_data_exchange_thread(void *arg){
    char *thread_info=(char*)arg;
    int thread_info_argc;
    char *thread_info_argv[8];
    char send_data[BUFSIZ];
    int sockfd;
    struct sockaddr_in serv_addr;
    
    thread_info_argc=tokenize(thread_info,thread_info_argv);

    //DEBUG
    // printf("thread_infow2: %s\n",thread_info);
    printf("thread_info_argc : %d\n",thread_info_argc);
    printf("%s\n",thread_info_argv[0]);
    printf("%s\n",thread_info_argv[1]);
    printf("%s\n",thread_info_argv[2]);

    if(thread_info_argc!=8){
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
    serv_addr.sin_port = htons(WORKING_SERVER_PORT+atoi(thread_info_argv[0]));

    //DEBUG
    // printf("ip : %s\n",working_server_ip[atoi(thread_info_argv[0])]);
    // printf("WORKING_SERVER_PORT : %d\n",WORKING_SERVER_PORT+atoi(thread_info_argv[0]));

    // working 서버에 연결
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("connect");
        pthread_exit((void *)1);
    }

    snprintf(send_data,sizeof(send_data),"%s %s %s %s %s %s %s",thread_info_argv[1],thread_info_argv[2],thread_info_argv[3],thread_info_argv[4],thread_info_argv[5],thread_info_argv[6],thread_info_argv[7]);
    //DEBUG
    // printf("send_data : %s",send_data);

    send(sockfd, send_data, strlen(send_data), 0);

    int recv_len = recv(sockfd, pow_result, BUFMAX, 0);
    pow_result[recv_len] = '\0';

    //DEBUG
    printf("pow_result : %s\n",pow_result);

    close(sockfd);
    free(thread_info);
    pthread_mutex_lock(&lock);
    cancel_thread_num=atoi(thread_info_argv[0]);
    pthread_mutex_unlock(&lock);
    thread_finished=1;
    //DEBUG
    // printf("in_thread_finished : %d\n",thread_finished);
    //DEBUG
    // printf("in_thread_cancel_thread_num : %d\n",cancel_thread_num);
    pthread_exit((void*)pow_result);
}

void communicate_working_server(int working_number){
    char *thread_info=malloc(BUFMAX*sizeof(char));

    //DEBUG
    // int send_data_argc;
    // char *send_data_argv[7];

    sprintf(thread_info,"%d %s",working_number,to_working_server_message);

    //DEBUG
    // send_data_argc=tokenize(thread_info,send_data_argv);
    // printf("send_data_argc : %d\n",send_data_argc);
    // printf("*******\n%s\n%s\n%s\n********\n",send_data_argv[0],send_data_argv[1],send_data_argv[2]);

    if(pthread_create(&data_exchange_thread[working_number], NULL, working_server_data_exchange_thread, thread_info) < 0){
        perror("could not create thread");
        free(thread_info);
        exit(1);
    }
}

void canceled_working_server(int working_number){
    pthread_t communication_thread;
    int *working_number_alloc=malloc(sizeof(int));
    *working_number_alloc=working_number;

    //DEBUG
    printf("canceled_working_server\n");

    if(pthread_create(&communication_thread, NULL, working_server_canceld_thread, working_number_alloc) < 0){
        perror("could not create thread");
        exit(1);
    }
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
