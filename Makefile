CC = gcc

CLI = client
MAIN = main_server
WORK = working_server

all : $(CLI) $(MAIN) $(WORK) 

$(CLI) : client.c
	$(CC) -o $@ $^ 

$(MAIN) : main_server.c 
	$(CC) -o $@ $^ -pthread -lssl -lcrypto

$(WORK) : working_server.c 
	$(CC) -o $@ $^ -pthread -lssl -lcrypto


clean :
	rm -rf *.o
	rm -rf $(CLI)
	rm -rf $(MAIN)
	rm -rf $(WORK)
