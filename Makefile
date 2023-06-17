CC = gcc

CLI = client
MAIN = main_server
WORK = working_server
TEST = test_working_server

all : $(CLI) $(MAIN) $(WORK) $(TEST)

$(CLI) : client.c
	$(CC) -o $@ $^ 

$(MAIN) : main_server.c 
	$(CC) -o $@ $^ -pthread -lssl -lcrypto

$(WORK) : working_server.c 
	$(CC) -o $@ $^ -pthread -lssl -lcrypto

$(TEST) :test_working_server.c
	$(CC) -o $@ $^ -pthread -lssl -lcrypto

clean :
	rm -rf *.o
	rm -rf $(CLI)
	rm -rf $(MAIN)
	rm -rf $(WORK)
	rm -rf $(TEST)
