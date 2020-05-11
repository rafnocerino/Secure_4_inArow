Server: check_message.cpp send_message.cpp server.cpp
	g++ -c -g check_message.cpp
	g++ -c -g send_message.cpp
	g++ -c -g server.cpp
	g++ -g check_message.o send_message.o server.o -lcrypto -pthread -o Server
