Client:
	g++ -c -g client_.cpp
	g++ -c -g send_message.cpp
	g++ -c -g check_message.cpp
	g++ -c -g gioco_v2.1.cpp
	g++  client_.o send_message.o check_message.o gioco_v2.1.o -lcrypto -o client
	rm -f *.o
