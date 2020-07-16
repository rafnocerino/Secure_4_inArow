Client:
	g++ -c -g gcm.cpp
	g++ -c -g dh.cpp
	g++ -c -g digital_signature.cpp
	g++ -c -g client_.cpp
	g++ -c -g send_message.cpp
	g++ -c -g check_message.cpp
#	g++ -c -g gioco_v2.1.cpp
#	g++ gcm.o client_.o send_message.o check_message.o gioco_v2.1.o digital_signature.o dh.o -lcrypto -pthread -o client
	g++ gcm.o client_.o send_message.o check_message.o digital_signature.o dh.o -lcrypto -pthread -o client
	rm -f *.o
