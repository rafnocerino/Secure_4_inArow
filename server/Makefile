Server: ../protocol_constant.h ../gcm.cpp ../dh.cpp ../check_message.cpp ../digital_signature.cpp ../send_message.cpp server.cpp 
	g++ -c -g ../gcm.cpp	
	g++ -c -g ../dh.cpp	
	g++ -c -g ../digital_signature.cpp	
	g++ -c -g ../check_message.cpp
	g++ -c -g ../send_message.cpp
	g++ -c -g users_datastructure.cpp
	g++ -c -g challenges_datastructure.cpp
	g++ -c -g server.cpp
	g++ -g gcm.o dh.o digital_signature.o check_message.o send_message.o challenges_datastructure.o users_datastructure.o server.o -lcrypto -pthread -o Server
	rm -f *.o
