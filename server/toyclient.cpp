#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "protocol_constant.h"
#include<openssl/hmac.h>
#include <iostream> 
#include <string.h>
#include <openssl/evp.h>
using namespace std;

int main(){
	unsigned char *buf;
	buf = (unsigned char*)malloc(SIZE_MESSAGE_LOGIN);
	char username[255];
	sprintf(username,"Dario");
	int memcpyPos = 0;
	uint8_t opcode = OPCODE_LOGIN;	
	uint8_t seqNum = 0;
	uint8_t stringDim = 15;
	memcpy(buf , &opcode, SIZE_OPCODE);
	memcpyPos += SIZE_OPCODE;
	memcpy(buf + memcpyPos,&seqNum,SIZE_SEQNUMBER);	
	memcpyPos += SIZE_SEQNUMBER;
	memcpy(buf + memcpyPos,&stringDim,SIZE_LEN);
	memcpyPos += SIZE_LEN;
	memcpy(buf + memcpyPos,username,strlen(username)+1);
	memcpyPos += strlen("Dario") + 1;
	int sock;
    char ip_addr[] = "127.0.0.1";
    uint16_t port = 7799;
    struct sockaddr_in sv_addr;
    memset(&sv_addr, 0, sizeof(sv_addr));
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip_addr, &sv_addr.sin_addr);
	printf("Messaggio inviato:\n");
 	BIO_dump_fp (stdout, (const char *)buf, memcpyPos);
	sendto(sock, buf, memcpyPos, 0, (struct sockaddr*)&sv_addr, sizeof(struct sockaddr_in));
	//Ricezione dell'ACK
	struct sockaddr_in serverAddress;
	free(buf);
	socklen_t size = sizeof(struct sockaddr_in);
	buf = (unsigned char*)malloc(SIZE_MESSAGE_ACK);
	int received = recvfrom(sock, buf, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)&serverAddress,&size);
	printf("Messaggio ricevuto:\n");
 	BIO_dump_fp (stdout, (const char *)buf, received);
	return 0;
}
