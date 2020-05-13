#include "send_message.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "protocol_constant.h"
using namespace std;

#define BUF_SIZE 512



void send_challengeRefused(int socket, unsigned char* buffer, uint8_t seq_numb, int challenge_id, sockaddr_in* sv_addr_challenge, int addr_size) {

    uint8_t op_code = htons(OPCODE_CHALLENGE_REFUSED);
    uint8_t seqnumb = htons(seq_numb);
    int id = htons(challenge_id);
    int pos=0;

    memset(buffer,0,BUF_SIZE);
    memcpy(buffer,&op_code,SIZE_OPCODE);
    pos+=SIZE_OPCODE;
    memcpy(buffer+pos,&seqnumb,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    memcpy(buffer+pos,&id,sizeof(id));
    pos+=sizeof(id);

    int ret=sendto(socket,buffer,pos,0,(struct sockaddr*)sv_addr_challenge,addr_size);
    if (ret < SIZE_MESSAGE_CHALLENGE_REFUSED) {
        perror("There was an error during the sending of the malformed msg ! \n");
        exit(-1);
    }
}

void send_challengeAccepted(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr_challenging, int addr_size,
                            int challenge_id) {
    uint8_t opcode = htons(OPCODE_CHALLENGE_ACCEPTED);
    uint8_t seqnumb = htons(seq_numb);
    int pos = 0;
    int id = htons(challenge_id);

    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcode, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seqnumb, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    memcpy(buffer + pos, &id, sizeof(id));
    pos += sizeof(id);

    int ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr_challenging, addr_size);
    if (ret < SIZE_MESSAGE_CHALLENGE_ACCEPTED) {
        perror("There was an error during the sending of the malformed msg ! \n");
        exit(-1);
    }
}

void send_malformedMsg(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size) {
   int pos = 0;
	uint8_t opcodeMex = htons(OPCODE_MALFORMED_MEX);
	uint8_t seqNumMex = htons(seq_numb);
    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcodeMex, SIZE_OPCODE);
    pos += SIZE_OPCODE;

    memcpy(buffer + pos, &seq_numb, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;

    int ret = sendto(socket, buffer, SIZE_MESSAGE_MALFORMED_MEX, 0, (struct sockaddr*)sv_addr, addr_size);
	
    if (ret < (int)SIZE_MESSAGE_MALFORMED_MEX) {
        printf("There was an error during the sending of the malformed msg ! \n");
        //exit(-1);
    }
    close(socket);
    //exit(-1);
}
void send_ACK(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;
    int ret;
	uint8_t seqNumMex = htons(seq_numb);
    uint8_t opcodeMex = htons(OPCODE_ACK);
	memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcodeMex, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seqNumMex, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;

    ret = sendto(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < (int)SIZE_MESSAGE_ACK) {
        perror("There was an error during the sending of the ACK \n");
        exit(-1);
    }
}

void send_UpdateStatus(int socket, unsigned char* buffer, char* username, uint8_t user_size, uint8_t op_code, uint8_t seq_numb, uint8_t status_code,
                       sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;
	uint8_t seqNumMex = htons(seq_numb);
    uint8_t opcodeMex = htons(OPCODE_UPDATE_STATUS);
	uint8_t statusCodeMex = htons(status_code);
	uint8_t lenMex = htons(user_size);
	memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcodeMex, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seqNumMex, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    memcpy(buffer + pos, &statusCodeMex, SIZE_STATUS_CODE);
    pos += SIZE_STATUS_CODE;
    memcpy(buffer + pos, &lenMex, SIZE_LEN);
    pos += SIZE_LEN;
    memcpy(buffer + pos, username, strlen(username) + 1);
    pos += strlen(username) + 1;

    int ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the ACK \n");
        exit(-1);
    }
}