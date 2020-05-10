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

void send_malformedMsg(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;
    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);

    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);

    int ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)&sv_addr, addr_size);
    if (ret < SIZE_MESSAGE_MALFORMED_MEX) {
        perror("There was an error during the sending of the malformed msg ! \n");
        exit(-1);
    }

    close(socket);
    exit(-1);
}
void send_ACK(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;
    int ret;

    op_code = OPCODE_ACK;
    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);
    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);

    ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the ACK \n");
        exit(-1);
    }
}

void send_UpdateStatus(int socket, unsigned char* buffer, char* username, uint8_t user_size, uint8_t op_code, uint8_t seq_numb, uint8_t status_code,
                       sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;

    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);
    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);
    memcpy(buffer + pos, &status_code, sizeof(status_code));
    pos += sizeof(status_code);
    memcpy(buffer + pos, &user_size, sizeof(user_size));
    pos += sizeof(user_size);
    strcpy((char*)buffer + pos, username);
    pos += strlen(username) + 1;

    int ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the ACK \n");
        exit(-1);
    }
}