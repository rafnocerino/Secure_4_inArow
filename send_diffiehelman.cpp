#include "send_message.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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

/* OP_CODE - SEQ_NUMB - LEN - DH_PARAM */

void send_dh(int socket, struct sockaddr_in* sv_addr, EVP_PKEY* dhsigned, int len_dhsigned
                           uint8_t seq_numb) {
    socklen_t len=sizeof(*adversary_socket);
    uint8_t op_code = OPCODE_DH_KEY;
    uint8_t seq = seq_numb;
    int id = challenge_id;
    char buffer[BUF_SIZE];
    int msg_size=SIZE_OPCODE+SIZE_SEQNUMBER+len_dhsigned;
    int pos = 0;
    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &op_code, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seq, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    memcpy(buffer+pos,&msg_size, sizeof(msg_size));
    pos += sizeof(msg_size);
    memcpy(buffer + pos, dhsiged, len_dhsigned);
    pos += len_dhsigned;
    

    int ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the challenge request ! \n");
        exit(-1);
    }
}

void wait_ACK(int sd, sockaddr_in* sock, uint8_t sq_numb)
{
	struct timeval tv;
	int ret;
	socklen_t len;
	char buffer[BUF_SIZE]; //
	tv.tv_sec = 120; //after 120 sec u
	tv.tv_usec= 0 ;
	
	cout<<"Waiting for ACK ..."<<endl;
	if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
		perror("Error");
		// this program should not exit 
		//should go back to the login
		exit(-1);
	}
	ret=recvfrom(sd,buffer,sizeof(buffer),0,(struct sockaddr*)sock,&len);
	//check if ACK or Malformed MSG
	cout<<"ACK recived!!!"<<endl;
	
}


// before calling this function in diffie helman intialize on param
void wait_dh(int sd, sockaddr_in* sock, uint8_t sq_numb, EVP_PKEY* param){
	struct timeval tv;
	int ret;
	socklen_t len;
	char buffer[BUF_SIZE]; //
	int pos=0;	
	int msg_len;
	tv.tv_sec = 120; //after 120 sec u
	tv.tv_usec= 0 ;
	
	cout<<"Waiting for ACK ..."<<endl;
	if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
		perror("Error");
		// this program should not exit 
		//should go back to the login
		exit(-1);
	}
	ret=recvfrom(sd,buffer,sizeof(buffer),0,(struct sockaddr*)sock,&len);

	
	//check if malformed
	//check signature
	pos+=SIZE_OPCODE;
	pos+=SIZE_SEQNUMBER;
	memcpy(msg_len,&(buffer+pos),sizeof(int));
	pos+=sizeof(int);
	msg_len=msg_len - SIZE_OPCODE -SIZE_SIZE_SEQNUMBER;
	memcpy(param, &(buffer+pos), msg_len);
	cout<<"DH parameter recived!!!"<<endl;
}
