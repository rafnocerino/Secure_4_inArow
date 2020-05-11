#include "check_message.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "protocol_constant.h"
using namespace std;

bool check_login(unsigned char* message, unsigned int messageLength,uint8_t* seqNum,char* username) {
    uint8_t actualOpcode;
    uint8_t actualLength;
    memcpy(&actualOpcode, message, SIZE_OPCODE);
    if (actualOpcode != OPCODE_LOGIN) 
		return false;
	memcpy(&seqNum, message + SIZE_OPCODE, SIZE_SEQNUMBER);	
    memcpy(&actualLength, message + SIZE_OPCODE + SIZE_SEQNUMBER, SIZE_LEN);
    if (actualLength != messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN + 1))  // L'uno in più è per il carattere di terminazione della stringa
        return false;
	memcpy(username,message + SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN, messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN));
    return true;
}

bool check_ack(int socket, unsigned char* buffer, unsigned int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb) {
    uint8_t rcv_seq_numb;
    uint8_t rcv_opcode;
    int pos = 0;

    memcpy(&rcv_opcode, buffer, sizeof(rcv_opcode));
    pos += sizeof(rcv_opcode);

    memcpy(&rcv_seq_numb, buffer + pos, sizeof(rcv_seq_numb));
    pos += sizeof(rcv_seq_numb);

    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        // this means that the msg that i sent was modified during the forwarding
        close(socket);
        exit(-1);
    }

    if ((rcv_opcode != exp_opcode) || (rcv_seq_numb != exp_seq_numb)) {
        return false;
    }

    return true;
}

bool check_challengeRequest(int socket, unsigned char* buffer, unsigned int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,
                            unsigned char* challenging_user, int& challenge_id,uint8_t& rcv_seq_numb) {
    
    uint8_t rcv_opcode;
    int pos = 0;
	uint8_t data_len;

    memcpy(&rcv_opcode, buffer, sizeof(rcv_opcode));
    pos += sizeof(rcv_opcode);

    memcpy(&rcv_seq_numb, buffer + pos, sizeof(rcv_seq_numb));
    pos += sizeof(rcv_seq_numb);

	memcpy(&challenge_id,buffer+pos,sizeof(challenge_id));
	pos+=sizeof(challenge_id);

	memcpy(&data_len,buffer+pos,SIZE_LEN);
	pos+=sizeof(data_len);
    
	strcpy((char*)challenging_user,(char*)buffer+pos);
    pos+=strlen((char*)challenging_user)+1;

	strtok((char*)challenging_user,";");
    int flush_len =strlen((char*)challenging_user)+1;
    memset(challenging_user+flush_len,0,255-flush_len);

	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        // this means that the msg that i sent was modified during the forwarding
        close(socket);
        exit(-1);
    }

	if(rcv_opcode != exp_opcode){
		return false;
	}
	
	if(data_len!=messageLength+SIZE_OPCODE+SIZE_SEQNUMBER+SIZE_CHALLENGE_NUMBER+SIZE_LEN+1){
		return false;
	}

	return true;

}

