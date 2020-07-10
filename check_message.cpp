#include "check_message.h"
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "protocol_constant.h"
using namespace std;



bool check_login(int socket,unsigned char* message, unsigned int messageLength,uint8_t& seqNum,char* username) {
    uint8_t actualOpcode;
    uint8_t actualLength;
    uint8_t seq;
    memcpy(&actualOpcode, message, SIZE_OPCODE);
    
    if (actualOpcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        exit(-1);
    }

    if (actualOpcode != OPCODE_LOGIN) 
		return false;
	memcpy(&seq, message + SIZE_OPCODE, SIZE_SEQNUMBER);
    seqNum=seq;	
    memcpy(&actualLength, message + SIZE_OPCODE + SIZE_SEQNUMBER, SIZE_LEN);
    if (actualLength != messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN + 1))  // L'uno in più è per il carattere di terminazione della stringa
        return false;
	memcpy(username,message + SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN, messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN));
    return true;
}

bool check_ack(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb) {
    uint8_t rcv_seq_numb;
    uint8_t rcv_opcode;
    int pos = 0;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;
   

    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
   

    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        // this means that the msg that i sent was modified during the forwarding
        close(socket);
        exit(-1);
    }

    if ((rcv_opcode != exp_opcode) || (rcv_seq_numb != exp_seq_numb) || (messageLength != SIZE_MESSAGE_ACK)) {
        return false;
    }

    return true;
}

bool check_challengeRequest(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,
                            unsigned char* challenging_user, int& challenge_id, uint8_t& rcv_seq_numb) {
    uint8_t rcv_opcode;
    int pos = 0;
    uint8_t data_len;
    uint8_t seq;
    int id;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    

    memcpy(&seq, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    rcv_seq_numb = seq;

    memcpy(&id, buffer + pos, SIZE_CHALLENGE_NUMBER);
    pos += SIZE_CHALLENGE_NUMBER;
    challenge_id = id;

    memcpy(&data_len, buffer + pos, SIZE_LEN);
    pos += sizeof(data_len);

    memcpy(challenging_user,buffer+pos,data_len);
    pos+=data_len;


    strtok((char*)challenging_user, ";");
    
    int flush_len = strlen((char*)challenging_user) + 1;
    memset(challenging_user + flush_len, 0, 255 - flush_len);

    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        // this means that the msg that i sent was modified during the forwarding
        close(socket);
        exit(-1);
    }

    if (rcv_opcode != exp_opcode) {
        return false;
    }

    //prestare attenzione alla formula per il controllo della len
    if (data_len != messageLength - SIZE_OPCODE - SIZE_SEQNUMBER - SIZE_CHALLENGE_NUMBER - SIZE_LEN ) {
        return false;
    }

    return true;
}

bool check_challengeUnavailable(int socket, unsigned char* buffer, int messageLength, uint8_t exp_seq_numb) {
    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    int pos = 0;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;
   
    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;

    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        exit(-1);
    }
    if ((rcv_opcode != OPCODE_CHALLENGE_UNAVAILABLE) || (exp_seq_numb != rcv_seq_numb) || messageLength != SIZE_MESSAGE_CHALLENGE_UNAVAILABLE) {
        return false;
    }

    return true;
}

bool check_challengeRefused(int socket,unsigned char* buffer, int messageLenght,uint8_t exp_seq_numb){
    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    int id;
    int pos = 0;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    
    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
   

    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        exit(-1);
    }

     if ((rcv_opcode != OPCODE_CHALLENGE_REFUSED) || (exp_seq_numb != rcv_seq_numb) || (messageLenght != SIZE_MESSAGE_CHALLENGE_REFUSED)) {
        return false;
    }

    return true;

}

bool check_challengeTimerExpired(int socket,unsigned char* buffer,int messageLenght,uint8_t exp_seq_numb){
    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    int pos = 0;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    
    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    

     if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        exit(-1);
    }

    if ((rcv_opcode != OPCODE_CHALLENGE_TIMER_EXPIRED) || (exp_seq_numb != rcv_seq_numb) || (messageLenght != SIZE_MESSAGE_CHALLENGE_TIMER_EXPIRED)) {
        return false;
    }

    return true;

}


bool check_challengeStart(int socket,unsigned char* buffer, int messageLength,uint8_t exp_seq_numb,unsigned char* ip,unsigned char* adv_pubkey){

    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    uint8_t len;
    int pos=0;

    memcpy(&rcv_opcode,buffer,SIZE_OPCODE);
    pos+=SIZE_OPCODE;
    memcpy(&rcv_seq_numb,buffer+pos,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    memcpy(adv_pubkey,buffer+pos,SIZE_PUBLIC_KEY);
    pos+=SIZE_PUBLIC_KEY;
    memcpy(&len,buffer+pos,SIZE_LEN);
    pos+=SIZE_LEN;
    memcpy(ip,buffer+pos,len);
    pos+=len;


    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        exit(-1);
    }

    if( (rcv_opcode != OPCODE_CHALLENGE_START) || (rcv_seq_numb != exp_seq_numb) || (messageLength != pos)){
        return false;
    }
    

    return true;
}

