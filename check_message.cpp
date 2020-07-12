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
#include <pthread.h>

#include <openssl/evp.h>

#include "protocol_constant.h"
using namespace std;



bool check_login(int socket,unsigned char* message, int messageLength,uint8_t& seqNum,char* username) {
   
	uint8_t actualOpcode;
    uint8_t actualLength;
    uint8_t seq;
    memcpy(&actualOpcode, message, SIZE_OPCODE);
    
    if (actualOpcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

    if (actualOpcode != OPCODE_LOGIN) 
		return false;

	memcpy(&seq, message + SIZE_OPCODE, SIZE_SEQNUMBER);
    seqNum=seq;	

    memcpy(&actualLength, message + SIZE_OPCODE + SIZE_SEQNUMBER, SIZE_LEN);
	
	//printf("->messagelength: %d\n",messageLength);
	//printf("->actualLength: %d\n",actualLength);

    if (actualLength != messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN))  // L'uno in più è per il carattere di terminazione della stringa
        return false;
	memcpy(username,message + SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN, messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN));
    return true;
}

bool check_ack(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb){
    uint8_t rcv_seq_numb;
    uint8_t rcv_opcode;
    int pos = 0;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;

	if(rcv_opcode != exp_opcode){
		return false;
	}
   

    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
   
	
	printf("-----------------------------------------\n");
	printf("OPCODE -> Exp. = %u ; Rcv = %u.\n",exp_opcode,rcv_opcode);
	printf("Message length = %d.\n",messageLength);
	printf("ACK -> Exp. s.n. = %u ; Rcv s.n. = %u\n",exp_seq_numb,rcv_seq_numb);
	printf("-----------------------------------------\n");

    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        // this means that the msg that i sent was modified during the forwarding
        close(socket);
        pthread_exit(NULL);
    }

    if ( (rcv_seq_numb != exp_seq_numb) || (messageLength != SIZE_MESSAGE_ACK)) {
        printf("Figli di troia.\n");
		return false;
    }

    return true;
}


bool check_challengeRequest(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,char* challenging_user, int& challenge_id, uint8_t& rcv_seq_numb,char* challengedUser){
    uint8_t rcv_opcode;
    int pos = 0;
    uint8_t data_len;
    uint8_t seq;
    int id;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    
	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        // this means that the msg that i sent was modified during the forwarding
        close(socket);
        pthread_exit(NULL);
    }

	if (rcv_opcode != exp_opcode) {
        return false;
    }

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
    
	//dario;raffa'\0'
	//dario'\0';raffa'\0'

    int flush_len = strlen((char*)challenging_user) + 1;
	
	if(challengedUser != NULL){
		memcpy(challengedUser,challenging_user + flush_len,flush_len);
		printf("-> challenged user: %s.\n",challengedUser);
	}	
	
    memset(challenging_user + flush_len, 0, 255 - flush_len);

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
   
	if(rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

	if(rcv_opcode != OPCODE_CHALLENGE_UNAVAILABLE){
		return false;
	}	

    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;


    if ((exp_seq_numb != rcv_seq_numb) || messageLength != SIZE_MESSAGE_CHALLENGE_UNAVAILABLE) {
        return false;
    }

    return true;
}

bool check_challengeRefused(int socket,unsigned char* buffer, int messageLenght,uint8_t exp_seq_numb,int *challengeId){
    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    int pos = 0;

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos += SIZE_OPCODE;

	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

	if(rcv_opcode != OPCODE_CHALLENGE_REFUSED){
		return false;
	}
    
    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
   
	memcpy(challengeId,buffer + pos,SIZE_CHALLENGE_NUMBER);
	pos += SIZE_CHALLENGE_NUMBER;

     if ((exp_seq_numb != rcv_seq_numb) || (messageLenght != SIZE_MESSAGE_CHALLENGE_REFUSED)) {
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
    
	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

	if(rcv_opcode != OPCODE_CHALLENGE_TIMER_EXPIRED){
		return false;
	}

    memcpy(&rcv_seq_numb, buffer + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    
	printf("OPCODE-> %u.\n",rcv_opcode);
	printf("EX. S.N. = %u | RC. S.N. = %u.\n",exp_seq_numb,rcv_seq_numb);	
	printf("Message Lenght = %d.\n",messageLenght);	



    if ((exp_seq_numb != rcv_seq_numb) || (messageLenght != SIZE_MESSAGE_CHALLENGE_TIMER_EXPIRED)) {
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

	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

	if(rcv_opcode != OPCODE_CHALLENGE_START){
		return false;
	}

    memcpy(&rcv_seq_numb,buffer+pos,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    memcpy(&len,buffer+pos,SIZE_LEN);
    pos+=SIZE_LEN;
    memcpy(adv_pubkey,buffer+pos,SIZE_PUBLIC_KEY);
    pos+=SIZE_PUBLIC_KEY;
    memcpy(ip,buffer+pos,len);
    pos+=len;

	printf("------Challenge Start Check------\n");
	printf("OPCODE -> %u.\n",rcv_opcode);
	printf("SEQ.NUM EXP = %u; RCV = %u.\n",exp_seq_numb,rcv_seq_numb);
	printf("LUNGHEZZA IP = %u.\n",len);
	printf("MESSAGE LENGTH = %d\n",messageLength);
	printf("POS = %d\n",pos);
	printf("---------------------------------\n");
	



    if((rcv_seq_numb != exp_seq_numb) || (messageLength != pos)){
        return false;
    }
    

    return true;
}

bool check_updateStatus(int socket,unsigned char* message,int messageLength,uint8_t expectedSeqNum,uint8_t& statusCode,char* username){
	
	uint8_t opcodeMex;
	uint8_t seqNumMex;
	uint8_t statusCodeMex;
	uint8_t lenMex;
	
	int pos = 0;	
	
	memcpy(&opcodeMex,message,SIZE_OPCODE);
	pos += SIZE_OPCODE;

	if(opcodeMex == OPCODE_MALFORMED_MEX){
		close(socket);		
		pthread_exit(NULL);
	}

	//Controllo del opcode	
	if(opcodeMex != OPCODE_UPDATE_STATUS)
		return false;

	memcpy(&seqNumMex,message + pos,SIZE_SEQNUMBER);
	pos += SIZE_SEQNUMBER;

	memcpy(&statusCodeMex,message + pos,SIZE_STATUS_CODE);
	pos += SIZE_STATUS_CODE;
	statusCode = statusCodeMex;
		
	memcpy(&lenMex,message + pos,SIZE_LEN);
	pos += SIZE_LEN;


	memcpy(username,message + pos,lenMex);
	pos += lenMex;


	printf("opcode -> %u\n",opcodeMex);
	printf("RCV S.N. -> %u | EX. S.N. -> %u \n",seqNumMex,expectedSeqNum);
	printf("status code -> %u\n",statusCodeMex);
	printf("LEN -> %u\n",lenMex);
	printf("Username -> %s \n",username);
	printf("messageLenght -> %d\n", messageLength);

	//Controllo della lunghezza del messaggio
	if(messageLength <= ( SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_STATUS_CODE + SIZE_LEN ) || messageLength > SIZE_MESSAGE_UPDATE_STATUS)
		return false;


	if(seqNumMex != expectedSeqNum){
		return false;
	}
	
	//Controllo dello status code
	if(statusCodeMex != STATUS_CHALLENGING && statusCodeMex != STATUS_IDLE && statusCodeMex != STATUS_WAITING)
		return false;
	

	if(messageLength != SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_STATUS_CODE + SIZE_LEN + lenMex)
		return false;

	return true;
}

bool check_exit(int socket,unsigned char* message,int messageLength,uint8_t expectedSeqNum,char* username){
	uint8_t actualOpcode = 10;
	uint8_t actualSeqNum = 10;
	uint8_t actualLength = 10;

	memcpy(&actualOpcode,message,SIZE_OPCODE);

	if(actualOpcode == OPCODE_MALFORMED_MEX){
		close(socket);
		pthread_exit(NULL);
	}

	if(actualOpcode != OPCODE_EXIT){
		return false;
	}


	memcpy(&actualSeqNum,message + SIZE_OPCODE, SIZE_SEQNUMBER);
	memcpy(&actualLength,message + SIZE_OPCODE + SIZE_SEQNUMBER, SIZE_LEN);
	memcpy(username,message + SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN, actualLength);

	printf("-------Check-exit-------------------------\n");
	printf("S.N. EXP = %u | RCV. = %u \n",expectedSeqNum,actualSeqNum);
	printf("Message Recived Lenght = %d\n",messageLength);
	printf("Lenght username = %u\n", actualLength);
	printf("---------------------------------------\n");
	
	if(actualSeqNum != expectedSeqNum){
		return false;
	}
	
	
	if(actualLength != messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN)){  // L'uno in più è per il carattere di terminazione della stringa
		return false;
	}

	
	return true;
}

bool check_challengeAccepted(int socket,unsigned char* buffer,int messageLength,uint8_t expectedSeqNum,int* challengeNumber){
	uint8_t actualOpcode;
	uint8_t seqNumMex;

	memcpy(&actualOpcode,buffer,SIZE_OPCODE);

	if(actualOpcode == OPCODE_MALFORMED_MEX){
		close(socket);
		pthread_exit(NULL);
	}	

	if(actualOpcode != OPCODE_CHALLENGE_ACCEPTED){
		return false;
	}
	
	memcpy(&seqNumMex,buffer + SIZE_OPCODE,SIZE_SEQNUMBER);
	if(seqNumMex != expectedSeqNum){
		return false;
	}

	memcpy(challengeNumber, buffer + SIZE_OPCODE + SIZE_SEQNUMBER, SIZE_CHALLENGE_NUMBER);

	return true;
}

bool check_available_userList(int socket, unsigned char* buffer,int& list_len,int messageLength,uint8_t exp_seq_numb,char* available_users,int& flag){

    uint8_t opcodeMex;
	uint8_t seqNumMex;
	uint8_t lenMex;
    uint8_t fl;

    int pos=0;

    memcpy(&opcodeMex,buffer,SIZE_OPCODE);
    pos+=SIZE_OPCODE;

    if (opcodeMex == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

	if(opcodeMex != OPCODE_AVAILABLE_USER_LIST){
		return false;
	}

    memcpy(&seqNumMex,buffer+pos,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    memcpy(&lenMex,buffer+pos,SIZE_LEN);
    pos+=SIZE_LEN;
    list_len=lenMex;
    memcpy(&fl,buffer+pos,SIZE_LAST_FLAG);
    pos+=SIZE_LAST_FLAG;
    flag=fl;
    memcpy(available_users,buffer+pos,lenMex);
    pos+=lenMex;


	printf("------User List Check------\n");
	printf("OPCODE -> %u.\n",opcodeMex);
	printf("SEQ.NUM EXP = %u; RCV = %u.\n",exp_seq_numb,seqNumMex);
	printf("LUNGHEZZA CHUNK = %u.\n",lenMex);
	printf("MESSAGE LENGTH = %d\n",messageLength);
	printf("POS = %d\n",pos);
	printf("---------------------------------\n");


    if((seqNumMex != exp_seq_numb) || (messageLength != pos)){
        return false;
    }
    

    return true;
}
