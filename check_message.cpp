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

#include "gcm.h"
#include "protocol_constant.h"
using namespace std;



bool check_login(int socket,unsigned char* message, int messageLength,char* username) {
   
	uint8_t actualOpcode;
    uint8_t actualLength;

    memcpy(&actualOpcode, message, SIZE_OPCODE);
    
    if (actualOpcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

    if (actualOpcode != OPCODE_LOGIN) 
		return false;

    memcpy(&actualLength, message + SIZE_OPCODE, SIZE_LEN);


    if (actualLength != messageLength - (SIZE_OPCODE  + SIZE_LEN))  
        return false;
	
	memcpy(username,message + SIZE_OPCODE + SIZE_LEN, messageLength - (SIZE_OPCODE + SIZE_LEN));
    return true;
}

bool check_ack(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb, unsigned char*  key){
    uint8_t rcv_seq_numb;
    uint8_t rcv_opcode;
    int pos = 0;
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc(SIZE_OPCODE + SIZE_SEQNUMBER);


    check=gcm_decrypt(key,buffer,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the ack has given negative result.\n");
		return false;
	}
	
	memcpy(&rcv_opcode, plaintext, SIZE_OPCODE);
    pos += SIZE_OPCODE;

	if(rcv_opcode != exp_opcode){
		free(plaintext);
		return false;
	}
   

    memcpy(&rcv_seq_numb, plaintext + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
   
	
	printf("-----------------------------------------\n");
	printf("OPCODE -> Exp. = %u ; Rcv = %u.\n",exp_opcode,rcv_opcode);
	printf("Message length = %d.\n",messageLength);
	printf("ACK -> Exp. s.n. = %u ; Rcv s.n. = %u\n",exp_seq_numb,rcv_seq_numb);
	printf("-----------------------------------------\n");

    if (rcv_opcode == OPCODE_MALFORMED_MEX) {
		free(plaintext);
        // this means that the msg that i sent was modified during the forwarding
		printf("Received malformed message !.\n");
        close(socket);
        pthread_exit(NULL);
    }

    if ( (rcv_seq_numb != exp_seq_numb) || (messageLength != SIZE_MESSAGE_ACK)) {
        printf("Received altered ack message.\n");
		free(plaintext);
		return false;
    }
	
	free(plaintext);
    return true;
}


bool check_challengeRequest(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,char* challenging_user, int& challenge_id, uint8_t& rcv_seq_numb,char* challengedUser,unsigned char* key){
    uint8_t rcv_opcode;
    int pos = 0;
    uint8_t data_len;
    uint8_t seq;
    int id;
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (messageLength - SIZE_TAG - SIZE_IV);


    check=gcm_decrypt(key,buffer,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the challenge request has given negative result.\n");
		return false;
	}
	
	
    memcpy(&rcv_opcode, plaintext, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    
	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        // this means that the msg that i sent was modified during the forwarding
		free(plaintext);
        close(socket);
        pthread_exit(NULL);
    }

	if (rcv_opcode != exp_opcode){
		free(plaintext);
        return false;
    }

    memcpy(&seq, plaintext + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    rcv_seq_numb = seq;

    memcpy(&id, plaintext + pos, SIZE_CHALLENGE_NUMBER);
    pos += SIZE_CHALLENGE_NUMBER;
    challenge_id = id;

    memcpy(&data_len, plaintext + pos, SIZE_LEN);
    pos += sizeof(data_len);

    memcpy(challenging_user,plaintext+pos,data_len);
    pos+=data_len;

    strtok((char*)challenging_user, ";");
   

    int flush_len = strlen((char*)challenging_user) + 1;
	
	if(challengedUser != NULL){
		memcpy(challengedUser,challenging_user + flush_len,flush_len);
		printf("-> challenged user: %s.\n",challengedUser);
	}	
	
    memset(challenging_user + flush_len, 0, 255 - flush_len);

    messageLength -= SIZE_TAG + SIZE_IV;

    //prestare attenzione alla formula per il controllo della len
    if(data_len != messageLength - SIZE_OPCODE - SIZE_SEQNUMBER - SIZE_CHALLENGE_NUMBER - SIZE_LEN ){
		
		free(plaintext);
        return false;
    }
	
	free(plaintext);
    return true;
}

bool check_challengeUnavailable(int socket, unsigned char* buffer, int messageLength, uint8_t exp_seq_numb, unsigned char* key) {
    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    int pos = 0;
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (SIZE_MESSAGE_CHALLENGE_UNAVAILABLE);


    check=gcm_decrypt(key,buffer,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the challenge unavailable has given negative result.\n");
		return false;
	}
	
	
    memcpy(&rcv_opcode, plaintext, SIZE_OPCODE);
    pos += SIZE_OPCODE;
   
	if(rcv_opcode == OPCODE_MALFORMED_MEX) {
		
		free(plaintext);
        printf("Received a malformed message ! \n");
		close(socket);
        pthread_exit(NULL);
    	}

	if(rcv_opcode != OPCODE_CHALLENGE_UNAVAILABLE){
		free(plaintext);
		return false;
	}	

    memcpy(&rcv_seq_numb, plaintext + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;


    if ((exp_seq_numb != rcv_seq_numb) || messageLength != SIZE_MESSAGE_CHALLENGE_UNAVAILABLE) {
		free(plaintext);
        return false;
    }
	
	free(plaintext);
    return true;
}

bool check_challengeRefused(int socket,unsigned char* buffer, int messageLength,uint8_t exp_seq_numb,int *challengeId,unsigned char* key){
    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    int pos = 0;
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (SIZE_MESSAGE_CHALLENGE_REFUSED);


    check=gcm_decrypt(key,buffer,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the challenge refused has given negative result.\n");
		return false;
	}
	
    memcpy(&rcv_opcode, plaintext, SIZE_OPCODE);
    pos += SIZE_OPCODE;

	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
        close(socket);
        pthread_exit(NULL);
    }

	if(rcv_opcode != OPCODE_CHALLENGE_REFUSED){
		free(plaintext);
		return false;
	}
    
    memcpy(&rcv_seq_numb, plaintext + pos, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
   
	memcpy(challengeId,plaintext + pos,SIZE_CHALLENGE_NUMBER);
	pos += SIZE_CHALLENGE_NUMBER;

     if ((exp_seq_numb != rcv_seq_numb) || (messageLength != SIZE_MESSAGE_CHALLENGE_REFUSED)) {
        free(plaintext);
		return false;
    }
	
	free(plaintext);
    return true;
}

bool check_challengeStart(int socket,unsigned char* buffer, int messageLength,uint8_t exp_seq_numb,unsigned char* ip,unsigned char* adv_pubkey,unsigned char* key){

    uint8_t rcv_opcode;
    uint8_t rcv_seq_numb;
    uint8_t len;
    int pos=0;
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (messageLength - SIZE_TAG - SIZE_IV);


    check=gcm_decrypt(key,buffer,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the challenge start has given negative result.\n");
		return false;
	}
	
    memcpy(&rcv_opcode,plaintext,SIZE_OPCODE);
    pos+=SIZE_OPCODE;

	if (rcv_opcode == OPCODE_MALFORMED_MEX) {
		free(plaintext);
        close(socket);
        pthread_exit(NULL);
    }

	if(rcv_opcode != OPCODE_CHALLENGE_START){
		free(plaintext);
		return false;
	}

    memcpy(&rcv_seq_numb,plaintext+pos,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    memcpy(&len,plaintext+pos,SIZE_LEN);
    pos+=SIZE_LEN;
    memcpy(adv_pubkey,plaintext+pos,SIZE_PUBLIC_KEY);
    pos+=SIZE_PUBLIC_KEY;
    memcpy(ip,plaintext+pos,len);
    pos+=len;

	printf("------Challenge Start Check------\n");
	printf("OPCODE -> %u.\n",rcv_opcode);
	printf("SEQ.NUM EXP = %u; RCV = %u.\n",exp_seq_numb,rcv_seq_numb);
	printf("LUNGHEZZA IP = %u.\n",len);
	printf("MESSAGE LENGTH = %d\n",messageLength);
	printf("POS = %d\n",pos);
	printf("---------------------------------\n");
	

    messageLength -= SIZE_TAG + SIZE_IV;

    if((rcv_seq_numb != exp_seq_numb) || (messageLength != pos)){
		free(plaintext);
        return false;
    }
    
	free(plaintext);
    return true;
}

bool check_updateStatus(int socket,unsigned char* message,int messageLength,uint8_t expectedSeqNum,uint8_t& statusCode,char* username, unsigned char* key){
	
	uint8_t opcodeMex;
	uint8_t seqNumMex;
	uint8_t statusCodeMex;
	uint8_t lenMex;
	
	int pos = 0;	
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (messageLength - SIZE_IV - SIZE_TAG);


    check=gcm_decrypt(key,message,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the update status has given negative result.\n");
		return false;
	}
	
	memcpy(&opcodeMex,plaintext,SIZE_OPCODE);
	pos += SIZE_OPCODE;

	if(opcodeMex == OPCODE_MALFORMED_MEX){
		free(plaintext);
		close(socket);		
		pthread_exit(NULL);
	}

	//Controllo del opcode	
	if(opcodeMex != OPCODE_UPDATE_STATUS){
		free(plaintext);
		return false;
	}
	memcpy(&seqNumMex,plaintext + pos,SIZE_SEQNUMBER);
	pos += SIZE_SEQNUMBER;

	memcpy(&statusCodeMex,plaintext + pos,SIZE_STATUS_CODE);
	pos += SIZE_STATUS_CODE;
	statusCode = statusCodeMex;
		
	memcpy(&lenMex,plaintext + pos,SIZE_LEN);
	pos += SIZE_LEN;


	memcpy(username,plaintext + pos,lenMex);
	pos += lenMex;


	printf("opcode -> %u\n",opcodeMex);
	printf("RCV S.N. -> %u | EX. S.N. -> %u \n",seqNumMex,expectedSeqNum);
	printf("status code -> %u\n",statusCodeMex);
	printf("LEN -> %u\n",lenMex);
	printf("Username -> %s \n",username);
	printf("messageLenght -> %d\n", messageLength);

	//Controllo della lunghezza del messaggio
	/*if(messageLength <= ( SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_STATUS_CODE + SIZE_LEN ) || messageLength > SIZE_MESSAGE_UPDATE_STATUS){
		free(plaintext);
		return false;
	}*/
	
	messageLength -= SIZE_IV + SIZE_TAG;

	if(seqNumMex != expectedSeqNum){
		free(plaintext);
		return false;
	}
	
	//Controllo dello status code
	if(statusCodeMex != STATUS_CHALLENGING && statusCodeMex != STATUS_IDLE && statusCodeMex != STATUS_WAITING){
		free(plaintext);
		return false;
	}
	

	if(messageLength != SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_STATUS_CODE + SIZE_LEN + lenMex){
		free(plaintext);
		return false;
	}
	
	free(plaintext);
	return true;
}

bool check_exit(int socket,unsigned char* message,int messageLength,uint8_t expectedSeqNum,char* username,unsigned char* key){
	uint8_t actualOpcode = 10;
	uint8_t actualSeqNum = 10;
	uint8_t actualLength = 10;
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (messageLength - SIZE_IV - SIZE_TAG);


    check=gcm_decrypt(key,message,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the challenge exit has given negative result.\n");
		return false;
	}
	
	memcpy(&actualOpcode,plaintext,SIZE_OPCODE);

	if(actualOpcode == OPCODE_MALFORMED_MEX){
		free(plaintext);
		close(socket);
		pthread_exit(NULL);
	}

	if(actualOpcode != OPCODE_EXIT){
		free(plaintext);
		return false;
	}


	memcpy(&actualSeqNum,plaintext + SIZE_OPCODE, SIZE_SEQNUMBER);
	memcpy(&actualLength,plaintext + SIZE_OPCODE + SIZE_SEQNUMBER, SIZE_LEN);
	memcpy(username,plaintext + SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN, actualLength);

	printf("-------Check-exit-------------------------\n");
	printf("S.N. EXP = %u | RCV. = %u \n",expectedSeqNum,actualSeqNum);
	printf("Message Recived Lenght = %d\n",messageLength);
	printf("Lenght username = %u\n", actualLength);
	printf("---------------------------------------\n");
	
	messageLength -= SIZE_IV + SIZE_TAG;

	if(actualSeqNum != expectedSeqNum){
		free(plaintext);
		return false;
	}
	
	
	if(actualLength != messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN)){  
		free(plaintext);
		return false;
	}

	free(plaintext);
	return true;
}

bool check_challengeAccepted(int socket,unsigned char* buffer,int messageLength,uint8_t expectedSeqNum,int* challengeNumber, unsigned char* key){
	uint8_t actualOpcode;
	uint8_t seqNumMex;
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (SIZE_MESSAGE_CHALLENGE_ACCEPTED);


    check=gcm_decrypt(key,buffer,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the challenge accepted has given negative result.\n");
		return false;
	}
	
	memcpy(&actualOpcode,plaintext,SIZE_OPCODE);

	if(actualOpcode == OPCODE_MALFORMED_MEX){
		free(plaintext);
		close(socket);
		pthread_exit(NULL);
	}	

	if(actualOpcode != OPCODE_CHALLENGE_ACCEPTED){
		free(plaintext);
		return false;
	}
	
	memcpy(&seqNumMex,plaintext + SIZE_OPCODE,SIZE_SEQNUMBER);
	if(seqNumMex != expectedSeqNum){
		free(plaintext);
		return false;
	}
	
	if(messageLength != SIZE_MESSAGE_CHALLENGE_ACCEPTED){
		free(plaintext);
		return false;
	}

	memcpy(challengeNumber, plaintext + SIZE_OPCODE + SIZE_SEQNUMBER, SIZE_CHALLENGE_NUMBER);
	
	free(plaintext);
	return true;
}

bool check_available_userList(int socket, unsigned char* buffer,int& list_len,int messageLength,uint8_t exp_seq_numb,char* available_users,int& flag, unsigned char* key){

    uint8_t opcodeMex;
	uint8_t seqNumMex;
	uint8_t lenMex;
    uint8_t fl;

    int pos=0;
	
	bool check;
	unsigned char* plaintext = (unsigned char*) malloc (messageLength - SIZE_TAG - SIZE_IV);


    check=gcm_decrypt(key,buffer,messageLength,plaintext);	
	if(!check){
		
		free(plaintext);
		printf("The decryption of the available user list has given negative result.\n");
		return false;
	}

    memcpy(&opcodeMex,plaintext,SIZE_OPCODE);
    pos+=SIZE_OPCODE;

    if (opcodeMex == OPCODE_MALFORMED_MEX) {
		free(plaintext);
        close(socket);
        pthread_exit(NULL);
    }

	if(opcodeMex != OPCODE_AVAILABLE_USER_LIST){
		free(plaintext);
		return false;
	}

    memcpy(&seqNumMex,plaintext+pos,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    memcpy(&lenMex,plaintext+pos,SIZE_LEN);
    pos+=SIZE_LEN;
    list_len=lenMex;
    memcpy(&fl,plaintext+pos,SIZE_LAST_FLAG);
    pos+=SIZE_LAST_FLAG;
    flag=fl;
    memcpy(available_users,plaintext+pos,lenMex);
    pos+=lenMex;


	printf("------User List Check------\n");
	printf("OPCODE -> %u.\n",opcodeMex);
	printf("SEQ.NUM EXP = %u; RCV = %u.\n",exp_seq_numb,seqNumMex);
	printf("LUNGHEZZA CHUNK = %u.\n",lenMex);
	printf("MESSAGE LENGTH = %d\n",messageLength);
	printf("POS = %d\n",pos);
	printf("---------------------------------\n");

    messageLength -= SIZE_TAG + SIZE_IV; 

    if((seqNumMex != exp_seq_numb) || (messageLength != pos)){
		free(plaintext);
        return false;
    }
    
	free(plaintext);
    return true;
}

bool check_signature_message_server(unsigned char* buffer,int messageLength,unsigned char* expectedRandomData){
	uint8_t opcodeMex = 0;
	int clearMessageSize = messageLength - SIZE_SIGNATURE;
	unsigned char* randomDataMex = (unsigned char*)malloc(SIZE_RANDOM_DATA);
	memset(randomDataMex,0,SIZE_RANDOM_DATA);
	memcpy(&opcodeMex,buffer,SIZE_OPCODE);
	if(opcodeMex != OPCODE_SIGNATURE_MESSAGE){
		return false;
	}
	memcpy(randomDataMex,buffer + SIZE_OPCODE + SIZE_CERTIFICATE_LEN, SIZE_RANDOM_DATA);
	if(memcmp(expectedRandomData,randomDataMex,SIZE_RANDOM_DATA) != 0){
		return false;
	}
	free(randomDataMex);
	return true;
}

bool check_certificateMessage(unsigned char* certificate_buffer,int messageLength,int cert_len){
	int pos = 0;
	uint8_t rcv_opcode;
	memcpy(&rcv_opcode,certificate_buffer,SIZE_OPCODE);
	pos += SIZE_OPCODE;
	
	if(messageLength != cert_len + SIZE_OPCODE){
		return false;
	}	
	
	if(rcv_opcode != OPCODE_CERTIFICATE){
		return false;
	}
	
	return true;
}

bool check_signatureMessageClient(unsigned char* buffer,int messageLength,unsigned char* random_data,unsigned char* signature){
	
	int pos = 0;
	uint8_t rcv_opcode;
	
	memcpy(&rcv_opcode,buffer,SIZE_OPCODE);
	pos = pos + SIZE_OPCODE + SIZE_CERTIFICATE_LEN;
	
	memcpy(random_data,buffer + pos,SIZE_RANDOM_DATA);
	pos = pos + SIZE_RANDOM_DATA;
	
	memcpy(signature,buffer + pos,SIZE_SIGNATURE);
	
	if(messageLength != SIZE_MESSAGE_SIGNATURE_MESSAGE){
		return false;
	}	
	
	if(rcv_opcode != OPCODE_SIGNATURE_MESSAGE){
		return false;
	}
	
	return true;
}

bool check_DHmessage(unsigned char* buffer,int messageLength,int pkey_len,unsigned char* peer_dh_pubkey){
	
	int pos = 0;
	uint8_t rcv_opcode;
	
	
	memcpy(&rcv_opcode,buffer,SIZE_OPCODE);
	pos+=SIZE_OPCODE;
	
	memcpy(peer_dh_pubkey,buffer+pos,pkey_len);
	pos+=pkey_len;
	
	if(rcv_opcode != OPCODE_DH_MESSAGE){
		return false;
	}
	
	if( messageLength != SIZE_OPCODE + SIZE_SIGNATURE + pkey_len){
		return false;
	}
	
	return true;
	
}

bool check_DHmessage_info(unsigned char* buffer, int messageLength,int& pkey_len){
	
	int pos =0;
	uint8_t rcv_opcode;
	int pkey_lenMex;
	
	memcpy(&rcv_opcode,buffer,SIZE_OPCODE);
	pos+=SIZE_OPCODE;
	memcpy(&pkey_lenMex,buffer + pos, SIZE_DH_PUBLIC_KEY_LEN);
	pos+=SIZE_DH_PUBLIC_KEY_LEN;
	pkey_len = pkey_lenMex;
	
	if(rcv_opcode != OPCODE_DH_MESSAGE_INFO){
		return false;
	}
	
	if( messageLength != SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN + SIZE_SIGNATURE){
		return false;
	}
	
	return true;
}

bool check_FirstAvailable_userList(int socket, unsigned char* buffer,int& list_len,int messageLength,uint8_t& seq_numb,char* available_users,int& flag, unsigned char* key){
    
    uint8_t opcodeMex;
    uint8_t seqNumMex;
    uint8_t lenMex;
    uint8_t fl;

 

    int pos=0;
    
    bool check;
    unsigned char* plaintext = (unsigned char*) malloc (messageLength - SIZE_TAG - SIZE_IV);

 


    check=gcm_decrypt(key,buffer,messageLength,plaintext);    
    if(!check){
        
        free(plaintext);
        printf("The decryption of the available user list has given negative result.\n");
        return false;
    }

 

    memcpy(&opcodeMex,plaintext,SIZE_OPCODE);
    pos+=SIZE_OPCODE;

 

    if (opcodeMex == OPCODE_MALFORMED_MEX) {
        free(plaintext);
        close(socket);
        pthread_exit(NULL);
    }

 

    if(opcodeMex != OPCODE_AVAILABLE_USER_LIST){
        free(plaintext);
        return false;
    }

 

    memcpy(&seqNumMex,plaintext+pos,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    seq_numb=seqNumMex;
    
    memcpy(&lenMex,plaintext+pos,SIZE_LEN);
    pos+=SIZE_LEN;
    list_len=lenMex;
    memcpy(&fl,plaintext+pos,SIZE_LAST_FLAG);
    pos+=SIZE_LAST_FLAG;
    flag=fl;
    memcpy(available_users,plaintext+pos,lenMex);
    pos+=lenMex;

 


    printf("------User List Check------\n");
    printf("OPCODE -> %u.\n",opcodeMex);
    printf("LUNGHEZZA CHUNK = %u.\n",lenMex);
    printf("MESSAGE LENGTH = %d\n",messageLength);
    printf("POS = %d\n",pos);
    printf("---------------------------------\n");

 

    messageLength -= SIZE_TAG + SIZE_IV; 

 

    if(messageLength != pos){
        free(plaintext);
        return false;
    }
    
    free(plaintext);
    return true;
}
