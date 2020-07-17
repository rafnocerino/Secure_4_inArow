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

#include "digital_signature.h"
#include "protocol_constant.h"
#include "gcm.h"

using namespace std;

void send_DHmessage_info(int socket, int pkey_len,struct sockaddr_in* sv_addr, char* username, bool serverCall){
	
	unsigned char* msg_to_sign = (unsigned char*)malloc(SIZE_OPCODE+SIZE_DH_PUBLIC_KEY_LEN);
	socklen_t len=sizeof(*sv_addr);
	int pos = 0;
	int pkey_len_mex = pkey_len;
    uint8_t op_code = OPCODE_DH_MESSAGE_INFO;
	
	memcpy(msg_to_sign,&op_code,SIZE_OPCODE);
	pos += SIZE_OPCODE;
	memcpy(msg_to_sign + pos,&pkey_len_mex,SIZE_DH_PUBLIC_KEY_LEN);
	pos += SIZE_DH_PUBLIC_KEY_LEN;
	
	if(!sendAndSignMsg(socket,username,msg_to_sign,pos,sv_addr,len,serverCall)){
		perror("There was an error during the sending of the signed DH public key.\n");
		close(socket);
		pthread_exit(NULL);
		
	}
	
	
}

void send_DHmessage(int socket,int pkey_len,struct sockaddr_in* sv_addr, unsigned char* myDHpubkey,char* username,bool serverCall){
	
	unsigned char* msg_to_sign = (unsigned char*)malloc(SIZE_OPCODE + pkey_len);
	
	socklen_t len=sizeof(*sv_addr);
	int pos = 0;
    uint8_t op_code = OPCODE_DH_MESSAGE;
    
	
	memcpy(msg_to_sign,&op_code,SIZE_OPCODE);
	pos += SIZE_OPCODE;
	memcpy(msg_to_sign + pos, myDHpubkey,pkey_len);
	pos += pkey_len;
	
	if(!sendAndSignMsg(socket,username,msg_to_sign,pos,sv_addr,len,serverCall)){
		perror("There was an error during the sending of the signed DH public key.\n");
		close(socket);
		pthread_exit(NULL);
		
	}
}

void send_signature_message(int socket,unsigned char* buffer,unsigned char* random_data,char* username,int sizeCertificate,struct sockaddr_in* address,int address_size,bool serverCall){
		
		uint8_t opcodeMex = OPCODE_SIGNATURE_MESSAGE;
		uint32_t sizeCertificateMex = sizeCertificate;
		
		int pos = 0;
		
		//Pulisco il buffer per l'invio
		memset(buffer, 0, BUF_SIZE);
		memcpy(buffer,&opcodeMex,SIZE_OPCODE);
		pos = pos + SIZE_OPCODE;
		
		memcpy(buffer + pos,&sizeCertificateMex,SIZE_CERTIFICATE_LEN);
		pos = pos + SIZE_CERTIFICATE_LEN;
		
		memcpy(buffer + pos,random_data,SIZE_RANDOM_DATA);
		pos = pos + SIZE_RANDOM_DATA;
		
		if(!sendAndSignMsg(socket,username,buffer,pos,address,address_size,serverCall)){
			perror("Errore: impossibile inviare il messaggio correttamente firmato.\n");
			close(socket);
			pthread_exit(NULL);
		}	
}

void send_certificate_message(int socket,unsigned char* certificate,int certificateLen,struct sockaddr_in* address,int address_size){
	
	unsigned char *bufferCertificateMessage = (unsigned char*)malloc(SIZE_OPCODE + certificateLen);
	uint8_t opcodeMex = OPCODE_CERTIFICATE;
	int ret = 0;
	
	memset(bufferCertificateMessage,0,SIZE_OPCODE + certificateLen);
	memcpy(bufferCertificateMessage,&opcodeMex,SIZE_OPCODE);
	memcpy(bufferCertificateMessage + SIZE_OPCODE,certificate,certificateLen);
	
	ret = sendto(socket,bufferCertificateMessage,SIZE_OPCODE + certificateLen,0,(struct sockaddr*)address,sizeof(*address)); 
	
	free(bufferCertificateMessage);
	
	if(ret < SIZE_OPCODE + certificateLen){
		perror("Errore: impossibile inviare il messaggio contente il certificato.\n"); 
		close(socket);
		pthread_exit(NULL);
	}
}

void send_login(int socket,unsigned char* buffer,char* username,uint8_t len,sockaddr_in* sv_addr_main,int addr_main){
	uint8_t opcode = OPCODE_LOGIN;
	uint8_t lenMex = len;
	int pos = 0;	

	memcpy(buffer,&opcode,SIZE_OPCODE);
	pos += SIZE_OPCODE;
	
	memcpy(buffer + pos,&lenMex,SIZE_LEN);
	pos += SIZE_LEN;

	memcpy(buffer + pos,username,len);
	pos += len;
	
	int ret = sendto(socket,buffer,pos,0,(struct sockaddr*)sv_addr_main,addr_main);	

	if(ret < pos){
		perror("Errore: impossibile inviare il messaggio di login.\n");
		close(socket);
		pthread_exit(NULL);
	}
}

/*--------------------------Messaggi-che-richiedono-cifratura:--------------------------------------------------------------------*/

void send_exit(int socket, unsigned char* buffer,char* username, uint8_t seqNum,sockaddr_in* sv_addr_priv,int addr_size,unsigned char *key){

    uint8_t opcode = OPCODE_EXIT;
	uint8_t seqNumMex = seqNum;
	uint8_t lenMex = strlen(username) + 1;
	int pos = 0;
	memset(buffer,0,BUF_SIZE);

    memcpy(buffer,&opcode,SIZE_OPCODE);
    pos+=SIZE_OPCODE;
    memcpy(buffer+pos,&seqNumMex,SIZE_SEQNUMBER);
    pos+=SIZE_SEQNUMBER;
    memcpy(buffer+pos,&lenMex,SIZE_LEN);
    pos+=SIZE_LEN;
    memcpy(buffer+pos,username,lenMex);
	pos+=lenMex;
    
	struct cipher_txt c;
   
	gcm_encrypt(buffer,pos,key,&c);

	int ret = sendto(socket,c.all,c.all_len,0,(struct sockaddr*)sv_addr_priv,addr_size);

	if(ret < pos){
		perror("Errore: impossibile inviare il messaggio di exit.\n");
		close(socket);
		pthread_exit(NULL);
	}
}

void send_challengeStart(int socket,unsigned char* buffer,char* ip,unsigned char* public_key,uint8_t seqNum,sockaddr_in* client_addr,int addr_size,unsigned char *key){
	uint8_t opcode = OPCODE_CHALLENGE_START;
	uint8_t seqNumMex = seqNum;
	uint8_t lenMex = strlen(ip) + 1;
	int pos = 0;
	memset(buffer,0,BUF_SIZE);
	
	memcpy(buffer + pos,&opcode,SIZE_OPCODE);
	pos += SIZE_OPCODE;
	
	memcpy(buffer + pos,&seqNumMex,SIZE_SEQNUMBER);
	pos += SIZE_SEQNUMBER;

	memcpy(buffer + pos,&lenMex,SIZE_LEN);
	pos += SIZE_LEN;
	
	memcpy(buffer + pos,public_key,SIZE_PUBLIC_KEY);
	pos += SIZE_PUBLIC_KEY;

	memcpy(buffer + pos,ip,lenMex);
	pos += lenMex;

	struct cipher_txt c;
	
	gcm_encrypt(buffer,pos,key,&c);

	int ret = sendto(socket,c.all,c.all_len,0,(struct sockaddr*)client_addr,addr_size);

	if(ret < pos){
		perror("Errore: impossibile inviare il messaggio di challenge start.\n");
		close(socket);
		pthread_exit(NULL);
	}
}

void send_challengeUnavailable(int socket, unsigned char* buffer, uint8_t seqNum, sockaddr_in* clientAddress, int clientAddressLen,unsigned char *key){
	int pos = 0;
	int ret;

	uint8_t opcodeMex = OPCODE_CHALLENGE_UNAVAILABLE;
	uint8_t seqNumMex = seqNum;
	
	memset(buffer,0,BUF_SIZE);

	memcpy(buffer + pos,&opcodeMex,SIZE_OPCODE);
	pos += SIZE_OPCODE;

	memcpy(buffer + pos,&seqNumMex,SIZE_SEQNUMBER);
	pos += SIZE_SEQNUMBER;
	
	struct cipher_txt c;
	
	gcm_encrypt(buffer,pos,key,&c);
	
	ret = sendto(socket,c.all,c.all_len,0,(struct sockaddr*)clientAddress,clientAddressLen);
	
	if(ret < (int)SIZE_MESSAGE_CHALLENGE_UNAVAILABLE){
		perror("There was an error during the sending of the sending of the challenge unavailable message. \n");
		close(socket);
		pthread_exit(NULL);
	}	
}

void send_AvailableUserListChunk(int socket,unsigned char* buffer,uint8_t seq_numb,uint8_t len,bool lastFlag,char* chunk,sockaddr_in* client_addr, int addr_size,unsigned char *key){

	printf("Addr. size -> %d.\n",addr_size);
	printf("Porta -> %u.\n",client_addr->sin_port);
	printf("Indirizzo -> %s.\n",inet_ntoa(client_addr->sin_addr));
	int pos = 0;
    uint8_t seqNumMex = seq_numb;
    uint8_t opcodeMex = OPCODE_AVAILABLE_USER_LIST;
    uint8_t lastFlagMex = lastFlag == true ? 1 : 0;
    uint8_t lenMex = len;
	memset(buffer, 0, BUF_SIZE);
	memcpy(buffer, &opcodeMex, SIZE_OPCODE);
    pos += SIZE_OPCODE;
	memcpy(buffer + pos, &seqNumMex, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
	memcpy(buffer + pos, &lenMex, SIZE_LEN);
    pos += SIZE_LEN;
	memcpy(buffer + pos, &lastFlagMex, SIZE_LAST_FLAG);
    pos += SIZE_LAST_FLAG;	
    memcpy(buffer + pos, chunk, lenMex);
    pos += lenMex;

	printf("pos -> %d.\n",pos);
	BIO_dump_fp(stdout,(const char*)buffer,pos);

	struct cipher_txt c;
	
	gcm_encrypt(buffer,pos,key,&c);

	int ret = sendto(socket,c.all,c.all_len,0,(struct sockaddr*)client_addr, sizeof(*client_addr));
	
	if(ret < pos){
		perror("There was an error during the sending of the chunk.\n");
		close(socket);
		pthread_exit(NULL);
	}
}

void send_UpdateStatus(int socket, unsigned char* buffer,const char* username, uint8_t user_size, uint8_t op_code, uint8_t seq_numb, uint8_t status_code,
                       sockaddr_in* sv_addr, int addr_size,unsigned char *key){
    int pos = 0;
    uint8_t seqNumMex = seq_numb;
    uint8_t opcodeMex = OPCODE_UPDATE_STATUS;
    uint8_t statusCodeMex =status_code;
    uint8_t lenMex = user_size;
    

    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcodeMex, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seqNumMex, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    memcpy(buffer + pos, &statusCodeMex, SIZE_STATUS_CODE);
    pos += SIZE_STATUS_CODE;
    memcpy(buffer + pos, &lenMex, SIZE_LEN);
    pos += SIZE_LEN;
    memcpy(buffer + pos, username,lenMex);
    pos += lenMex;
    
    struct cipher_txt c;
	
	gcm_encrypt(buffer,pos,key,&c);
    
    int ret = sendto(socket, c.all, c.all_len, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the update status msg \n");
        close(socket);
        pthread_exit(NULL);
    }
}


void send_ACK(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size,unsigned char *key){
    int pos = 0;
    int ret;
    uint8_t seqNumMex = seq_numb;
    uint8_t opcodeMex = OPCODE_ACK;

    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcodeMex, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seqNumMex, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    
    struct cipher_txt c;
    
    gcm_encrypt(buffer,pos,key,&c);

    ret = sendto(socket, c.all, c.all_len, 0, (struct sockaddr*)sv_addr, addr_size);
	
	printf("ret -> %d\n",ret);
	//BIO_dump_fp(stdout,(const char*)c.all,c.all_len);
	BIO_dump_fp(stdout,(const char*)buffer,pos);
	printf("Sono la porta magica %d\n",sv_addr->sin_port);
    if (ret < (int)SIZE_MESSAGE_ACK) {
        perror("There was an error during the sending of the ACK \n");
        close(socket);
        pthread_exit(NULL);
    }
}

void send_challengeAccepted(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr_challenging, int addr_size,int challenge_id,unsigned char *key){
    uint8_t opcode = OPCODE_CHALLENGE_ACCEPTED;
    uint8_t seqnumb = seq_numb;
    int pos = 0;
    int id = challenge_id;

    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcode, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seqnumb, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    memcpy(buffer + pos, &id, sizeof(id));
    pos += sizeof(id);

    struct cipher_txt c;
    
    gcm_encrypt(buffer,pos,key,&c);

    int ret = sendto(socket, c.all, c.all_len, 0, (struct sockaddr*)sv_addr_challenging, addr_size);
    if (ret < SIZE_MESSAGE_CHALLENGE_ACCEPTED) {
        perror("There was an error during the sending of the challenge accepted msg ! \n");
        pthread_exit(NULL);
    }
}

void send_malformedMsg(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size,unsigned char *key){
    int pos = 0;
    uint8_t opcodeMex = OPCODE_MALFORMED_MEX;
    uint8_t seqNumMex = seq_numb;

    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &opcodeMex, SIZE_OPCODE);
    pos += SIZE_OPCODE;

    memcpy(buffer + pos, &seq_numb, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;

    struct cipher_txt c;
    
    gcm_encrypt(buffer,pos,key,&c);

    int ret = sendto(socket, c.all, c.all_len, 0, (struct sockaddr*)sv_addr, addr_size);

	close(socket);

    if (ret < (int)SIZE_MESSAGE_MALFORMED_MEX) {
        perror("There was an error during the sending of the malformed msg ! \n");
        pthread_exit(NULL);
    }
}

void send_challengeRefused(int socket, unsigned char* buffer, uint8_t seq_numb, int challenge_id, sockaddr_in* sv_addr_challenge, int addr_size,unsigned char *key) {
    uint8_t op_code = OPCODE_CHALLENGE_REFUSED;
    uint8_t seqnumb = seq_numb;
    int id = challenge_id;
    int pos = 0;

    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &op_code, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seqnumb, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    memcpy(buffer + pos, &id, sizeof(id));
    pos += sizeof(id);

	struct cipher_txt c;
    
    gcm_encrypt(buffer,pos,key,&c);

    int ret = sendto(socket,c.all, c.all_len, 0, (struct sockaddr*)sv_addr_challenge, addr_size);
    if (ret < SIZE_MESSAGE_CHALLENGE_REFUSED) {
        perror("There was an error during the sending of the malformed msg ! \n");
        pthread_exit(NULL);
    }
}

void send_challengeRequest(int socket, struct sockaddr_in* sv_addr, int addr_size, unsigned char* buffer, const char* challenger, char* challenged,uint8_t seq_numb, int challenge_id,unsigned char *key) {
    uint8_t op_code = OPCODE_CHALLENGE_REQUEST;
    uint8_t seq = seq_numb;
    int id = challenge_id;

    int pos = 0;
    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &op_code, SIZE_OPCODE);
    pos += SIZE_OPCODE;
    memcpy(buffer + pos, &seq, SIZE_SEQNUMBER);
    pos += SIZE_SEQNUMBER;
    memcpy(buffer + pos, &id, SIZE_CHALLENGE_NUMBER);
    pos += SIZE_CHALLENGE_NUMBER;

    char data[255];
    strcpy(data, challenger);
    strcat(data, ";");
    strcat(data, challenged);

    uint8_t data_len = strlen(data)+1;

    memcpy(buffer + pos, &data_len, SIZE_LEN);
    pos += SIZE_LEN;
    memcpy(buffer + pos, data, data_len);
    pos += data_len;

	struct cipher_txt c;
    
    gcm_encrypt(buffer,pos,key,&c);

    int ret = sendto(socket,c.all,c.all_len, 0, (struct sockaddr*)sv_addr, addr_size);
    
    if (ret < pos) {
        perror("There was an error during the sending of the challenge request ! \n");
        close(socket);
        pthread_exit(NULL);
    }
}
