#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <sys/socket.h> 
#include <arpa/inet.h>
#include <netinet/in.h> 

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <semaphore.h>
#include <vector>
#include <pthread.h>
#include <cstdint>
#include <math.h>
#include <stdint.h>

#include <unistd.h>

#include "protocol_constant.h"
#include "send_message.h"
#include "digital_signature.h"
#include "check_message.h"
using namespace std;

// Funzione per la rimozione 

bool removeFile(const char* fileName){
	if(remove(fileName) == 0){
		return true;
	}
	return false;
}

int serialize_PEM_Pub_Key(EVP_PKEY* pubkey,unsigned char** pubkeyBuffer){
	BIO* mbio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(mbio,pubkey);
	int ret = BIO_get_mem_data(mbio,pubkeyBuffer);
	return ret;
}

EVP_PKEY* deserialize_PEM_pubkey(int pubkeySize,unsigned char* pubkey_buf){
	BIO* mbio = BIO_new(BIO_s_mem());
	BIO_write(mbio,pubkey_buf,pubkeySize);
	EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(mbio,NULL,NULL,NULL);
	return pubkey;
}

void sharedSecretCreationDH(int sd, struct sockaddr_in* opposite_addr, bool first,char* username,EVP_PKEY* oppositeKey,unsigned char* sharedSecret,unsigned int& sharedSecretLen){
  
  
  
  int ret; 
  bool check;
  unsigned char buffer[BUF_SIZE];
  struct timeval time;
  socklen_t size = sizeof(*opposite_addr);
  int received;
  
  time.tv_sec=30;
  time.tv_usec=0;
  setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));
 
 /* GENERATE KEY */
  printf("-------STARTING DH PROTOCOL TO DERIVE SHARED KEY !---------\n");
 EVP_PKEY *params;

 
 params = EVP_PKEY_new();
 
 
 if(params == NULL) {
	perror("Error during the memory allocation for DH parameters ! \n");
	close(sd);
	pthread_exit(NULL);
 }

	 
 if(1 != EVP_PKEY_set1_DH(params,DH_get_2048_224())){
	perror("Error during the creation of DH parameters ! \n");
	close(sd);
	pthread_exit(NULL);
 }

	 
 // Create context for the key generation 
 EVP_PKEY_CTX *DHctx = EVP_PKEY_CTX_new(params, NULL);
 if(!DHctx){
	perror("Error during the creation of the context for the key generation ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
 /* Generate a new key */
 EVP_PKEY *my_dhkey = NULL;
 
 if(EVP_PKEY_keygen_init(DHctx) != 1) {
	perror("Error during the initialization of DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
 if(EVP_PKEY_keygen(DHctx, &my_dhkey) != 1){ 
	perror("Error during the creation of DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
//Created the structure that will be used to store the peer public key 
 EVP_PKEY* peer_pubkey = EVP_PKEY_new();
 if(peer_pubkey == NULL){
	
	perror("Error during the memory allocation of peer's DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
//here i extract my dh pubkey writing it on a file
 string name = "./tmp/mydhpubkey";
 name+=reinterpret_cast<const char*>(username);
 name+=".pem";

 
 FILE* file_mydhpubkey = fopen( name.c_str(),"wb");
 if(!file_mydhpubkey){
	perror("Error during the creation of temp my DH public key file! \n");
	close(sd);
	pthread_exit(NULL);
 } 
 
  if(PEM_write_PUBKEY(file_mydhpubkey, my_dhkey)<=0){
	 perror("Error during the storing of temp my DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
  fclose(file_mydhpubkey);
 
  
  file_mydhpubkey = fopen(name.c_str(),"rb");
	if(!file_mydhpubkey){
		perror("Error during the opening of temp my DH public key file! \n");
		close(sd);
		pthread_exit(NULL);
 } 
 
 EVP_PKEY* pubkey_temp = PEM_read_PUBKEY(file_mydhpubkey,NULL,NULL,NULL);
 
 if(pubkey_temp == NULL){
	 printf("Error during the reading of th DH public key.\n");
	 close(sd);
	 pthread_exit(NULL);
 }
 
 
 
	unsigned char* my_dh_pubkey;  

	int pubkey_temp_len = serialize_PEM_Pub_Key(pubkey_temp,&my_dh_pubkey);


 fclose(file_mydhpubkey); 
 
 removeFile(name.c_str());
 
// Inizializzazione del contesto per derivare il segreto condiviso:
unsigned char *skey;
size_t skeylen;
EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_dhkey,NULL);
if(ctx_drv == NULL){
	perror("Errore: durante il protocollo DH impossibile eseguire EVP_PKEY_CTX_new.\n");
	close(sd);
	pthread_exit(NULL);
}

if(EVP_PKEY_derive_init(ctx_drv) <= 0){
	perror("Errore: durante il protocollo DH impossibile eseguire EVP_PKEY_derive_init.\n");
	close(sd);
	pthread_exit(NULL);	
}

 
 if(first){
	
	char usernameServer[] = "server"; 
	
	send_DHmessage_info(sd, pubkey_temp_len,opposite_addr, usernameServer , true);
	
	
	send_DHmessage(sd,pubkey_temp_len,opposite_addr,my_dh_pubkey,usernameServer,first);
	
	//after sending my DH pubkey, i wait for the reception of the opposite DH pubkey
	
	int pubkey_len; // contains the dimension of the opposite DH pubkey
	
	memset(buffer,0,BUF_SIZE);
	size = sizeof(*opposite_addr);
	received = recvfrom(sd,buffer,SIZE_MESSAGE_DH_MESSAGE_INFO,0,(struct sockaddr*)opposite_addr,&size);
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message info ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=check_DHmessage_info(buffer,received,pubkey_len);
	if(!check){
		
		perror("The DH message info received is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,buffer,received,NULL);
	if(!check){
		
		printf("The signature verification of the received DH message info has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}	
	
	
	//memcpy(&pubkey_len,buffer+SIZE_OPCODE,SIZE_DH_PUBLIC_KEY_LEN);

	unsigned char* temp_buf = (unsigned char*)malloc(SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE);
	
	received = recvfrom(sd,temp_buf,SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE,0,(struct sockaddr*)opposite_addr,&size);
	
	//received += SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN;
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	
	unsigned char* peer_DH_pubkey = (unsigned char*) malloc (pubkey_len);
	
	check = check_DHmessage(temp_buf,received,pubkey_len,peer_DH_pubkey);
	if(!check){
		
		printf("The structure of the received DH message is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,temp_buf,received,NULL);
	if(!check){
		
		printf("The signature verification of the received DH message has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	free(temp_buf);
	
	
	peer_pubkey = deserialize_PEM_pubkey(pubkey_len,peer_DH_pubkey);
	
	
	if(peer_pubkey == NULL ){
		
		perror("There was an error during the reading of the peer DH public key! \n");
		close(sd);
		exit(-1);
	}
	
	if (EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) <= 0) {
		
		perror("There was an error during the derive set peer! \n");
		close(sd);
		exit(-1);
	
	}
	
	//that derivation is performed in order to obtain the dimension of the shared secret
	EVP_PKEY_derive(ctx_drv, NULL, &skeylen);
	
	/*Here we allocate buffer for the shared secret*/
	skey = (unsigned char*)( malloc( int(skeylen) ) );
	if (!skey){
		
		perror("There was an error during the memory allocation for the shared secret \n");
		close(sd);
		exit(-1);
		
	}
	
	if (EVP_PKEY_derive(ctx_drv, skey, &skeylen) <= 0){
		
		perror("There was an error during the storing of the shared secret \n");
		close(sd);
		exit(-1);
	
	}
	
	
}else{
	 
	int pubkey_len; // contains the dimension of the opposite DH pubkey
	
	memset(buffer,0,BUF_SIZE);
	size = sizeof(*opposite_addr);
	received = recvfrom(sd,buffer,SIZE_MESSAGE_DH_MESSAGE_INFO,0,(struct sockaddr*)opposite_addr,&size);
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message info ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=check_DHmessage_info(buffer,received,pubkey_len);
	if(!check){
		
		perror("The DH message info received is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,buffer,received,oppositeKey);
	if(!check){
		
		printf("The signature verification of the received DH message info has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}	
	
	
	//memcpy(&pubkey_len,buffer+SIZE_OPCODE,SIZE_DH_PUBLIC_KEY_LEN);
	
	unsigned char* temp_buf = (unsigned char*)malloc(SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE);
	
	received = recvfrom(sd,temp_buf,SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE,0,(struct sockaddr*)opposite_addr,&size);
	
	//received += SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN;
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	
	unsigned char* pkeyServerBuffer = (unsigned char*)malloc(pubkey_len);
	
	check = check_DHmessage(temp_buf,received,pubkey_len,pkeyServerBuffer);
	if(!check){
		
		printf("The structure of the received DH message is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,temp_buf,SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE,oppositeKey);
	if(!check){
		
		printf("The signature verification of the received DH message has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	free(temp_buf);
	  
	 
	

	peer_pubkey = deserialize_PEM_pubkey(pubkey_len,pkeyServerBuffer);
				
	if(peer_pubkey == NULL){
		perror("Errore: durante il protocollo DH impossibile leggere da file la chiave pubblica del server.\n");
		close(sd);
		pthread_exit(NULL);
	}
				
				
	//8. Derivazione del segreto condiviso
	if (EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) <= 0){
		perror("Errore: durante il protocollo DH impossibile eseguire peer_pubkey.\n");
		close(sd);
		pthread_exit;
	}
				
	// Derivo una prima volta per conoscere la lunghezza del buffer:
	EVP_PKEY_derive(ctx_drv, NULL, &skeylen);
				
	// Alloco il buffer per il segreto condiviso
	skey = (unsigned char*)(malloc(int(skeylen)));
				
	if(!skey){
		perror("Errore: durante il protocollo DH impossibile allocare skey.\n");
		close(sd);
		pthread_exit;		
		}
				
	if(EVP_PKEY_derive(ctx_drv, skey, &skeylen) <= 0){
		perror("Errore: durante il protocollo DH impossibile eseguire EVP_PKEY_derive.\n");
		close(sd);
		pthread_exit;
	} 
				
	send_DHmessage_info(sd, pubkey_temp_len,opposite_addr, username , false);
	send_DHmessage(sd,pubkey_temp_len,opposite_addr,my_dh_pubkey,username,first);
			
 }
 
	EVP_MD_CTX* md_ctx;
	
	unsigned int digestlen;
	
	//context allocation new()
	md_ctx=EVP_MD_CTX_new();
 
	//Hashing (init+single up+finalization)
	EVP_DigestInit(md_ctx,EVP_sha256());
	EVP_DigestUpdate(md_ctx,(unsigned char*)skey,skeylen);
	EVP_DigestFinal(md_ctx,sharedSecret,&digestlen);

	sharedSecretLen = digestlen;
	
	time.tv_sec = 0;
	time.tv_usec = 0;
	
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));
	
	 //context deallocation free()
	 EVP_MD_CTX_free(md_ctx);
	 
	 EVP_PKEY_CTX_free(ctx_drv);
	 EVP_PKEY_free(peer_pubkey);
	 EVP_PKEY_free(my_dhkey);
	 EVP_PKEY_CTX_free(DHctx);
	 EVP_PKEY_free(params);
	 
	  printf("-------SHARED KEY CREATED SUCCESSFULLY !---------\n");
	 
	 return;
}


void sharedSecretCreationDH(int sd, struct sockaddr_in* opposite_addr, bool first,char* username,EVP_PKEY* oppositeKey,unsigned char* sharedSecret,unsigned int& sharedSecretLen, char* myUsername){
  
  int ret; 
  bool check;
  unsigned char buffer[BUF_SIZE];
  struct timeval time;
  socklen_t size = sizeof(*opposite_addr);
  int received;
  
  time.tv_sec=30;
  time.tv_usec=0;
  setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));
 
 /* GENERATE KEY */
 
 printf("-------STARTING DH PROTOCOL TO DERIVE SHARED KEY !---------\n");
 
 EVP_PKEY *params;

 
 params = EVP_PKEY_new();
 
 
 if(params == NULL) {
	perror("Error during the memory allocation for DH parameters ! \n");
	close(sd);
	pthread_exit(NULL);
 }

	 
 if(1 != EVP_PKEY_set1_DH(params,DH_get_2048_224())){
	perror("Error during the creation of DH parameters ! \n");
	close(sd);
	pthread_exit(NULL);
 }

	 
 // Create context for the key generation 
 EVP_PKEY_CTX *DHctx = EVP_PKEY_CTX_new(params, NULL);
 if(!DHctx){
	perror("Error during the creation of the context for the key generation ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
 /* Generate a new key */
 EVP_PKEY *my_dhkey = NULL;
 
 if(EVP_PKEY_keygen_init(DHctx) != 1) {
	perror("Error during the initialization of DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
 if(EVP_PKEY_keygen(DHctx, &my_dhkey) != 1){ 
	perror("Error during the creation of DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
//Created the structure that will be used to store the peer public key 
 EVP_PKEY* peer_pubkey = EVP_PKEY_new();
 if(peer_pubkey == NULL){
	
	perror("Error during the memory allocation of peer's DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
 
//here i extract my dh pubkey writing it on a file
 
 FILE* file_mydhpubkey = fopen("./tmp/mydhpubkey.pem","wb");
 if(!file_mydhpubkey){
	perror("Error during the creation of temp my DH public key file! \n");
	close(sd);
	pthread_exit(NULL);
 } 
 
  if(PEM_write_PUBKEY(file_mydhpubkey, my_dhkey)<=0){
	 perror("Error during the storing of temp my DH public key ! \n");
	close(sd);
	pthread_exit(NULL);
 }
 
	fclose(file_mydhpubkey);
 
  file_mydhpubkey = fopen("./tmp/mydhpubkey.pem","rb");

 
 EVP_PKEY* pubkey_temp = PEM_read_PUBKEY(file_mydhpubkey,NULL,NULL,NULL);
 
 if(pubkey_temp == NULL){
	 printf("Errore: impossibile leggere la chiave pubblica per il protocollo DH.\n");
	 close(sd);
	 pthread_exit(NULL);
 }
 
 
	unsigned char* my_dh_pubkey;  

	int pubkey_temp_len = serialize_PEM_Pub_Key(pubkey_temp,&my_dh_pubkey);


 fclose(file_mydhpubkey); 
 
 removeFile("./tmp/mydhpubkey.pem");
 
// Inizializzazione del contesto per derivare il segreto condiviso:
unsigned char *skey;
size_t skeylen;
EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_dhkey,NULL);
if(ctx_drv == NULL){
	perror("Errore: durante il protocollo DH impossibile eseguire EVP_PKEY_CTX_new.\n");
	close(sd);
	pthread_exit(NULL);
}

if(EVP_PKEY_derive_init(ctx_drv) <= 0){
	perror("Errore: durante il protocollo DH impossibile eseguire EVP_PKEY_derive_init.\n");
	close(sd);
	pthread_exit(NULL);	
}

 
 if(first){
	
	char* usernameServer = myUsername; 
	
	send_DHmessage_info(sd, pubkey_temp_len,opposite_addr, usernameServer , false);
	
	
	send_DHmessage(sd,pubkey_temp_len,opposite_addr,my_dh_pubkey,usernameServer,false);
	
	//after sending my DH pubkey, i wait for the reception of the opposite DH pubkey
	
	int pubkey_len; // contains the dimension of the opposite DH pubkey
	
	memset(buffer,0,BUF_SIZE);
	size = sizeof(*opposite_addr);
	received = recvfrom(sd,buffer,SIZE_MESSAGE_DH_MESSAGE_INFO,0,(struct sockaddr*)opposite_addr,&size);
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message info ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=check_DHmessage_info(buffer,received,pubkey_len);
	if(!check){
		
		perror("The DH message info received is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,buffer,received,oppositeKey,true);
	if(!check){
		
		printf("The signature verification of the received DH message info has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}	
	
	
	//memcpy(&pubkey_len,buffer+SIZE_OPCODE,SIZE_DH_PUBLIC_KEY_LEN)
	
	
	unsigned char* temp_buf = (unsigned char*)malloc(SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE);
	
	received = recvfrom(sd,temp_buf,SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE,0,(struct sockaddr*)opposite_addr,&size);
	
	//received += SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN;
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	
	unsigned char* peer_DH_pubkey = (unsigned char*) malloc (pubkey_len);
	
	check = check_DHmessage(temp_buf,received,pubkey_len,peer_DH_pubkey);
	if(!check){
		
		printf("The structure of the received DH message is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,temp_buf,received,oppositeKey,true);
	if(!check){
		
		printf("The signature verification of the received DH message has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	free(temp_buf);
	
	/*FILE* f = fopen("./tmp/tmp_dh_pubkey_1","wb");
	if(!f){
		perror("There was an error during the creating of temporary peer DH file ! \n");
		close(sd);
		pthread_exit(NULL);
	}
	
	ret = fwrite(buffer+SIZE_OPCODE,1,SIZE_DH_PUBLIC_KEY,f);
	if(ret < SIZE_DH_PUBLIC_KEY){
		perror("There was an error during the storing of the temp server certificate! \n");
		close(sd);
		pthread_exit(NULL);
	}
	
	fclose(f);
	
	f = fopen("./tmp/tmp_dh_pubkey_1","rb");*/
	
	peer_pubkey = deserialize_PEM_pubkey(pubkey_len,peer_DH_pubkey);
	
	/*fclose(f);
	
	removeFile("./tmp/tmp_dh_pubkey_1");*/
	
	if(peer_pubkey == NULL ){
		
		perror("There was an error during the reading of the peer DH public key! \n");
		close(sd);
		exit(-1);
	}
	
	if (EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) <= 0) {
		
		perror("There was an error during the derive set peer! \n");
		close(sd);
		exit(-1);
	
	}
	
	//that derivation is performed in order to obtain the dimension of the shared secret
	EVP_PKEY_derive(ctx_drv, NULL, &skeylen);
	
	/*Here we allocate buffer for the shared secret*/
	skey = (unsigned char*)( malloc( int(skeylen) ) );
	if (!skey){
		
		perror("There was an error during the memory allocation for the shared secret \n");
		close(sd);
		exit(-1);
		
	}
	
	if (EVP_PKEY_derive(ctx_drv, skey, &skeylen) <= 0){
		
		perror("There was an error during the storing of the shared secret \n");
		close(sd);
		exit(-1);
	
	}
	
	
}else{
	 
	int pubkey_len; // contains the dimension of the opposite DH pubkey
	
	memset(buffer,0,BUF_SIZE);
	size = sizeof(*opposite_addr);
	received = recvfrom(sd,buffer,SIZE_MESSAGE_DH_MESSAGE_INFO,0,(struct sockaddr*)opposite_addr,&size);
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message info ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=check_DHmessage_info(buffer,received,pubkey_len);
	if(!check){
		
		perror("The DH message info received is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,buffer,received,oppositeKey);
	if(!check){
		
		printf("The signature verification of the received DH message info has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}	
	
	
	//memcpy(&pubkey_len,buffer+SIZE_OPCODE,SIZE_DH_PUBLIC_KEY_LEN);
	
	unsigned char* temp_buf = (unsigned char*)malloc(SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE);
	
	received = recvfrom(sd,temp_buf,SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE,0,(struct sockaddr*)opposite_addr,&size);
	
	//received += SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN;
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	
	unsigned char* pkeyServerBuffer = (unsigned char*)malloc(pubkey_len);
	
	check = check_DHmessage(temp_buf,received,pubkey_len,pkeyServerBuffer);
	if(!check){
		
		printf("The structure of the received DH message is altered! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	check=verifySignMsg(username,temp_buf,SIZE_OPCODE + pubkey_len + SIZE_SIGNATURE,oppositeKey);
	if(!check){
		
		printf("The signature verification of the received DH message has given negative result ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	free(temp_buf);
	 
				
				peer_pubkey = deserialize_PEM_pubkey(pubkey_len,pkeyServerBuffer);
				
				if(peer_pubkey == NULL){
						perror("Errore: durante il protocollo DH impossibile leggere da file la chiave pubblica del server.\n");
						close(sd);
						pthread_exit(NULL);
				}
				
				
				//8. Derivazione del segreto condiviso
				if (EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey) <= 0){
					perror("Errore: durante il protocollo DH impossibile eseguire peer_pubkey.\n");
					close(sd);
					pthread_exit;
				}
				
				// Derivo una prima volta per conoscere la lunghezza del buffer:
				EVP_PKEY_derive(ctx_drv, NULL, &skeylen);
				
				// Alloco il buffer per il segreto condiviso
				skey = (unsigned char*)(malloc(int(skeylen)));
				
				if(!skey){
					perror("Errore: durante il protocollo DH impossibile allocare skey.\n");
					close(sd);
					pthread_exit;		
				}
				
				if(EVP_PKEY_derive(ctx_drv, skey, &skeylen) <= 0){
					perror("Errore: durante il protocollo DH impossibile eseguire EVP_PKEY_derive.\n");
					close(sd);
					pthread_exit;
				} 
				
				
				send_DHmessage_info(sd, pubkey_temp_len,opposite_addr, username , false);
				send_DHmessage(sd,pubkey_temp_len,opposite_addr,my_dh_pubkey,username,first);
			
 }
 
	EVP_MD_CTX* md_ctx;
	
	unsigned int digestlen;
	
	//context allocation new()
	md_ctx=EVP_MD_CTX_new();
 
	//Hashing (init+single up+finalization)
	EVP_DigestInit(md_ctx,EVP_sha256());
	EVP_DigestUpdate(md_ctx,(unsigned char*)skey,skeylen);
	EVP_DigestFinal(md_ctx,sharedSecret,&digestlen);

	sharedSecretLen = digestlen;
	
	time.tv_sec = 0;
	time.tv_usec = 0;
	
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));
	
	 //context deallocation free()
	 EVP_MD_CTX_free(md_ctx);
	 
	 EVP_PKEY_CTX_free(ctx_drv);
	 EVP_PKEY_free(peer_pubkey);
	 EVP_PKEY_free(my_dhkey);
	 EVP_PKEY_CTX_free(DHctx);
	 EVP_PKEY_free(params);
	 
	 printf("-------SHARED KEY CREATED SUCCESSFULLY !---------\n");
	 return;
}
