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
 printf("Start: loading standard DH parameters\n");
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
 
  cout<<"9"<<endl;
 
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
 
 
 /* cout<<"10"<<endl;
 
 fseek(file_mydhpubkey, 0, SEEK_END);  
 long len = ftell(file_mydhpubkey);  */
 
	unsigned char* my_dh_pubkey;  

	int pubkey_temp_len = serialize_PEM_Pub_Key(pubkey_temp,&my_dh_pubkey);

	printf("DEBUG: pubkey_temp_len = %d\n",pubkey_temp_len);
	printf("DEBUG: my_dh_pubkey = \n");
	
	BIO_dump_fp(stdout,(const char*)my_dh_pubkey,pubkey_temp_len);

 /*fseek(file_mydhpubkey, 0, SEEK_SET);  
 fread(my_dh_pubkey, 1, len, file_mydhpubkey);  */
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
	
	char usernameServer[] = "server"; 
	
	send_DHmessage(sd,pubkey_temp_len,opposite_addr,my_dh_pubkey,usernameServer,first);
	
	//after sending my DH pubkey, i wait for the reception of the opposite DH pubkey
	
	memset(buffer,0,BUF_SIZE);
	size = sizeof(*opposite_addr);
	received = recvfrom(sd,buffer,SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN,0,(struct sockaddr*)opposite_addr,&size);
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	int pubkey_len;
	memcpy(&pubkey_len,buffer+SIZE_OPCODE,SIZE_DH_PUBLIC_KEY_LEN);
	
	unsigned char* temp_buf = (unsigned char*)malloc(SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN + pubkey_len + SIZE_SIGNATURE);
	received = recvfrom(sd,temp_buf + SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN,pubkey_len + SIZE_SIGNATURE,0,(struct sockaddr*)opposite_addr,&size);
	
	received += SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN;
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	memcpy(temp_buf,buffer,SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN);
	
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
	
	BIO_dump_fp (stdout, (const char *)skey, skeylen);
	
}else{
	 
	// Comportamento del client:
	
	//1. Mi metto in attesa di un messaggio contenente la chiave pubblica del server: 
	memset(buffer,0,BUF_SIZE);
	size = sizeof(*opposite_addr);
	
	received = recvfrom(sd,buffer,SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN,0,(struct sockaddr*)opposite_addr,&size);
	int pubkey_len;
	memcpy(&pubkey_len,buffer+SIZE_OPCODE,SIZE_DH_PUBLIC_KEY_LEN);
	
	unsigned char* temp_buf = (unsigned char*)malloc(SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN + pubkey_len + SIZE_SIGNATURE);
	received = recvfrom(sd,temp_buf + SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN,pubkey_len + SIZE_SIGNATURE,0,(struct sockaddr*)opposite_addr,&size);
	
	received += SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN;
	
	if( received <= 0 ){
		
		printf("Timer expired for the reception of DH message ! \n");
		close(sd);
		pthread_exit(NULL);
		
	}
	
	memcpy(temp_buf,buffer,SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN);
	
	//2. Se la chiave pubblica arriva entro lo scadere del timer e il messaggio ha una grandezza corretta:
	//if(received == SIZE_MESSAGE_DH_MESSAGE){
		//Alloco il buffer che conterrà la chiave pubblica del server:
		unsigned char* pkeyServerBuffer = (unsigned char*)malloc(pubkey_len);
		//3. Controllo la struttura del messaggio e estrazione della chiave pubblica:
		if(check_DHmessage(temp_buf,received,pubkey_len,pkeyServerBuffer)){
			printf("DEBUG: la struttura del messaggio DH message ricevuto è corretta.\n");
			//4. Verifico la firma contenuta nel messaggio:
			if(verifySignMsg(username,temp_buf,received,oppositeKey)){
				printf("DEBUG: la firma del messaggio DH message ricevuto è corretta.\n");
				free(temp_buf);
				//5. Salvataggio della chiave pubblica del protocollo DH ottenuta all'interno di un file temporaneo
				/*FILE* f = fopen("./tmp/tmp_DH_pubkey_2.pem","wb");
				
				if(!f){
					perror("Errore: durante il protocollo DH impossible memorizzare la chiave .\n");
					close(sd);
					pthread_exit(NULL);
				}
				 
				ret = fwrite(pkeyServerBuffer,1,SIZE_DH_PUBLIC_KEY,f);
				
				BIO_dump_fp (stdout, (const char *)pkeyServerBuffer, SIZE_DH_PUBLIC_KEY);
				
				fclose(f);
				
				if(ret < SIZE_DH_PUBLIC_KEY){
					perror("Errore: durante il protocollo DH impossibile scrivere su file la chiave pubblica del server.\n");
					close(sd);
					pthread_exit(NULL);
				}*/
				
				//6. Lettura della chiave pubblica dal file temporaneo:
				
				//f = fopen("./tmp/tmp_DH_pubkey_2.pem","rb");
				
				/*peer_pubkey = PEM_read_PUBKEY(f,NULL,NULL,NULL);*/
				
				peer_pubkey = deserialize_PEM_pubkey(pubkey_len,pkeyServerBuffer);
				
				if(peer_pubkey == NULL){
						perror("Errore: durante il protocollo DH impossibile leggere da file la chiave pubblica del server.\n");
						close(sd);
						pthread_exit(NULL);
				}
				
				//fclose(f);
								
				//7. Eliminazione del file temporaneo:
				/*if(!removeFile("./tmp/tmp_DH_pubkey_2.pem")){
					perror("Errore: durante il protocollo DH impossibile eliminare il file temporaneo con la chiave pubblica del server.\n");
					close(sd);
					pthread_exit;
				}*/
				
				
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
				
				//printf("Here it is the shared secret: \n");
				//BIO_dump_fp (stdout, (const char *)skey, skeylen);
				
				send_DHmessage(sd,pubkey_temp_len,opposite_addr,my_dh_pubkey,username,first);
			
			}else{
				perror("Errore: durante il protocollo DH il client ha ottenuto il messaggio contenente la chiava pubblica del server con firma errata.\n");
				close(sd);
				pthread_exit(NULL);
			}
		}else{
			perror("Errore: durante il protocollo DH il client ha ottenuto il messaggio contenente la chiava pubblica del server con formato errato.\n");
			close(sd);
			pthread_exit(NULL);
		}
		
	/*}else{
		perror("Errore: durante il protocollo DH il client non e' riuscito a ottenere il messaggio con la chiave pubblica del server.\n");
		close(sd);
		pthread_exit(NULL);
	}*/
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
	 return;
}
