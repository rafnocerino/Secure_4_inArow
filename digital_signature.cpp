#include <iostream> 
#include <string>
#include <pthread.h>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "digital_signature.h"
#include "protocol_constant.h"

#include <sys/types.h>
#include <sys/socket.h>
using namespace std;

bool sendAndSignMsg(int socket,char* userName, unsigned char* msg_to_sign,int messageLen,struct sockaddr_in* address,int address_len,bool serverCall,bool needChunk /*= false*/){

	// used for return values
	int ret; 

	string prvkey_file_name = serverCall == true ? "../private keys/" : "./private keys/";
	prvkey_file_name+=reinterpret_cast<const char*>(userName);
	prvkey_file_name+="_prv.pem";

	// load my private key:
	FILE* prvkey_file = fopen(prvkey_file_name.c_str(), "r");
	if(!prvkey_file){
		cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; 
		return false;
	}

	EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, userName);
	fclose(prvkey_file);
	if(!prvkey){
		cerr << "Error: PEM_read_PrivateKey returned NULL\n";
		return false; 
	}
 
   const EVP_MD* md = EVP_sha256();
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){
		cerr << "Error: EVP_MD_CTX_new returned NULL\n";
		return false; 
	}

	// allocate buffer for signature:
	unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
	if(!sgnt_buf){
		cerr << "Error: malloc returned NULL (signature too big?)\n";
		return false; 
	}
   
	// sign the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_SignInit(md_ctx, md);

	if(ret == 0){
		cerr << "Error: EVP_SignInit returned " << ret << "\n";
		return false;
	}

	ret = EVP_SignUpdate(md_ctx,msg_to_sign,messageLen);
	if(ret == 0){
		cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
		return false;
	}

	unsigned int sgnt_size;
	ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);

	if(ret == 0){
		cerr << "Error: EVP_SignFinal returned " << ret << "\n";
		return false;
	}
	
	// delete the digest and the private key from memory:
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(prvkey);
	
	// Fase di invio del messaggio firmato all'utente
	
	cout<<"DEBUG: invio del messaggio firmato."<<endl;
	
	unsigned char* sendBuffer = (unsigned char*)malloc(messageLen + sgnt_size);
	memset(sendBuffer,0,messageLen + sgnt_size);
	memcpy(sendBuffer,msg_to_sign,messageLen);
	memcpy(sendBuffer + messageLen,sgnt_buf,sgnt_size);
	
	cout<<"DEBUG: Indirizzo ="<<inet_ntoa(address->sin_addr)<<endl;
	cout<<"DEBUG: Lunghezza Indirizzo = "<<address_len<<endl;
		
	if(needChunk){
		ret = sendto(socket, sendBuffer, SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN, 0,(struct sockaddr*)address,address_len);
		if(ret < SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN){
			perror("Errore: impossibile inviare il messaggio signature_message chunk 1.\n");
			return false;
		}
		ret = sendto(socket, sendBuffer + SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN, messageLen + sgnt_size - (SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN), 0,(struct sockaddr*)address,address_len);	
		if(ret < messageLen + sgnt_size - (SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN)){
			perror("Errore: impossibile inviare il messaggio signature_message chunk 2.\n");
			return false;			
		}
	}else{		
		ret = sendto(socket, sendBuffer, messageLen + sgnt_size, 0,(struct sockaddr*)address,address_len);
		if(ret < messageLen + sgnt_size){
			perror("Errore: impossibile inviare il messaggio signature_message.\n");
			return false;
		}
	}
	
	free(sendBuffer);
	
	
	
	return true;
}

bool verifySignMsg(char* userName, unsigned char* msg_signed,int messageLength,EVP_PKEY* pubkey){
   int ret; // used for return values
   
   if(pubkey == NULL){
		// read the peer's public key file from keyboard:
		string pubkey_file_name ="../public keys/";
		pubkey_file_name+=reinterpret_cast<const char*>(userName);
		pubkey_file_name+="_public.pem";

		// load the peer's public key:
		FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
		if(!pubkey_file){ cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; exit(1); }
		pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
		fclose(pubkey_file);
		if(!pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }
	}
	
	long int clear_size = messageLength - SIZE_SIGNATURE;
	
	unsigned char* clear_buf;
	clear_buf = (unsigned char*)malloc(clear_size);
	memset(clear_buf,0,clear_size);
	memcpy(clear_buf,msg_signed,clear_size);
	
	long int sgnt_size = SIZE_SIGNATURE;
   
	unsigned char* sgnt_buf;
	sgnt_buf = (unsigned char*)malloc(sgnt_size);
	memset(sgnt_buf,0,sgnt_size); 
	memcpy(sgnt_buf,msg_signed + clear_size,sgnt_size);
   
   
   
   cout<<"DEBUG: Verifica della firma"<<endl;
   cout<<"DEBUG: Clear Buffer = "<<endl;
   BIO_dump_fp(stdout,(const char*)clear_buf,clear_size);
   cout<<"DEBUG: Clear Size = "<<clear_size<<endl;
   cout<<"DEBUG: Signature Size = "<<sgnt_size<<endl;
   // declare some useful variables:
   const EVP_MD* md = EVP_sha256();

   // create the signature context:
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; pthread_exit(NULL); }

   // verify the plaintext:
   // (perform a single update on the whole plaintext, 
   // assuming that the plaintext is not huge)
   ret = EVP_VerifyInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; pthread_exit(NULL); }
   ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);  
   if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pubkey);
   if(ret != 1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
      cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
      // deallocate buffers:
      return false;
   }
   cout<<"DEBUG: firma correttamente verificata."<<endl;
   free(clear_buf);
   free(sgnt_buf);
   EVP_PKEY_free(pubkey);
   EVP_MD_CTX_free(md_ctx);
   return true;
}
