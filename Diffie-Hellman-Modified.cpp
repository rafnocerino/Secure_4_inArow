#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "send_diffiehelman.h"

#define BUF_SIZE 512

using namespace std;

const char* sharedSecretCreationDH(int sd, sockaddr_in* adversary_socket, uint8_t seq_numb, bool id){
 /* GENERATE KEY */
 printf("Start: loading standard DH parameters\n");
 EVP_PKEY *params;
 char buffer[BUF_SIZE];

 if(NULL == (params = EVP_PKEY_new())) handleErrors();
 if(1 != EVP_PKEY_set1_DH(params,DH_get_2048_224())) handleErrors();
 /* Create context for the key generation */
 EVP_PKEY_CTX *DHctx;
 if(!(DHctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();
 /* Generate a new key */
 EVP_PKEY *my_dhkey = NULL;
 if(1 != EVP_PKEY_keygen_init(DHctx)) handleErrors();
 if(1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) handleErrors();
 /* Store in this peer_pubkey the parameter recived from the other host */
 EVP_PKEY* peer_pubkey;
 if(NULL == (peer_pubkey = EVP_PKEY_new())) handleErrors();
 //SIGN MY_PUBKEY
 if(id){
 	//WAIT SHARED
	wait_dh(sd,adversary_socket,seq_numb,peer_pubkey);
         	//VALIDATE SIGNATURE 
		//STORE IN peer_pubkey		
		//SEND ACK
	//send_ack();
        //SEND SHARED 
	send_dh(sd,adversary_socket,params,sizeof(*params),seq_numb);
        //WAIT ACK
	//wait_ACK();
 }
 else{
 	//SEND SHARED
	send_dh(sd,adversary_socket,params,sizeof(*params),seq_numb);	
	//WAIT ACK
	//wait_ACK(sd,adversary_socket,seq_numb);
	//WAIT SHARED
	wait_dh(sd,adversary_socket,seq_numb,peer_pubkey);
		//VALIDATE SIGNATURE 
		//STORE IN peer_pubkey
		//SEND ACK
	//send_ACK(sd, buffer, OPCODE_ACK, seq_numb, sv_addr_challenge, addr_size);
	//send_ack(sd,adversary_socket, );
 }
 /*creating a context, the buffer for the shared key and an int for its length*/
 EVP_PKEY_CTX *derive_ctx;
 unsigned char *skey;
 size_t skeylen;
 derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);
 if (!derive_ctx) handleErrors();
 if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
 /*Setting the peer with its pubkey*/
 if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) handleErrors();
 /* Determine buffer length, by performing a derivation but writing the result nowhere */
 EVP_PKEY_derive(derive_ctx, NULL, &skeylen);
 /*allocate buffer for the shared secret*/
 skey = (unsigned char*)(malloc(int(skeylen)));
 if (!skey) handleErrors();
 /*Perform again the derivation and store it in skey buffer*/
 if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) handleErrors();
 printf("Here it is the shared secret: \n");
 BIO_dump_fp (stdout, (const char *)skey, skeylen);
 // HASH THE SHARED KEY AND SAVE ON THE HEAP

 return skey;
}



