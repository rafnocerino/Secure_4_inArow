#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <pthread.h>

#include "gcm.h"
#include "protocol_constant.h"
using namespace std;

int handleErrors(){
	printf("An error occourred.\n");
	pthread_exit(NULL);
}

void gcm_encrypt(unsigned char *plaintext, int plaintext_len,unsigned char *key,cipher_txt* c){
  	
    EVP_CIPHER_CTX *ctx;
    unsigned char* ciphertext=(unsigned char*)malloc(plaintext_len);
    unsigned char* iv=(unsigned char*)malloc(SIZE_IV);
    unsigned char* aad=(unsigned char*)malloc(SIZE_IV);
    unsigned char* tag=(unsigned char*)malloc(SIZE_TAG);
    
    if(!ciphertext || !iv || !aad || !tag){
		printf("ERROR: unable to allocate a buffer.\n");
		pthread_exit(NULL);
	}
    
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],SIZE_IV);
    //RAND_bytes((unsigned char*)&aad[0],aad_len);
    aad=iv;

    int len;
    int ciphertext_len;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv))
        handleErrors();
     
    //Provide AAD 
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, SIZE_IV))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();

    //cout<<"The below numb should be 12:"<<endl;
    ciphertext_len = len;
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;	
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SIZE_TAG, tag))
        handleErrors();
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    c->cphr=ciphertext;
   
    c->len_cphr=ciphertext_len;    

    c->iv=iv;
    c->len_iv = SIZE_IV;
    //c->aad=aad;
    c->tag = tag;

    c->all = (unsigned char*)malloc(ciphertext_len + 2 * SIZE_IV + SIZE_TAG);
    
    if(!c->all){
		printf("ERROR: an error occurred during the allocation of the buffer.\n");
		pthread_exit(NULL);
	}
	
    memcpy(c->all,ciphertext,ciphertext_len);
    memcpy(c->all+ciphertext_len, iv, SIZE_IV);
    //memcpy(c->all+ciphertext_len+iv_len, aad, iv_len);
    memcpy(c->all+ciphertext_len+SIZE_IV, tag, SIZE_TAG);
    c->all_len = ciphertext_len + SIZE_IV + SIZE_TAG;
   
    return;
}


bool gcm_decrypt(unsigned char *key,unsigned char* all, int all_len,unsigned char* pt){

    int ciphertext_len = all_len - SIZE_IV - SIZE_TAG; //iv add tag
    int aad_len = SIZE_IV;
    
	unsigned char *plaintext=(unsigned char*)malloc(ciphertext_len);
    unsigned char* ciphertext=(unsigned char*)malloc(ciphertext_len);
    unsigned char* iv=(unsigned char*)malloc(SIZE_IV); 
    unsigned char* aad=(unsigned char*)malloc(aad_len);
    unsigned char* tag=(unsigned char*)malloc(SIZE_TAG);
    
    if(!plaintext || !ciphertext || !iv || !aad || !tag){
		printf("ERROR: an error occurred during the allocation of the buffer.\n");
		pthread_exit(NULL);
	}
	
    memcpy(ciphertext,all,ciphertext_len);
    memcpy(iv,all+ciphertext_len,SIZE_IV);
    aad=iv;

    memcpy(tag,all + ciphertext_len + SIZE_IV,SIZE_TAG);

	EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
		
       perror("Error during the creation of the decipher context! \n");
	   return false;
		
	}
    if(!EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv)){
		
       perror("Error during the init of the decipher context! \n");
	   return false;
		
	}
        
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
		
       perror("Error during the update of the decipher context! \n");
	   return false;
		
	}
  
	//Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
		
       perror("Error during the second update of the decipher context! \n");
	   return false;
		
	}
      
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
		
       perror("Error during the computation of the tag! \n");
	   return false;
		
	}
        
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);
   

    if(ret > 0) {
        /* Success */
	//cout<<"SUCCESS"<<endl;
        plaintext_len += len;
		memcpy(pt,plaintext,plaintext_len);
        return true;
    }else{
        /* Verify failed */
        return false;
    }
}


