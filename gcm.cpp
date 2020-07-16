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
    //int iv_len= SIZE_IV;
    //int aad_len=iv_len;
    //cout<<"The below numb should be 12:"<<endl;
    //cout<<iv_len<<endl;
    //cout<<aad_len<<endl;
    unsigned char* iv=(unsigned char*)malloc(SIZE_IV);
    unsigned char* aad=(unsigned char*)malloc(SIZE_IV);
    unsigned char* tag=(unsigned char*)malloc(SIZE_TAG);
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
    memcpy(c->all,ciphertext,ciphertext_len);
    memcpy(c->all+ciphertext_len, iv, SIZE_IV);
    //memcpy(c->all+ciphertext_len+iv_len, aad, iv_len);
    memcpy(c->all+ciphertext_len+SIZE_IV, tag, SIZE_TAG);
    c->all_len = ciphertext_len + SIZE_IV + SIZE_TAG;
    
    cout<<"CIPHER"<<endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len); 
    //BIO_dump_fp (stdout, (const char *)c->cphr, c->len_cphr); 
    //BIO_dump_fp (stdout, (const char *)c->all, c->len_cphr); 
    //cout<<ciphertext<<endl;
    cout<<"------- END ------------"<<endl;
    /*cout<<"IV"<<endl;
    BIO_dump_fp (stdout, (const char *)iv, iv_len); 
    BIO_dump_fp (stdout, (const char *)c->iv, c->len_iv); 
    BIO_dump_fp (stdout, (const char *)c->all+c->len_cphr, c->len_iv); 
    cout<<iv<<endl;
    cout<<"------- END ------------"<<endl;
    cout<<"AAD"<<endl;
    BIO_dump_fp (stdout, (const char *)aad, iv_len); 
    BIO_dump_fp (stdout, (const char *)c->aad, c->len_iv); 
    BIO_dump_fp (stdout, (const char *)c->all+c->len_cphr+c->len_iv, c->len_iv); 
    cout<<"------- END ------------"<<endl;
    cout<<"------- TAG ------------"<<endl;
    BIO_dump_fp (stdout, (const char *)tag, 16); 
    BIO_dump_fp (stdout, (const char *)c->tag, 16); 
    BIO_dump_fp (stdout, (const char *)c->all+c->len_cphr+c->len_iv+c->len_iv, 16); 
    cout<<"------- END ------------"<<endl;*/
    return;
}

/*int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)*/

bool gcm_decrypt(unsigned char *key,unsigned char* all, int all_len,unsigned char* pt){

    int ciphertext_len = all_len - SIZE_IV - SIZE_TAG; //iv add tag
    unsigned char *plaintext=(unsigned char*)malloc(ciphertext_len);
    unsigned char* ciphertext=(unsigned char*)malloc(ciphertext_len);
    memcpy(ciphertext,all,ciphertext_len);
    //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len); 
    //cout<<ciphertext<<endl;
    unsigned char* iv=(unsigned char*)malloc(SIZE_IV); 
    memcpy(iv,all+ciphertext_len,SIZE_IV);

    int aad_len = SIZE_IV;
    unsigned char* aad=(unsigned char*)malloc(aad_len);
    aad=iv;

    unsigned char* tag=(unsigned char*)malloc(SIZE_TAG);
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
    cout<<"HERE"<<endl;
    BIO_dump_fp (stdout, (const char *)plaintext, plaintext_len);

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

/*int main (void){
	unsigned char msg[] = "Dario";
    BIO_dump_fp (stdout, (const char *)msg, sizeof(msg));
	//create key
	unsigned char key_gcm[]="12345678901234561234567890123456";
	struct cipher_txt c;
    int pt_len=sizeof(msg);
	gcm_encrypt(msg, pt_len, key_gcm, &c);
	unsigned char* pt = (unsigned char*)malloc(pt_len); 	
	if(!gcm_decrypt(key_gcm, c.all, c.all_len,pt)){
		cout<<"Errore"<<endl;
	}
	cout<<pt<<endl;
	
	return 1;
}*/
