#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <pthread.h>
using namespace std;


struct cipher_txt{
	//cipher iv aad tag
	unsigned char* all;
	int all_len;
	unsigned char* cphr;
	int len_cphr;
	unsigned char* iv;
	int len_iv;
	unsigned char* aad;
	//aad same len as iv
	unsigned char* tag;
	//tag 16 byte by default

};

int handleErrors(){
	printf("An error occourred.\n");
	pthread_exit(NULL);
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len,unsigned char *key,cipher_txt* c){
    EVP_CIPHER_CTX *ctx;
    unsigned char* ciphertext=(unsigned char*)malloc(plaintext_len);
    int iv_len= EVP_CIPHER_iv_length(EVP_aes_256_gcm());
    int aad_len=iv_len;
    //cout<<"The below numb should be 12:"<<endl;
    //cout<<iv_len<<endl;
    //cout<<aad_len<<endl;
    unsigned char* iv=(unsigned char*)malloc(iv_len);
    unsigned char* aad=(unsigned char*)malloc(iv_len);
    unsigned char* tag=(unsigned char*)malloc(16);
    RAND_poll();
    RAND_bytes((unsigned char*)&iv[0],iv_len);
    RAND_bytes((unsigned char*)&aad[0],aad_len);
    //aad=iv;

    int len;
    int ciphertext_len;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv))
        handleErrors();
     
    //Provide AAD 
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
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
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        handleErrors();
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    c->cphr=ciphertext;
   
    c->len_cphr=ciphertext_len;    

    c->iv=iv;
    c->len_iv=iv_len;
    c->aad=aad;
    c->tag=tag;

    c->all=(unsigned char*)malloc(ciphertext_len+2*iv_len+16);
    memcpy(c->all,ciphertext,ciphertext_len);
    memcpy(c->all+ciphertext_len, iv, iv_len);
    memcpy(c->all+ciphertext_len+iv_len, aad, iv_len);
    memcpy(c->all+ciphertext_len+iv_len+iv_len, tag, 16);
    c->all_len=ciphertext_len+2*iv_len+16;
    
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
    return ciphertext_len;
}

/*int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)*/

int gcm_decrypt(unsigned char *key,unsigned char* all, int all_len){

    int ciphertext_len=all_len-12-12-16; //iv add tag
    unsigned char *plaintext=(unsigned char*)malloc(ciphertext_len);
    unsigned char* ciphertext=(unsigned char*)malloc(ciphertext_len);
    memcpy(ciphertext,all,ciphertext_len);
    //BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len); 
    //cout<<ciphertext<<endl;
    int iv_len=12;
    unsigned char* iv=(unsigned char*)malloc(iv_len); 
    memcpy(iv,all+ciphertext_len,iv_len);

    int aad_len=12;
    unsigned char* aad=(unsigned char*)malloc(aad_len);
    memcpy(aad,all+ciphertext_len+iv_len,aad_len);

    int tag_len=16;
    unsigned char* tag=(unsigned char*)malloc(tag_len);
    memcpy(tag,all+ciphertext_len+iv_len+aad_len,tag_len);

    /*cout<<"CIPHER"<<endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len); 
 
    cout<<"------- END ------------"<<endl;
    cout<<"IV"<<endl;
    BIO_dump_fp (stdout, (const char *)iv, iv_len); 
        cout<<iv<<endl;
    cout<<"------- END ------------"<<endl;
    cout<<"AAD"<<endl;
    BIO_dump_fp (stdout, (const char *)aad, iv_len); 
    cout<<"------- END ------------"<<endl;

    cout<<"AAD"<<endl;
    BIO_dump_fp (stdout, (const char *)tag, 16); */
	
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if(!EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv))
        handleErrors();
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();
	//Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        handleErrors();
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
	cout<<"SUCCESS"<<endl;
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
int main (void)
{
	unsigned char msg[] = "Dario";
    BIO_dump_fp (stdout, (const char *)msg, sizeof(msg));
	//create key
	unsigned char key_gcm[]="12345678901234561234567890123456";
	struct cipher_txt c;

    int pt_len=sizeof(msg);
	gcm_encrypt(msg, pt_len, key_gcm, &c);
	
	cout<<"DEBUG: all_len = "<<c.all_len<<endl;
	cout<<"DEBUG: cphr = "<<c.len_cphr<<endl;
	gcm_decrypt(key_gcm, c.all, c.all_len);
	
	cout<<sizeof(msg)<<endl;
	
	
	return 1;
}
