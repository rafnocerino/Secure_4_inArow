#include <iostream> 
#include <string>
#include <stdlib.h>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
using namespace std;



struct cipher_text{
	unsigned char* cphr;
	int len_cphr;
	unsigned char* iv;
	int len_iv;
};
//buffer 
//chiave
void symmetric_enc(unsigned char* key, unsigned char* clear_buf, int clear_size, cipher_text* c/*,unsigned char* iv, unsigned char* ciphertxt*/){
	int ret;
   	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
   	int iv_len = EVP_CIPHER_iv_length(cipher);
   	int block_size = EVP_CIPHER_block_size(cipher);

	unsigned char* iv = (unsigned char*)malloc(iv_len);
   	// Seed OpenSSL PRNG
   	RAND_poll();
   	// Generate 16 bytes at random. That is my IV
   	RAND_bytes((unsigned char*)&iv[0],iv_len);
   
   	// check for possible integer overflow in (clear_size + block_size) --> PADDING!
   	// (possible if the plaintext is too big, assume non-negative clear_size and block_size):
   	if(clear_size > INT_MAX - block_size) { cerr <<"Error: integer overflow (plaintext too big?)\n"; exit(1); }
   	// allocate a buffer for the ciphertext:
   	int enc_buffer_size = clear_size + block_size;
   	unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
   	if(!cphr_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
	
	//Create and initialise the context with used cipher, key and iv
	EVP_CIPHER_CTX *ctx;
   	ctx = EVP_CIPHER_CTX_new();
   	if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
   	ret = EVP_EncryptInit(ctx, cipher, key, iv);
   	if(ret != 1){
      		cerr <<"Error: EncryptInit Failed\n";
      		exit(1);
   	}
   	int update_len = 0; // bytes encrypted at each chunk
  	int total_len = 0; // total encrypted bytes
   
   	// Encrypt Update
   	ret = EVP_EncryptUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
   	if(ret != 1){
   	   cerr <<"Error: EncryptUpdate Failed\n";
   	   exit(1);
  	 }
   	total_len += update_len;
   
   	//Encrypt Final. Finalize the encryption and adds the padding
   	ret = EVP_EncryptFinal(ctx, cphr_buf + total_len, &update_len);
   	if(ret != 1){
  	    cerr <<"Error: EncryptFinal Failed\n";
  	    exit(1);
  	 }
  	total_len += update_len;
  	int cphr_size = total_len;

   	// delete the context from memory:
   	EVP_CIPHER_CTX_free(ctx);

	BIO_dump_fp (stdout, (const char *)cphr_buf, cphr_size);
	
	//DEVE RITORNARE IV e cphr_buffer
	c->cphr=cphr_buf;
	c->len_cphr=cphr_size ;
	c->iv= iv;
	c-> len_iv= iv_len;
	
}


void symmetric_dec(unsigned char* key, unsigned char* cphr_buf, unsigned char* iv, int cphr_size, int iv_len){
	int ret;	
	const EVP_CIPHER* cipher= EVP_aes_128_cbc();
	 
	// Allocate buffer for IV, ciphertext, plaintext
   	unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
   	if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
	
   	//Create and initialise the context
   	EVP_CIPHER_CTX *ctx;
   	ctx = EVP_CIPHER_CTX_new();
   	if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
   	ret = EVP_DecryptInit(ctx, cipher, key, iv);
   	if(ret != 1){
   	   cerr <<"Error: DecryptInit Failed\n";
   	   exit(1);
   	}
   	
   	int update_len = 0; // bytes decrypted at each chunk
  	int total_len = 0; // total decrypted bytes
   
  	// Decrypt Update: one call is enough because our ciphertext is small.
   	ret = EVP_DecryptUpdate(ctx, clear_buf, &update_len, cphr_buf, cphr_size);
   	if(ret != 1){
   	   cerr <<"Error: DecryptUpdate Failed\n";
   	   exit(1);
   	}
   	total_len += update_len;
   
   	//Decrypt Final. Finalize the Decryption and adds the padding
   	ret = EVP_DecryptFinal(ctx, clear_buf + total_len, &update_len);
   	if(ret != 1){
  	    cerr <<"Error: DecryptFinal Failed\n";
	    exit(1);
   	}
   	total_len += update_len;
  	int clear_size = total_len;

   	// delete the context from memory:
   	EVP_CIPHER_CTX_free(ctx);

	BIO_dump_fp (stdout, (const char *)clear_buf, clear_size);
	
	

}

//void symmetric_dec(unsigned char* key, unsigned char* cphr_buf, unsiged char* iv, int iv_len, int cphr_size)
int main(){
	unsigned char key[]="dklfjalkdjflasdjfalsdjffla";
	unsigned char plaintxt[]="Questo messaggio deve essere cifrato";
	cipher_text ct;
	symmetric_enc(key,plaintxt, sizeof(plaintxt)-1, &ct);
	symmetric_dec(key, ct.cphr, ct.iv, ct.len_cphr, ct.len_iv);
	


}
