#include <iostream> 
#include <string>
#include <pthread.h>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

bool sendAndSignMsg(/*int socket,*/unsigned char* userName, unsigned char* msg_to_sign/*,struct sockaddr_in* address,int address_len*/){

 
	// used for return values
	int ret; 

	string prvkey_file_name="./private keys/";
	prvkey_file_name+=reinterpret_cast<const char*>(userName);
	prvkey_file_name+="_prv.pem";

	// load my private key:
	FILE* prvkey_file = fopen(prvkey_file_name.c_str(), "r");
	if(!prvkey_file){
		cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; 
		pthread_exit(NULL); 
	}

	EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
	fclose(prvkey_file);
	if(!prvkey){
		cerr << "Error: PEM_read_PrivateKey returned NULL\n";
		pthread_exit(NULL); 
	}
 
   const EVP_MD* md = EVP_sha256();
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){
		cerr << "Error: EVP_MD_CTX_new returned NULL\n";
		pthread_exit(NULL); 
	}

	// allocate buffer for signature:
	unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
	if(!sgnt_buf){
		cerr << "Error: malloc returned NULL (signature too big?)\n";
		pthread_exit(NULL); 
	}
   
	// sign the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_SignInit(md_ctx, md);

	if(ret == 0){
		cerr << "Error: EVP_SignInit returned " << ret << "\n";
		pthread_exit(NULL);
	}

	ret = EVP_SignUpdate(md_ctx, msg_to_sign, strlen((const char*)msg_to_sign));
	if(ret == 0){
		cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
		pthread_exit(NULL);
	}

	unsigned int sgnt_size;
	ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);

	if(ret == 0){
		cerr << "Error: EVP_SignFinal returned " << ret << "\n";
		pthread_exit(NULL);
	}

	
	//datastructure init
   /*sign->sign_buf= sgnt_buf;
   sign->len=sgnt_size;*/

	cout<<"EVP_PKEY: "<<EVP_PKEY_size(prvkey)<<endl;
	cout<<"SIZE: "<<sgnt_size<<endl;

	// delete the digest and the private key from memory:
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(prvkey);
	BIO_dump_fp(stdout,(const char*)sgnt_buf, strlen((const char*)sgnt_buf)+1);
	

}
/*
bool verifySignMsg(unsigned char* userName, unsigned char* text, struct signature* sign){
   int ret; // used for return values

   // read the peer's public key file from keyboard:
   string pubkey_file_name="./public keys/";
   pubkey_file_name+=reinterpret_cast<const char*>(userName);
   pubkey_file_name+=".pem";

   // load the peer's public key:
   FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
   if(!pubkey_file){ cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; exit(1); }
   EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
   fclose(pubkey_file);
   if(!pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

   unsigned char* clear_buf = text;
   unsigned char* sgnt_buf = sign->sign_buf;
   long int clear_size=strlen((const char*)clear_buf);
   long int sgnt_size=sign->len;
   cout<<"Autenticazione"<<endl;
   cout<<clear_buf<<endl;
   cout<<sgnt_buf<<endl;
   cout<<clear_size<<endl;
   cout<<sgnt_size<<endl;
   // declare some useful variables:
   const EVP_MD* md = EVP_sha256();

   // create the signature context:
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

   // verify the plaintext:
   // (perform a single update on the whole plaintext, 
   // assuming that the plaintext is not huge)
   ret = EVP_VerifyInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);  
   if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pubkey);
   if(ret != 1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
      cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
      // deallocate buffers:
      return false;
   }
   cout<<"QIO"<<endl;
   //free(clear_buf);
   //free(sgnt_buf);
   EVP_PKEY_free(pubkey);
   EVP_MD_CTX_free(md_ctx);
   return true;
}*/

int main() {
	//struct signature sign;
	unsigned char name[]="raffa";
	unsigned char msg[] ="Ciaosdfsdfsdfsdfsdfadsfasdfsdsda";
	sendAndSignMsg(name,msg/*,&sign*/);
	//*sign.sign_buf='A';
	/*if(verifySignMsg(name,msg,&sign))
		cout<<"Firma autenticata con SUCCESSO"<<endl;
	else
		cout<<"Firma NON AUTENTICA"<<endl;*/
	return 0;
}
