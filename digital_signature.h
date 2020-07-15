#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>


bool sendAndSignMsg(int socket,char* userName, unsigned char* msg_to_sign,int messageLen,struct sockaddr_in* address,int address_len,bool serverCall);
bool verifySignMsg(char* userName, unsigned char* msg_signed,int messageLength,EVP_PKEY* pubkey);
