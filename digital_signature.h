bool sendAndSignMsg(int socket,char* userName,unsigned char* msg_to_sign,int messageLen,struct sockaddr_in* address,int address_len);
bool verifySignMsg(char* userName, unsigned char* msg_signed,int signatureLength,EVP_PKEY* pubkey);
