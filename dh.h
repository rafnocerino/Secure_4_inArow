void sharedSecretCreationDH(int sd, struct sockaddr_in* opposite_addr, bool first,char* username,EVP_PKEY* oppositeKey,unsigned char* sharedSecret,unsigned int& sharedSecretLen,unsigned char* myRandomData,unsigned char* opRandomData);
EVP_PKEY* deserialize_PEM_pubkey(int pubkeySize,unsigned char* pubkey_buf);
void sharedSecretCreationDH(int sd, struct sockaddr_in* opposite_addr, bool first,char* username,EVP_PKEY* oppositeKey,unsigned char* sharedSecret,unsigned int& sharedSecretLen, char* myUsername);
bool removeFile(const char* fileName);
