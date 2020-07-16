struct cipher_txt{
	//cipher iv aad tag
	unsigned char* all;
	int all_len;
	unsigned char* cphr;
	int len_cphr;
	unsigned char* iv;
	int len_iv;
	unsigned char* tag;
	//tag 16 byte by default

};

void gcm_encrypt(unsigned char *plaintext, int plaintext_len,unsigned char *key,cipher_txt* c);
bool gcm_decrypt(unsigned char *key,unsigned char* all, int all_len,unsigned char* pt);
