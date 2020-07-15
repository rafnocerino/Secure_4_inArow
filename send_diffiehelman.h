void send_dh(int socket, struct sockaddr_in* sv_addr, EVP_PKEY* dhsigned, int len_dhsigned
                           uint8_t seq_numb);
void wait_ACK(int sd, sockaddr_in* sock, uint8_t sq_numb);
void wait_dh(int sd, sockaddr_in* sock, uint8_t sq_numb, EVP_PKEY* param);
