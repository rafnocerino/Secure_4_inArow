#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

void send_challengeRequest(int socket, struct sockaddr_in* sv_addr, int addr_size, unsigned char* buffer, const char* challenger, char* challenged,
                           uint8_t seq_numb, int challenge_id);
void send_challengeRefused(int socket, unsigned char* buffer, uint8_t seq_numb, int challenge_id, sockaddr_in* sv_addr_challenge, int addr_size);
void send_challengeAccepted(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr_challenging, int addr_size,
                            int challenge_id);
void send_malformedMsg(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size);
void send_ACK(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size);
void send_UpdateStatus(int socket, unsigned char* buffer,const char* username, uint8_t user_size, uint8_t op_code, uint8_t seq_numb, uint8_t status_code,
                       sockaddr_in* sv_addr, int addr_size);
void send_AvailableUserListChunk(int socket,unsigned char* buffer,uint8_t seq_numb,uint8_t len,bool lastFlag,char* chunk,sockaddr_in* client_addr, int addr_size);
void send_challengeUnavailable(int socket, unsigned char* buffer, uint8_t seqNum, sockaddr_in* clientAddress, int clientAddressLen);
void send_challengeStart(int socket,unsigned char* buffer,char* ip,unsigned char* public_key,uint8_t seqNum,sockaddr_in* client_addr,int addr_size);
void send_exit(int socket, unsigned char* buffer,char* username, uint8_t seqNum,sockaddr_in* sv_addr_priv,int addr_size);
void send_login(int socket,unsigned char* buffer,char* username,uint8_t len,sockaddr_in* sv_addr_main,int addr_main);
void send_signature_message(int socket,unsigned char* buffer,unsigned char* random_data,char* username,int sizeCertificate,struct sockaddr_in* address,int address_size,bool serverCall);
void send_certificate_message(int socket,unsigned char* certificate,int certificateLen,struct sockaddr_in* address,int address_size);
void send_DHmessage(int socket,int pkey_len,struct sockaddr_in* sv_addr, unsigned char* myDHpubkey,char* username,bool serverCall);
void send_DHmessage_info(int socket, int pkey_len,struct sockaddr_in* sv_addr, char* username, bool serverCall);
