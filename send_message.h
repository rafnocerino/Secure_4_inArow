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

void send_challengeRequest(int socket, struct sockaddr_in* sv_addr, int addr_size, unsigned char* buffer, char* challenger, char* challenged,
                           uint8_t seq_numb, int challenge_id);
void send_challengeRefused(int socket, unsigned char* buffer, uint8_t seq_numb, int challenge_id, sockaddr_in* sv_addr_challenge, int addr_size);
void send_challengeAccepted(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr_challenging, int addr_size,
                            int challenge_id);
void send_malformedMsg(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size);
void send_ACK(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size);
void send_UpdateStatus(int socket, unsigned char* buffer, char* username, uint8_t user_size, uint8_t op_code, uint8_t seq_numb, uint8_t status_code,
                       sockaddr_in* sv_addr, int addr_size);
