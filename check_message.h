#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

bool check_challengeTimerExpired(int socket,unsigned char* buffer,int messageLenght,uint8_t exp_seq_numb);
bool check_challengeRefused(int socket,unsigned char* buffer, int messageLenght,uint8_t exp_seq_numb,int* challengeId);
bool check_challengeStart(int socket,unsigned char* buffer, int messageLength,uint8_t exp_seq_numb,unsigned char* ip,unsigned char* adv_pubkey);
bool check_challengeUnavailable(int socket, unsigned char* buffer, int messageLength, uint8_t exp_seq_numb);
bool check_ack(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb) ;
bool check_challengeRequest(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,char* challenging_user, int& challenge_id, uint8_t& rcv_seq_numb);
bool check_login(int socket,unsigned char* message, int messageLength,uint8_t& seqNum,char* username);
bool check_updateStatus(unsigned char* message,int messageLength,uint8_t expectedSeqNum,uint8_t* statusCode,char* username); 
bool check_exit(unsigned char* message,int messageLength,uint8_t expectedSeqNum,char* username);
bool check_challengeAccepted(unsigned char* buffer,int messageLength,uint8_t expectedSeqNum,int* challengeNumber);
bool check_available_userList(int socket, unsigned char* buffer,int& list_len,int messageLength,uint8_t exp_seq_numb,char* available_users,int& flag);