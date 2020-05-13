#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

bool check_challengeStart(int socket,unsigned char* buffer, int messageLength,uint8_t exp_seq_numb,unsigned char* ip,unsigned char* adv_pubkey);
bool check_challenge_Unavailable(int socket, unsigned char* buffer, int messageLength, uint8_t exp_seq_numb);
bool check_ack(int socket, unsigned char* buffer, unsigned int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb);
bool check_challengeRequest(int socket, unsigned char* buffer, unsigned int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,
                            unsigned char* challenging_user, int& challenge_id, uint8_t& rcv_seq_numb);
bool check_login(unsigned char* message, unsigned int messageLength,uint8_t* seqNum,char* username); 
