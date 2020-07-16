#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
using namespace std;

bool check_challengeRefused(int socket,unsigned char* buffer, int messageLength,uint8_t exp_seq_numb,int* challengeId,unsigned char* key);
bool check_challengeStart(int socket,unsigned char* buffer, int messageLength,uint8_t exp_seq_numb,unsigned char* ip,unsigned char* adv_pubkey,unsigned char* key);
bool check_challengeUnavailable(int socket, unsigned char* buffer, int messageLength, uint8_t exp_seq_numb,unsigned char* key);
bool check_ack(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,unsigned char* key);
bool check_challengeRequest(int socket, unsigned char* buffer, int messageLength, uint8_t exp_opcode, uint8_t exp_seq_numb,char* challenging_user, int& challenge_id, uint8_t& rcv_seq_numb, char* challengedUser,unsigned char* key);
bool check_login(int socket,unsigned char* message, int messageLength,char* username);
bool check_updateStatus(int socket,unsigned char* message,int messageLength,uint8_t expectedSeqNum,uint8_t& statusCode,char* username,unsigned char* key); 
bool check_exit(int socket,unsigned char* message,int messageLength,uint8_t expectedSeqNum,char* username,unsigned char* key);
bool check_challengeAccepted(int socket,unsigned char* buffer,int messageLength,uint8_t expectedSeqNum,int* challengeNumber,unsigned char* key);
bool check_available_userList(int socket,unsigned char* buffer,int& list_len,int messageLength,uint8_t exp_seq_numb,char* available_users,int& flag,unsigned char* key);
bool check_signature_message_server(unsigned char* buffer,int messageLength,unsigned char* expectedRandomData);
bool check_certificateMessage(unsigned char* certificate_buffer,int messageLength,int cert_len);
bool check_signatureMessageClient(unsigned char* buffer,int messageLength,unsigned char* random_data,unsigned char* signature);
bool check_DHmessage(unsigned char* buffer,int messageLength,int pkey_len,unsigned char* peer_dh_pubkey);
bool check_DHmessage_info(unsigned char* buffer, int messageLength,int& pkey_len);
bool check_FirstAvailable_userList(int socket, unsigned char* buffer,int& list_len,int messageLength,uint8_t& seq_numb,char* available_users,int& flag, unsigned char* key);
