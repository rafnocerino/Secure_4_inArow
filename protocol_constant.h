#include <math.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

//File per le costanti della dimensione dei campi dei messaggi espresse in byte
#define SIZE_OPCODE 1
#define SIZE_SEQNUMBER 1
#define SIZE_LEN 1
#define SIZE_LAST_FLAG 1
#define SIZE_CHALLENGE_NUMBER 4
#define SIZE_STATUS_CODE 1
#define SIZE_IP_ADDRESS 16
#define SIZE_PUBLIC_KEY 451
#define SIZE_CHALLENGE_NUMBER 4
#define SIZE_RANDOM_DATA 16
#define SIZE_SESSION_KEY 32
#define SIZE_SIGNATURE 256
#define SIZE_CERTIFICATE_LEN 4
#define SIZE_DH_PUBLIC_KEY_LEN 4
#define SIZE_IV 16 

const int SIZE_TAG = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
const int SIZE_AAD = EVP_CIPHER_iv_length(EVP_aes_256_gcm());

//Lunghezze in byte di tutti i messaggi
const unsigned int SIZE_MESSAGE_LOGIN = SIZE_OPCODE + SIZE_LEN + pow(2,8*SIZE_LEN);
const unsigned int SIZE_MESSAGE_SIGNATURE_MESSAGE = SIZE_OPCODE + SIZE_CERTIFICATE_LEN + SIZE_RANDOM_DATA + SIZE_SIGNATURE;
const unsigned long int SIZE_MESSAGE_CERTIFICATE = SIZE_OPCODE + pow(2,8*SIZE_CERTIFICATE_LEN);
const unsigned int SIZE_MESSAGE_AVAILABLE_USER_LIST = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LAST_FLAG + SIZE_LEN + pow(2,8*SIZE_LEN) + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_CHALLENGE_REQUEST = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER + SIZE_LEN + pow(2,8*SIZE_LEN) + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_CHALLENGE_ACCEPTED = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_CHALLENGE_START = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_PUBLIC_KEY + SIZE_LEN + SIZE_IP_ADDRESS + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_CHALLENGE_REFUSED = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_CHALLENGE_UNAVAILABLE = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_UPDATE_STATUS = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_STATUS_CODE + SIZE_LEN + pow(2,8*SIZE_LEN) + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_ACK = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_EXIT = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN + pow(2,8*SIZE_LEN) + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_MALFORMED_MEX = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_IV + SIZE_TAG + SIZE_AAD;
const unsigned int SIZE_MESSAGE_DH_MESSAGE_INFO = SIZE_OPCODE + SIZE_DH_PUBLIC_KEY_LEN + SIZE_SIGNATURE;
/*--------------------------------------------STATUS-CODE---------------------------------------------------------------*/
#define STATUS_IDLE 0
#define STATUS_CHALLENGING 1
#define STATUS_WAITING 2
#define STATUS_IN_CHALLENGE 3
/*----------------------------------------------------------------------------------------------------------------------*/

/*--------------------------------------------OPCODE--------------------------------------------------------------------*/
#define OPCODE_LOGIN 0
#define OPCODE_SIGNATURE_MESSAGE 1
#define OPCODE_CERTIFICATE 2
#define OPCODE_AVAILABLE_USER_LIST 3
#define OPCODE_CHALLENGE_REQUEST 4
#define OPCODE_CHALLENGE_ACCEPTED 5
#define OPCODE_CHALLENGE_START 6
#define OPCODE_DH_MESSAGE 7
#define OPCODE_CHALLENGE_REFUSED 8
#define OPCODE_CHALLENGE_UNAVAILABLE 9
#define OPCODE_UPDATE_STATUS 10
#define OPCODE_ACK 11
#define OPCODE_EXIT 12
#define OPCODE_MALFORMED_MEX 13 
#define OPCODE_DH_MESSAGE_INFO 14
/*----------------------------------------------------------------------------------------------------------------------*/

#define WAIT_TIME_LOGIN 30


#define BUF_SIZE 1024
