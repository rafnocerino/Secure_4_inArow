#include <math.h>
//File per le costanti della dimensione dei campi dei messaggi espresse in byte
#define SIZE_OPCODE 1
#define SIZE_SEQNUMBER 1
#define SIZE_LEN 1
#define SIZE_LEN_AVAILABLE_USER_LIST 4
#define SIZE_LAST_FLAG 1
#define SIZE_CHALLENGE_NUMBER 4
#define SIZE_STATUS_CODE 1
#define SIZE_IP_ADDRESS 16
#define SIZE_PUBLIC_KEY 16

//Lunghezze in byte di tutti i messaggi
const unsigned int SIZE_MESSAGE_LOGIN = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN + pow(2,8*SIZE_LEN);
const unsigned int SIZE_MESSAGE_LOGIN_OK = SIZE_OPCODE + SIZE_SEQNUMBER;
const unsigned int SIZE_MESSAGE_LOGIN_NO = SIZE_OPCODE + SIZE_SEQNUMBER;
const unsigned int SIZE_MESSAGE_AVAILABLE_USER_LIST = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN_AVAILABLE_USER_LIST + pow(2,8*SIZE_LEN_AVAILABLE_USER_LIST);
const unsigned int SIZE_MESSAGE_CHALLENGE_REQUEST = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER + SIZE_LEN + pow(2,8*SIZE_LEN);
const unsigned int SIZE_MESSAGE_CHALLENGE_ACCEPTED = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER;
const unsigned int SIZE_MESSAGE_CHALLENGE_START = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_PUBLIC_KEY + SIZE_IP_ADDRESS;
const unsigned int SIZE_MESSAGE_CHALLENGE_TIMER_EXPIRED = SIZE_OPCODE + SIZE_SEQNUMBER;
const unsigned int SIZE_MESSAGE_CHALLENGE_REFUSED = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER;
const unsigned int SIZE_MESSAGE_CHALLENGE_UNAVAILABLE = SIZE_OPCODE + SIZE_SEQNUMBER;
const unsigned int SIZE_MESSAGE_UPDATE_STATUS = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_STATUS_CODE + SIZE_LEN + pow(2,8*SIZE_LEN);
const unsigned int SIZE_MESSAGE_ACK = SIZE_OPCODE + SIZE_SEQNUMBER;
const unsigned int SIZE_MESSAGE_EXIT = SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN + pow(2,8*SIZE_LEN);
const unsigned int SIZE_MESSAGE_MALFORMED_MEX = SIZE_OPCODE + SIZE_SEQNUMBER;

/*--------------------------------------------STATUS-CODE---------------------------------------------------------------*/
#define STATUS_IDLE 0
#define STATUS_CHALLENGING 1
#define STATUS_WAITING 2
/*----------------------------------------------------------------------------------------------------------------------*/

/*--------------------------------------------OPCODE--------------------------------------------------------------------*/
#define OPCODE_LOGIN 0
#define OPCODE_LOGIN_OK 1
#define OPCODE_LOGIN_NO 2
#define OPCODE_AVAILABLE_USER_LIST 3
#define OPCODE_CHALLENGE_REQUEST 4
#define OPCODE_CHALLENGE_ACCEPTED 5
#define OPCODE_CHALLENGE_START 6
#define OPCODE_CHALLENGE_TIMER_EXPIRED 7
#define OPCODE_CHALLENGE_REFUSED 8
#define OPCODE_CHALLENGE_UNAVAILABLE 9
#define OPCODE_UPDATE_STATUS 10
#define OPCODE_ACK 11
#define OPCODE_EXIT 12
#define OPCODE_MALFORMED_MEX 13 
/*----------------------------------------------------------------------------------------------------------------------*/
