#include "check_message.h"
#include "protocol_constant.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
using namespace std;

bool check_message_login(unsigned char* message,unsigned int messageLength){
	uint8_t actualOpcode;
	uint8_t actualLength;	
	memcpy(&actualOpcode,message,SIZE_OPCODE);
	if(actualOpcode != OPCODE_LOGIN)
		return false;
	memcpy(&actualLength,message+SIZE_OPCODE+SIZE_SEQNUMBER,SIZE_LEN);
	if(actualLength != messageLength - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN + 1)) //L'uno in più è per il carattere di terminazione della stringa
		return false;
	return true;	
}

bool check_message(uint8_t desiredOpcode,unsigned char* message,unsigned int messageLength,int desiredSequenceNumber){
	switch(desiredOpcode){
		case OPCODE_LOGIN:{
			return check_message_login(message,messageLength);
			break;
		}
		
	}
}
