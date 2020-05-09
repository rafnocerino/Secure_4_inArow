#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
using namespace std;

bool check_message(uint8_t desiredOpcode,unsigned char* message,unsigned int messageLength,int desiredSequenceNumber = -1);
