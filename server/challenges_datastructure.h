#include <string>
#include <vector>
#include "users_datastructure.h"
#include "../protocol_constant.h"
using namespace std;
#define MAX_INT_ON_4_BYTE 2147483648

struct challengeDataStructure{
	//	challenge number
	int challengeNumber;
	//	username dello sfidante
	string username1;
	//	username dello sfidato
	string username2;
	//	stato della sfida
	int status;	
};

int addNewChallengeDataStructure(string username1,string username2);
int searchChallengeDataStructureFromChallengeNumber(int challengeNumber);
bool removeChallengeDataStructureFromChallengeNumber(int challengeNumber);
vector <challengeDataStructure> getChallengesDataStructure();
