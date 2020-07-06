#include <string>
#include <vector>
#include "users_datastructure.h"
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

pthread_mutex_t lockChallengeDataStructure = PTHREAD_MUTEX_INITIALIZER;
int challengesDataStructureSize = 0;
int lastChallengeNumber = 0;
//	vettore con le entry che descrivono le challenges tra gli utenti
vector <challengeDataStructure> challengesDataStructure;

bool addNewChallengeDataStructure(int challengeNumber,string username1,string username2){

	//Controllo che l'utente sfidato sia ancora in attesa di essere sfidato
	if(getStatusUserDataStructure(username2) != 2)
		return false;

	challengeDataStructure* newChallengeDataStructure = new challengeDataStructure(); 
	newChallengeDataStructure->username1 = username1;
	newChallengeDataStructure->username2 = username2;
	newChallengeDataStructure->status = 0;
	pthread_mutex_lock(&lockChallengeDataStructure);
		newChallengeDataStructure->challengeNumber = lastChallengeNumber;
		challengesDataStructure.push_back(*newChallengeDataStructure);
		challengesDataStructureSize += 1;
		lastChallengeNumber = (lastChallengeNumber + 1) % MAX_INT_ON_4_BYTE;
	pthread_mutex_unlock(&lockChallengeDataStructure);
}

int searchChallengeDataStructureFromChallengeNumber(int challengeNumber){
	for(int i = 0; i < challengesDataStructureSize ; i++){
		if(challengesDataStructure.at(i).challengeNumber == challengeNumber)
			return i;
	}
	return -1;	
}

bool removeChallengeDataStructureFromChallengeNumber(int challengeNumber){
	int currentIndex = searchChallengeDataStructureFromChallengeNumber(challengeNumber);
	if(currentIndex == -1){
		return false;
	}
	challengesDataStructure.erase(challengesDataStructure.begin() + currentIndex);
	return true;
}
