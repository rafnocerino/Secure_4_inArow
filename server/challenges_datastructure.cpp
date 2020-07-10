#include "challenges_datastructure.h"

pthread_mutex_t lockChallengeDataStructure = PTHREAD_MUTEX_INITIALIZER;
int challengesDataStructureSize = 0;
int lastChallengeNumber = 0;
//	vettore con le entry che descrivono le challenges tra gli utenti
vector <challengeDataStructure> challengesDataStructure;

vector <challengeDataStructure> getChallengesDataStructure(){
	return challengesDataStructure;
}

int addNewChallengeDataStructure(string username1,string username2){

	//Controllo che l'utente sfidato sia ancora in attesa di essere sfidato
	if(getStatusUserDataStructure(username2) != STATUS_WAITING)
		return -1;

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

	return newChallengeDataStructure->challengeNumber;
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

bool updateChallengeDataStructure(int challengeNumber,int newStatus){
	int indexChallengeNumber = searchChallengeDataStructureFromChallengeNumber(challengeNumber);
	if(indexChallengeNumber == -1){
		return false;
	}
	challengesDataStructure.at(indexChallengeNumber).status = newStatus;
	return true;
}
