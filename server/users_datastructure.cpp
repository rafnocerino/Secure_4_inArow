#include "users_datastructure.h"
#include "../protocol_constant.h"

struct userDataStructure{
	//	username
	string username;
	//	status of the user
	int status;
	//	IP address
	struct sockaddr_in IPaddress;
};

pthread_mutex_t lockUsersDataStructure = PTHREAD_MUTEX_INITIALIZER;
//	vettore con le entry che descrivono gli utenti sarà 
vector <userDataStructure> usersDataStructure;

bool addNewUserDataStructure(string username,struct sockaddr_in IPaddress){
	string newUsername = username;
	struct sockaddr_in newIPaddress = IPaddress;
	int newStatus = 0;
	userDataStructure* newUser = new userDataStructure();
	newUser->username = username;
	newUser->status = newStatus;
	newUser->IPaddress = newIPaddress; 
	int found = 0;
	pthread_mutex_lock(&lockUsersDataStructure);
		for(int i = 0 ; i < usersDataStructure.size() && found==0; i++){
			if(usersDataStructure.at(i).username.compare(username) >= 0){
				if(usersDataStructure.at(i).username.compare(username) == 0){
					found = -1;
				}else{
					usersDataStructure.insert(usersDataStructure.begin()+i,*newUser);
					found = 1;
				}
			}
		}
		//Se non e' stato ancora trovato vuol dire che va messo in ultima posizione
		if(found == 0){
			usersDataStructure.push_back(*newUser);
		} 	
	pthread_mutex_unlock(&lockUsersDataStructure);
	printUserDataStructure();	
	return found == -1 ? false : true;
}

int bSearchUserDataStructureFromUsername(string username){
	int currentIndex;
	int startIndex = 0; 	
	int lastIndex = usersDataStructure.size() - 1; 	
	while(startIndex <= lastIndex){
		currentIndex = (startIndex + lastIndex)/2;
		if(usersDataStructure.at(currentIndex).username.compare(username) == 0){
			return currentIndex;
		}
		if(usersDataStructure.at(currentIndex).username.compare(username) < 0){
			startIndex = currentIndex + 1;
		}else{
			lastIndex = currentIndex - 1;
		}
	}
	return -1;
}


bool removeUserDataStructure(string username){
	int currentIndex  = bSearchUserDataStructureFromUsername(username);
	if(currentIndex == -1){
		return false;
	}
	pthread_mutex_lock(&lockUsersDataStructure);
		usersDataStructure.erase(usersDataStructure.begin() + currentIndex);	
	pthread_mutex_unlock(&lockUsersDataStructure);
	return true;
}

int getStatusUserDataStructure(string username){
	int currentIndex = bSearchUserDataStructureFromUsername(username);
	if(currentIndex == -1){
		return -1;
	}
	return usersDataStructure.at(currentIndex).status;	
} 

bool setStatusUserDataStructure(int newStatus,string username){
	int currentIndex = bSearchUserDataStructureFromUsername(username);
	if(currentIndex == -1){
		return false;
	}
	pthread_mutex_lock(&lockUsersDataStructure);
		usersDataStructure.at(currentIndex).status = newStatus;
	pthread_mutex_unlock(&lockUsersDataStructure);
	return true;	
}

bool getIPUserDataStructure(string username,struct sockaddr_in* requestedIP){
	int currentIndex = bSearchUserDataStructureFromUsername(username);
	if(currentIndex == -1){
		return false;
	}
	*requestedIP = usersDataStructure.at(currentIndex).IPaddress; 
	return true;
}

vector<string> availableUserListUserDataStructure(){
	vector<string> availableUserList;
	for(int i = 0; i < usersDataStructure.size() ; i++){
		if(usersDataStructure.at(i).status == STATUS_WAITING){
			availableUserList.push_back(usersDataStructure.at(i).username);
		}	
	}
	return availableUserList;
} 

void printUserDataStructure(){
	for(int i = 0; i < usersDataStructure.size() ; i++){
		char buffer[INET_ADDRSTRLEN];
		inet_ntop( AF_INET, &usersDataStructure.at(i).IPaddress.sin_addr, buffer, sizeof( buffer ));
		cout<<usersDataStructure.at(i).username<<","<<usersDataStructure.at(i).status<<","<<buffer<<"\n";	
	}
}
