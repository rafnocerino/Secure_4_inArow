#include <string>
#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h> //Per sockaddr_in
using namespace std;

bool addNewUserDataStructure(string username,struct sockaddr_in IPaddress);
bool removeUserDataStructure(string username);
int getStatusUserDataStructure(string username);
bool setStatusUserDataStructure(int newStatus,string username);
bool getIPUserDataStructure(string username,struct sockaddr_in* requestedIP);
vector<string> availableUserListUserDataStructure();
void printUserDataStructure();
