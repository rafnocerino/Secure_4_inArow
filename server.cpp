#include <unistd.h>
#include <sys/socket.h> //[]
#include <arpa/inet.h>
#include <netinet/in.h> //[]
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <semaphore.h>
#include <vector>
#include <pthread.h>
#include <math.h>
#include <openssl/evp.h>
#include "protocol_constant.h"
#include "check_message.h"

using namespace std;

#define SERVER_PORT 7799
#define MAX_REQUEST 50

pthread_mutex_t lockIndexesAvailableTID = PTHREAD_MUTEX_INITIALIZER; //[06]
sem_t indexesSem;
vector<int> indexesAvailableTID;

struct request{
	int threadIndex;
	socklen_t clientAddressLen;
	struct sockaddr_in clientAddress;
	char loginMessage[SIZE_MESSAGE_LOGIN];
	unsigned int sizeMessageRecived;
};

vector<int> intializeIndexesAvailableTID(){
	vector<int> result;
	for(int i=0;i<MAX_REQUEST;i++)
		result.push_back(i);
	return result;
}

void* serveClient(void *arg){
	unsigned int sizeMessageRecived = ((struct request*)arg)->sizeMessageRecived;
	unsigned char* loginMessage;
	loginMessage = (unsigned char*) malloc(sizeMessageRecived);	
    memcpy(loginMessage,((struct request*)arg)->loginMessage, sizeMessageRecived);
	int threadIndex = ((struct request*)arg)->threadIndex;
	socklen_t clientAddressLen = ((struct request*)arg)->clientAddressLen;
	struct sockaddr_in clientAddress = ((struct request*)arg)->clientAddress;
	pthread_mutex_lock(&lockIndexesAvailableTID);
		indexesAvailableTID.push_back(threadIndex);	
	pthread_mutex_unlock(&lockIndexesAvailableTID);
	printf("Messaggio ricevuto:\n");
 	BIO_dump_fp (stdout, (const char *)loginMessage, sizeMessageRecived);
	uint8_t opcode;
	uint8_t seqNum;
	uint8_t len;
	char* username;
	username = (char *) malloc(sizeMessageRecived - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN));
	int memcpyPos = 0; 

	memcpy(&opcode, loginMessage + memcpyPos,SIZE_OPCODE);
	printf("OPCODE RICEVUTO: %u.\n",opcode);
	memcpyPos += SIZE_OPCODE;

	memcpy(&seqNum, loginMessage +memcpyPos,SIZE_SEQNUMBER);
	printf("SEQ.NUMBER RICEVUTO: %u.\n",seqNum);
	memcpyPos += SIZE_SEQNUMBER;
	
	memcpy(&len, loginMessage + memcpyPos,SIZE_LEN);
	printf("LEN. RICEVUTA: %u.\n",len);
	memcpyPos += SIZE_LEN;

	memcpy(username,loginMessage + memcpyPos,sizeMessageRecived - memcpyPos); 
	printf("USERNAME. RICEVUTO: %s.\n",username);
	
	if(check_message(OPCODE_LOGIN,loginMessage,sizeMessageRecived)){
		printf("Il messaggio di login ricevuto e' corretto.\n");
	}else{
		printf("Il messaggio di login ricevuto e' malformato.\n");
	}
    sem_post(&indexesSem);	
	printf("Esco dal thread serveClient.\n");
	pthread_exit(NULL);
}

int main(){
	indexesAvailableTID = intializeIndexesAvailableTID();
	sem_init(&indexesSem,0,MAX_REQUEST);
	int serverSocket;
	struct sockaddr_in serverAddress;
	memset(&serverAddress,0,sizeof(serverAddress));
	serverSocket = socket(AF_INET,SOCK_DGRAM,0); //[]
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(SERVER_PORT); //[]
	serverAddress.sin_addr.s_addr = INADDR_ANY; //[]
	if(bind(serverSocket, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0){ //[]
		printf("ERRORE: e' stato riscontrato un errore nella fase di bind.\n");
		exit(-1);
	}else{
		printf("Creato socket di ascolto.\n");
	}
	pthread_t tid[MAX_REQUEST];
	while(1){
		struct request* currentRequest = (struct request*)malloc(sizeof(struct request));
		unsigned int sizeClientAddress = sizeof(currentRequest->clientAddress);
		sem_wait(&indexesSem);
		pthread_mutex_lock(&lockIndexesAvailableTID);
			currentRequest->threadIndex = indexesAvailableTID.back();
			indexesAvailableTID.pop_back();
		pthread_mutex_unlock(&lockIndexesAvailableTID);
		currentRequest->sizeMessageRecived = recvfrom(serverSocket,&currentRequest->loginMessage,SIZE_MESSAGE_LOGIN,0,(struct sockaddr*)&currentRequest->clientAddress,&currentRequest->clientAddressLen);
		if(currentRequest->sizeMessageRecived < 0){
			printf("ERRORE: il messaggio non e' stato ricevuto correttamente dal main socket.\n"); 
		}else{
			if(pthread_create(&tid[currentRequest->threadIndex],NULL,serveClient,(void*)currentRequest) != 0 ){
				printf("ERRORE: e' stato riscontrato un errore nella fase di creazione di un thread.\n");
			}
		}
	}
	sem_destroy(&indexesSem);
	return 0;
}

/*-----------------------------------------------------COMMENTI----------------------------------------------------------------------------
[] sys/socket.h definisce i seguenti metodi:
   - int socket(int domain, int type, int protocol)	
[] netinet/in.h contiene la struttura dati sockaddr_in necessaria a contenere le informazioni su porta e indirizzo
[] il metodo socket crea un socket in particolare PF_INET serve a specificare che si utilizzano indirizzi IPv4, SOCK_DGRAM che verrà usato il protocollo UDP mentre il terzo parametro può essere trascurato
[] htons assicura che i numeri vengono memorizzati in memoria secondo il byte order della rete che prevede che i byte più significativi vengano messi prima quindi assicura che i numeri siano memorizzati come lo sarebbero in una macchina big endian. 
[] Nel server INADDR_ANY è un argomento della bind che indica che il socket deve mettersi in ascolto su tutte le interfacce.
[] Il metodo bind serve ad assegnare un indirizzo locale ad un socket (quindi la prima metà di un socket pair) e serve quindi a specificare su quale IP:porta il server si metterà in ascolto. Il client invece non deve andare a invocare la bind in quanto sarà il kernel ad assegnargli la porta mentre l'IP sarà quello dell'interfaccia di rete utilizzata
[] Definizione delle buffer che conterrà i messaggi di login dei vari client che arrivano al server*/
