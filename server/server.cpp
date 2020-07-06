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
#include <openssl/rand.h>

#include "../protocol_constant.h"
#include "../check_message.h"
#include "../send_message.h"

#include "users_datastructure.h"

using namespace std;

#define SERVER_PORT 7799
#define MAX_REQUEST 50
#define BUF_SIZE 512

pthread_mutex_t lockIndexesAvailableTID = PTHREAD_MUTEX_INITIALIZER; //[06]
sem_t indexesSem;
vector<int> indexesAvailableTID;
pthread_mutex_t lockSequenceNumber = PTHREAD_MUTEX_INITIALIZER;
uint8_t lastSequenceNumber;

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
	printf("Messaggio ricevuto:\n");
 	BIO_dump_fp (stdout, (const char *)loginMessage, sizeMessageRecived);
	uint8_t seqNum;
	char* username;
	username = (char *) malloc(sizeMessageRecived - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN));
	unsigned char* sendBuffer;
	sendBuffer = (unsigned char*)malloc(BUF_SIZE);	
	int threadSocket = socket(AF_INET,SOCK_DGRAM,0);
	struct sockaddr_in threadSockAddr;	
	threadSockAddr.sin_family=AF_INET;
	threadSockAddr.sin_port=htons(0);
	threadSockAddr.sin_addr.s_addr=INADDR_ANY;
	if(bind(threadSocket,(struct sockaddr*)&threadSockAddr,sizeof(threadSockAddr)) < 0){
		printf("ERRORE: e' stato riscontrato un errore nella fase di bind del socket per comunicare con il server.\n");
	}else{
		if(check_login(loginMessage,sizeMessageRecived,&seqNum,username)){
			printf("Il messaggio di login ricevuto e' corretto.\n");
			printf("SEQ.NUMBER RICEVUTO: %u.\n",seqNum);
			printf("USERNAME. RICEVUTO: %s.\n",username);
			send_ACK(threadSocket, sendBuffer,OPCODE_ACK, seqNum, &clientAddress, sizeof(clientAddress));
			if(addNewUserDataStructure(username,clientAddress)){
				pthread_mutex_lock(&lockSequenceNumber);
					seqNum = lastSequenceNumber;
					lastSequenceNumber = (lastSequenceNumber + 1) % 256;
				pthread_mutex_unlock(&lockSequenceNumber);
				send_loginOK(threadSocket,sendBuffer,OPCODE_LOGIN_OK,seqNum,&clientAddress, sizeof(clientAddress));

				//Mi metto in attesa dell'ack
				memset(sendBuffer, 0, BUF_SIZE);
				sizeMessageRecived = recvfrom(threadSocket, sendBuffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)clientAddress, &clientAddressLen);

				if(sizeMessageRecived < SIZE_MESSAGE_ACK){
					perror("There was an error during the reception of the ACK ! \n");
					memset(sendBuffer, 0, BUF_SIZE);
					send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
					close(threadSocket);
				}else{
					if(check_ack(threadSocket,sendBuffer,sizeMessageRecived,OPCODE_ACK,seqNum)){
						//Invio della lista di utenti disponibili
						vector<string> availableUserList = availableUserListUserDataStructure();
						//for(int i=0;availableUserList.size())
					}else{
						memset(sendBuffer, 0, BUF_SIZE);
						send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
						close(threadSocket);
					}
				}
			}else{
				//Invio del messaggio login NO
			}
		}else{
			printf("Il messaggio di login ricevuto e' malformato.\n");
			send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
		}		
	}
	pthread_mutex_lock(&lockIndexesAvailableTID);
		indexesAvailableTID.push_back(threadIndex);	
	pthread_mutex_unlock(&lockIndexesAvailableTID);
    sem_post(&indexesSem);	
	printf("Esco dal thread serveClient.\n");
	pthread_exit(NULL);
}

int main(){
	indexesAvailableTID = intializeIndexesAvailableTID();
	sem_init(&indexesSem,0,MAX_REQUEST);

	//Inizializzazione in maniera casuale del sequence number per i messaggi inviati dal server	utilizzando OpenSSL
	RAND_poll();
	RAND_bytes(&lastSequenceNumber,1);

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
		unsigned int sizeClientAddress = sizeof(struct sockaddr_in);
		sem_wait(&indexesSem);
		pthread_mutex_lock(&lockIndexesAvailableTID);
			currentRequest->threadIndex = indexesAvailableTID.back();
			indexesAvailableTID.pop_back();
		pthread_mutex_unlock(&lockIndexesAvailableTID);
		currentRequest->sizeMessageRecived = recvfrom(serverSocket,&currentRequest->loginMessage,SIZE_MESSAGE_LOGIN,0,(struct sockaddr*)&currentRequest->clientAddress ,&sizeClientAddress);
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

/*----------------------------------COMMENTI----------------------------------------------------------------------------
[] sys/socket.h definisce i seguenti metodi:
   - int socket(int domain, int type, int protocol)	
[] netinet/in.h contiene la struttura dati sockaddr_in necessaria a contenere le informazioni su porta e indirizzo
[] il metodo socket crea un socket in particolare PF_INET serve a specificare che si utilizzano indirizzi IPv4, SOCK_DGRAM che verrà usato il protocollo UDP mentre il terzo parametro può essere trascurato
[] htons assicura che i numeri vengono memorizzati in memoria secondo il byte order della rete che prevede che i byte più significativi vengano messi prima quindi assicura che i numeri siano memorizzati come lo sarebbero in una macchina big endian. 
[] Nel server INADDR_ANY è un argomento della bind che indica che il socket deve mettersi in ascolto su tutte le interfacce.
[] Il metodo bind serve ad assegnare un indirizzo locale ad un socket (quindi la prima metà di un socket pair) e serve quindi a specificare su quale IP:porta il server si metterà in ascolto. Il client invece non deve andare a invocare la bind in quanto sarà il kernel ad assegnargli la porta mentre l'IP sarà quello dell'interfaccia di rete utilizzata
[] Definizione delle buffer che conterrà i messaggi di login dei vari client che arrivano al server
[] A questo punto sia che il messaggio sia corretto sia che non lo sia devo creare un nuovo socket per rispondere al client*/

