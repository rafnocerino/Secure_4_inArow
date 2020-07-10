//#include <unistd.h>
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
#include <cstdint>
#include <math.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif


//#include "../protocol_constant.h"
#include "../check_message.h"
#include "../send_message.h"

#include "users_datastructure.h"
#include "challenges_datastructure.h"
using namespace std;

#define SERVER_PORT 7799
#define MAX_REQUEST 50
#define BUF_SIZE 512
#define SLEEP 60

pthread_mutex_t lockIndexesAvailableTID = PTHREAD_MUTEX_INITIALIZER; //[06]
sem_t indexesSem;
vector<int> indexesAvailableTID;

struct request{
	int threadIndex;
	socklen_t clientAddressLen;
	struct sockaddr_in clientAddress;
	char loginMessage[SIZE_MESSAGE_LOGIN];
	unsigned int sizeMessageReceived;
};

struct timer{
	int challengeId;
	int socket;
	unsigned char* buffer;
	struct sockaddr_in clientAddress;	
	bool *exitORerror;
	uint8_t* seqNum;
};

vector<int> intializeIndexesAvailableTID(){
	vector<int> result;
	for(int i=0;i<MAX_REQUEST;i++)
		result.push_back(i);
	return result;
}

bool receive_ACK(int socket,uint8_t expSeqNum, sockaddr_in* clientAddress,int clientAddressLen){
	uint8_t seqNum = expSeqNum;
	uint8_t opcode = OPCODE_ACK;
	unsigned char* buffer = (unsigned char*)malloc(BUF_SIZE);
	socklen_t addressLen;
	int sizeMessageReceived = recvfrom(socket,buffer,SIZE_MESSAGE_ACK, 0, (struct sockaddr*)clientAddress,&addressLen);
	if(sizeMessageReceived < SIZE_MESSAGE_ACK){
		perror("There was an error during the reception of the ACK ! \n");
		memset(buffer, 0, BUF_SIZE);
		send_malformedMsg(socket,buffer,OPCODE_MALFORMED_MEX, seqNum,clientAddress, sizeof(clientAddress));
		close(socket);
		return false;
	}
	if(!check_ack(socket,buffer,sizeMessageReceived,OPCODE_ACK,seqNum)){
		send_malformedMsg(socket,buffer,OPCODE_MALFORMED_MEX, seqNum,clientAddress, sizeof(clientAddress));
	}
	return true;	
}

void* timer_thread(void *arg){
	
	int challengeId = ((struct timer*)arg)->challengeId;
	int socket = ((struct timer*)arg)->socket;	
	unsigned char* buffer = ((struct timer*)arg)->buffer;
	struct sockaddr_in clientAddress = ((struct timer*)arg)->clientAddress;	
	bool *exitORerror = ((struct timer*)arg)->exitORerror;
	uint8_t* seqNum = ((struct timer*)arg)->seqNum;
	memset(buffer,0,BUF_SIZE);	

	//sleep:
	#ifdef _WIN32
	Sleep(SLEEP);
	#else
	usleep(SLEEP*1000);  /* sleep for 100 milliSeconds */
  	#endif
	
	if(removeChallengeDataStructureFromChallengeNumber(challengeId)){
		//Se la challenge e' presente all'interno della struttura dati significa che non vi e' stata ancora una risposta
		//Percio' devo inviare un messaggio challenge timer expired:
		*seqNum = * seqNum + 1;
		//Invio il messaggio di timer expired		
		send_challengeTimerExpired(socket,buffer,*seqNum,&clientAddress,sizeof(clientAddress));
		//Aspetto il relativo ACK
		if(!receive_ACK(socket,OPCODE_ACK,&clientAddress,sizeof(clientAddress))){
			*exitORerror = true;
		}
	}
}

bool receive_UpdateStatus(int socket,unsigned char* sendBuffer,sockaddr_in* clientAddress,int clientAddressLen,uint8_t* statusCode){
	unsigned char* buffer = (unsigned char*)malloc(BUF_SIZE);
	socklen_t addressLen;
	int sizeMessageReceived = recvfrom(socket, buffer, SIZE_MESSAGE_UPDATE_STATUS, 0, (struct sockaddr*)clientAddress, &addressLen);
	uint8_t seqNum;
	char* username = (char *) malloc(sizeMessageReceived - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN + SIZE_STATUS_CODE));

	if(check_updateStatus(buffer,sizeMessageReceived,seqNum,statusCode,username)){
		printf("Il messaggio di update status ricevuto e' corretto.\n");
		printf("SEQ.NUMBER RICEVUTO: %u.\n",seqNum);
		printf("STATUS CODE RICEVUTO: %u.\n",*statusCode);
		printf("USERNAME. RICEVUTO: %s.\n",username);

		//Aggiorno la struttura dati con l'informazioni degli utenti
		setStatusUserDataStructure(*statusCode,username);

		send_ACK(socket,sendBuffer,OPCODE_ACK,seqNum,clientAddress,sizeof(clientAddress));
		return true;	
	}

	return false;
}



bool send_AvailableUserListTotal(int socket, unsigned char* buffer, uint8_t& seqNum, sockaddr_in* clientAddress, int clientAddressLen){
	string result = "";
	vector<string> availableUserList = availableUserListUserDataStructure();
	for(int i=0 ; i < availableUserList.size() - 1 ; i++){
		result += availableUserList.at(i) +";";
	}
	result += availableUserList.at(availableUserList.size() - 1);
	printf("LISTA DI UTENTI ATTUALMENTE IN ATTESA DI UNA SFIDA: %s.\n",result.c_str());
	int resultLength = result.length();
	int chunkPos = 0;
	const char *result_c = result.c_str();
	char *chunk; 
	while(resultLength >= 0){
		
		memset(buffer, 0, BUF_SIZE);
		uint8_t chunkSize = resultLength > 255 ? 255 : resultLength;
		chunk = new char[chunkSize];

		resultLength = resultLength - chunkSize;
		memcpy(chunk,result_c + chunkPos,chunkSize);
		chunkPos += chunkSize;

		
		seqNum = seqNum + 1;

		send_AvailableUserListChunk(socket,buffer,seqNum,chunkSize,chunkSize == 255 ? false : true,chunk,clientAddress, clientAddressLen);
		
		if(!receive_ACK(socket,seqNum,clientAddress,clientAddressLen)){
			return false;
		}
	}

	return true;
}

void* serveClient(void *arg){
	unsigned int sizeMessageReceived = ((struct request*)arg)->sizeMessageReceived;
	unsigned char* loginMessage;
	loginMessage = (unsigned char*) malloc(sizeMessageReceived);	
    memcpy(loginMessage,((struct request*)arg)->loginMessage, sizeMessageReceived);
	int threadIndex = ((struct request*)arg)->threadIndex;
	socklen_t clientAddressLen = ((struct request*)arg)->clientAddressLen;
	struct sockaddr_in clientAddress = ((struct request*)arg)->clientAddress;
	printf("Messaggio ricevuto:\n");
 	BIO_dump_fp (stdout, (const char *)loginMessage, sizeMessageReceived);
	//Numero di sequenza proprio della coppia client-server specifica	
	uint8_t seqNum;
	//Inizializzazione in maniera casuale del sequence number per i messaggi inviati dal server	utilizzando OpenSSL
	RAND_poll();
	RAND_bytes(&seqNum,1);
	char* username;
	username = (char *) malloc(sizeMessageReceived - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN));
	int challengeId = -1;	
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
		if(check_login(threadSocket,loginMessage,sizeMessageReceived,seqNum,username)){
			printf("Il messaggio di login ricevuto e' corretto.\n");
			printf("SEQ.NUMBER RICEVUTO: %u.\n",seqNum);
			printf("USERNAME. RICEVUTO: %s.\n",username);
			memset(sendBuffer, 0, BUF_SIZE);
			send_ACK(threadSocket, sendBuffer,OPCODE_ACK, seqNum, &clientAddress, sizeof(clientAddress));
			if(addNewUserDataStructure(username,clientAddress)){
				seqNum = seqNum + 1;
				send_loginOK(threadSocket,sendBuffer,OPCODE_LOGIN_OK,seqNum,&clientAddress, sizeof(clientAddress));
	
				if(receive_ACK(threadSocket,seqNum,&clientAddress,sizeof(clientAddress))){
					if(send_AvailableUserListTotal(threadSocket, sendBuffer, seqNum, &clientAddress, sizeof(clientAddress))){
						
						uint8_t statusCode = STATUS_IDLE;
						bool exitORerror = false;
						unsigned char* ip = (unsigned char*)malloc(SIZE_IP_ADDRESS);
						unsigned char* key =  (unsigned char*)malloc(SIZE_PUBLIC_KEY);
						uint8_t seqNum2;

						while(!exitORerror){

							seqNum = seqNum + 1;

							if(statusCode == STATUS_CHALLENGING){
									
								memset(sendBuffer, 0, BUF_SIZE);
								sizeMessageReceived = recvfrom(threadSocket, sendBuffer, SIZE_MESSAGE_CHALLENGE_REQUEST, 0,(struct sockaddr*)&clientAddress, &clientAddressLen); 

								//Nel caso in cui l'utente si mette in sfida possiamo:
								//a- Mandare un messaggio di update status
								//b- Mandare un messaggio di exit
								//c- Mandare un messaggio di sfida		

								//Nel caso di una sfida va fatto spazio per l'username dell'utente sfidato					
								char* usernameSfidato = (char*)malloc(sizeMessageReceived - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER + SIZE_LEN + 1));								
								if(check_updateStatus(sendBuffer,sizeMessageReceived,seqNum,&statusCode,username)){
									//Se arriva un update status cambio lo stato dell'utente nella struttura dati
									setStatusUserDataStructure(statusCode,username);
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress));		
								}else if(check_exit(sendBuffer,sizeMessageReceived,seqNum,username)){
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress));
									exitORerror = true;
								}else if(check_challengeRequest(threadSocket,sendBuffer,sizeMessageReceived,OPCODE_CHALLENGE_REQUEST,seqNum,usernameSfidato,challengeId,seqNum)){
									//Se arriva il messaggio di challenge request occorre:
									//1-Inviare il relativo ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress));
									//2-Creare una nuova entry della struttura dati
									challengeId = addNewChallengeDataStructure(username,usernameSfidato);
									if(challengeId == -1){
										//Nel caso in cui viene restituito -1 significa che l'utente sfidato non stava aspettando 
										//una challenge perciò occorre inviare un messaggio di challenge unavailable
										memset(sendBuffer, 0, BUF_SIZE);
										seqNum = seqNum + 1;	
										send_challengeUnavailable(threadSocket,sendBuffer,seqNum,&clientAddress,sizeof(clientAddress));
										//Aspetto l'ACK relativo al messaggio
										if(!receive_ACK(threadSocket,seqNum,&clientAddress,sizeof(clientAddress))){
											exitORerror = true;
										}else{
											//Invio la available user list
											if(!send_AvailableUserListTotal(threadSocket, sendBuffer, seqNum, &clientAddress, sizeof(clientAddress))){
												printf("Errore nell'invio della lista degli utenti disponibili.\n");												
												exitORerror = true;
											}
										}
									}else{
										//Invio del messaggio di sfida all'altro utente
										struct sockaddr_in utenteSfidatoAddress;
										memset(&utenteSfidatoAddress,0,sizeof(utenteSfidatoAddress));
										if(getIPUserDataStructure(usernameSfidato,&utenteSfidatoAddress)){
											//Estrazione del nuovo sequence number
											seqNum = seqNum + 1;	
											send_challengeRequest(threadSocket,&utenteSfidatoAddress,sizeof(utenteSfidatoAddress),sendBuffer, username,usernameSfidato,seqNum,challengeId);
											//Creo il thread per la gestione del timer:
											pthread_t tid;	
											struct timer* currentTimer = (struct timer*)malloc(sizeof(struct timer));
											currentTimer->challengeId = challengeId;
											currentTimer->socket = threadSocket;
											currentTimer->buffer = sendBuffer;
											currentTimer->clientAddress = clientAddress;
											currentTimer->exitORerror = &exitORerror;
											currentTimer->seqNum = &seqNum;
											if(pthread_create(&tid,NULL,timer_thread,(void*)currentTimer) != 0 ){
												printf("ERRORE: e' stato riscontrato un errore nella fase di creazione di un thread.\n");
											}
																							
											//Mi metto in attesa dell'ACK
											if(receive_ACK(threadSocket,seqNum,&clientAddress,sizeof(clientAddress))){
												//Non devo fare niente a questo punto in quanto la gestione e' tutta lato thread dello sfidante
											}else{
												printf("Errore nella ricezione dell'ACK relativo alla sfida.\n");
												exitORerror = true;					
											}
										}else{
											printf("Errore nell'ottenimento dell'indirizzo dell'utente sfidato.\n");
											exitORerror = true;
										}
									}
								}else{
									printf("Errore: arrivato un messaggio di un tipo non riconosciuto.\n");
									exitORerror = true;
						           send_malformedMsg(threadSocket,sendBuffer,OPCODE_MALFORMED_MEX,seqNum,&clientAddress,sizeof(clientAddress));
								}

							}else if(statusCode == STATUS_WAITING){
								//Nel caso in cui l'utente e' in waiting può inviare:
								//a-Un messaggio di challenge accepted
								//b-Un messaggio di challenge refused
								//c-Un messaggio di update status
								//d-Un messaggio di exit
								
								memset(sendBuffer, 0, BUF_SIZE);
								sizeMessageReceived = recvfrom(threadSocket,sendBuffer, SIZE_MESSAGE_UPDATE_STATUS, 0, (struct sockaddr*)&clientAddress, &clientAddressLen); 
								
								if(check_challengeAccepted(sendBuffer,sizeMessageReceived,seqNum,&challengeId)){
									//Nel caso in cui viene ricevuta la challenge accepted:
									//Va inviato il relativo ACK:
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress));
									//Prima di tutto occorre cercare se la challenge e' ancora disponibile
									int challengeIndex = searchChallengeDataStructureFromChallengeNumber(challengeId); 
									if(challengeIndex != -1){
										//Se la challenge e' disponibile devo aggiornare lo stato dei due utenti
										if(setStatusUserDataStructure(STATUS_IN_CHALLENGE,getChallengesDataStructure().at(challengeIndex).username2)){
											if(setStatusUserDataStructure(STATUS_IN_CHALLENGE,getChallengesDataStructure().at(challengeIndex).username1)){
											//Dopo aver aggiornato lo stato degli utenti occorre inviare il messaggio di challenge start a 
											//entrambi gli utenti
											
											//Vanno recuperati gli indirizzi degli utenti:
											struct sockaddr_in sfidante_addr;
											if(getIPUserDataStructure(getChallengesDataStructure().at(challengeIndex).username2,&sfidante_addr)){
													printf("IP SFIDANTE: %s\n",inet_ntoa(sfidante_addr.sin_addr));													
												seqNum = seqNum + 1; 	 send_challengeStart(threadSocket,sendBuffer,inet_ntoa(clientAddress.sin_addr),strdup("0000000000000000"),seqNum,&sfidante_addr,sizeof(sfidante_addr));
												// Aspettiamo di ricevere l'ACK
												if(receive_ACK(threadSocket,seqNum,&sfidante_addr,sizeof(sfidante_addr))){
													// Una volta ricevuto l'ACK posso inviare la challenge start al secondo utente
													seqNum = seqNum + 1;	send_challengeStart(threadSocket,sendBuffer,inet_ntoa(sfidante_addr.sin_addr),strdup("0000000000000000"),seqNum,&clientAddress,sizeof(clientAddress));
													//Aspettiamo di ricevere l'ACK													
													if(receive_ACK(threadSocket,seqNum,&sfidante_addr,sizeof(sfidante_addr))){
														printf("Correttamente inviate le challenge start.\n");
													}else{
														printf("Errore nella ricezione dell'ACK.\n");
														exitORerror = true;
													}
												}else{
													printf("Errore nella ricezione dell'ACK.\n");
													exitORerror = true;
												}
											
send_challengeStart(threadSocket,sendBuffer,inet_ntoa(sfidante_addr.sin_addr),strdup("0000000000000000"),seqNum,&clientAddress,sizeof(clientAddress));
											}else{
												printf("Errore: recupero dello IP dello sfidato non riuscito.\n");
												exitORerror = true;
											}
											
										}else{
											printf("Errore: aggiornamento dello stato dello sfidante non riuscito.\n");
											exitORerror = true;
										}

										}else{
											printf("Errore: aggiornamento dello stato dello sfidato non riuscito.\n");
											exitORerror = true;
										}
									}else{
										//Se tale challenge non e' più disponibile invio un messaggio di challenge unavailable all'utente	
  send_challengeUnavailable(threadSocket,sendBuffer,seqNum,&clientAddress,sizeof(clientAddressLen));
										//Attendo il relativo ACK
										receive_ACK(threadSocket,seqNum,&clientAddress,sizeof(clientAddress));
									}

								}else if(check_challengeRefused(threadSocket,sendBuffer,sizeMessageReceived,seqNum,&challengeId)){
									//Se la challenge e' stata rifiutata prima devo informare lo sfidante
									int challengeIndex = searchChallengeDataStructureFromChallengeNumber(challengeId); 
									if(challengeIndex == -1){
										printf("Errore: impossibile trovare la challenge.\n");
									}else{
										struct sockaddr_in sfidante_addr;
										seqNum = seqNum + 1;
										if(getIPUserDataStructure(getChallengesDataStructure().at(challengeIndex).username2,&sfidante_addr)){
											send_challengeRefused(threadSocket,sendBuffer,seqNum,challengeId,&sfidante_addr,sizeof(sfidante_addr));
											//Attendo l'ACK
											if(!receive_ACK(threadSocket,seqNum,&sfidante_addr,sizeof(sfidante_addr))){
												printf("Challenge refused inoltrata correttamente.\n");
												//Poi la elimino dalla struttura dati
												if(!removeChallengeDataStructureFromChallengeNumber(challengeId)){
													printf("Errore: impossibile rimuovere la challenge .\n");
												}
											}else{
												printf("Errore: la ricezione dell'ACK ha dato esito negativo.\n"); 
											}
										}else{
											printf("Errore: impossibile trovare l'utente richiesto.\n");
										}
									}
								}else if(receive_UpdateStatus(threadSocket,sendBuffer,&clientAddress, sizeof(clientAddress),&statusCode)){
									printf("Ricevuto un messaggio di update status nuovo stato %u.\n",statusCode);
								}else if(check_exit(sendBuffer,sizeMessageReceived,seqNum,username)){
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress));
									exitORerror = true;
								}else{
									printf("Errore: arrivato un messaggio di un tipo non riconosciuto.\n");
									send_malformedMsg(threadSocket,sendBuffer,OPCODE_MALFORMED_MEX,seqNum,&clientAddress,sizeof(clientAddress));
								}

							}else if(statusCode == STATUS_IDLE){
								//Nel caso l'utente e' in idle può solo inviare un messaggio di Update Status
								if(receive_UpdateStatus(threadSocket,sendBuffer,&clientAddress,sizeof(clientAddress),&statusCode)){
									printf("Ricevuto un messaggio di update status nuovo stato %u.\n",statusCode);
								}else{
									printf("Errore nella ricezione dell'update status (STATUS == IDLE) .\n");
									exitORerror = true;
								send_malformedMsg(threadSocket,sendBuffer,OPCODE_MALFORMED_MEX,seqNum,&clientAddress,sizeof(clientAddress));
								}
							}
					}
					//Se si esce dal ciclo in ogni caso va rimosso l'utente dalla struttura dati
					removeUserDataStructure(username);
					close(threadSocket);
}
}
}
}
}
/*
					}else{
						printf("Errore nell'invio della prima lista degli utenti disponibili.\n");
					}
				}else{

				}		*/

				//Mi metto in attesa dell'ack
				/*memset(sendBuffer, 0, BUF_SIZE);
				sizeMessageRecived = recvfrom(threadSocket, sendBuffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)clientAddress, &clientAddressLen);

				if(sizeMessageRecived < SIZE_MESSAGE_ACK){
					perror("There was an error during the reception of the ACK ! \n");
					memset(sendBuffer, 0, BUF_SIZE);
					send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
					close(threadSocket);
				}else{
					if(check_ack(threadSocket,sendBuffer,sizeMessageRecived,OPCODE_ACK,seqNum)){
						
						//Invio della lista di utenti disponibili
						

							uint8_t statusCode = 0;
							if(check_updateStatus(sendBuffer,sizeMessageReceived,&seqNum,&statusCode,username)){
								
								
								
								

								//Invio il corrispondente ACK
								memset(sendBuffer, 0, BUF_SIZE);								
								
								if(statusCode == STATUS_CHALLENGING){
									//Nel caso della challenging l'utente può fare due cose inviare una richiesta o mettersi in attesa
									memset(sendBuffer, 0, BUF_SIZE);
									sizeMessageReceived = recvfrom(threadSocket, sendBuffer, SIZE_MESSAGE_CHALLENGE_REQUEST, 0, (struct sockaddr*)clientAddress, &clientAddressLen);
									int challenge_id;									
									char* usernameSfidato;
									usernameSfidato = (char *) malloc(sizeMessageReceived - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_LEN));
									if(check_challengeRequest(threadSocket,sendBuffer,sizeMessageReceived,OPCODE_CHALLENGE_REQUEST,0,usernameSfidato,challenge_id,seqNum)){
										printf("Arrivata una richiesta di challenge.\n");
										printf("SEQ.NUMBER RICEVUTO: %u.\n",seqNum);
										printf("UTENTE SFIDATO: %s.\n",usernameSfidato);
										//Invio il relativo ACK
										memset(sendBuffer, 0, BUF_SIZE);
										send_ACK(threadSocket, sendBuffer,OPCODE_ACK, seqNum, &clientAddress, sizeof(clientAddress));
										//Controllo che l'utente sfidato sia in attesa di una sfida
										if(getStatusUserDataStructure(usernameSfidato) != STATUS_WAITING){
											//L'utente sfidato non sta aspettando una sfida

											pthread_mutex_lock(&lockSequenceNumber);
												seqNum = lastSequenceNumber;
												lastSequenceNumber = (lastSequenceNumber + 1) % 256;
											pthread_mutex_unlock(&lockSequenceNumber);
											
											send_challengeUnavailable(threadSocket,sendBuffer,seqNum,&clientAddress,sizeof(clientAddress));
											//Aspetto il relativo ACK
											memset(sendBuffer, 0, BUF_SIZE);
                                            sizeMessageReceived = recvfrom(threadSocket, sendBuffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)clientAddress, &clientAddressLen);
											if(sizeMessageReceived < SIZE_MESSAGE_ACK){
												perror("There was an error during the reception of the ACK ! \n");
												memset(sendBuffer, 0, BUF_SIZE);
												send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
												close(threadSocket);
											}else{

											}
										}else{
											//L'utente sta aspettando una sfida
										} 
									}
								}else if(statusCode == STATUS_WAITING){

								}
							}else{
								printf("Il messaggio di update status ricevuto non e' corretto.\n");
								memset(sendBuffer, 0, BUF_SIZE);
								send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
								close(threadSocket);		
							}
						}
					}else{
						printf("L'ACK ricevuto non e' corretto.\n");
						memset(sendBuffer, 0, BUF_SIZE);
						send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
						close(threadSocket);
					}
				}
			}else{
				printf("Errore nella fase di login dell'utente.\n");
				send_loginNO(threadSocket,sendBuffer,OPCODE_LOGIN_NO,seqNum,&clientAddress, sizeof(clientAddress));
				close(threadSocket);
			}		
		}else{
			printf("Il messaggio di login ricevuto e' malformato.\n");
			send_malformedMsg(threadSocket, sendBuffer,OPCODE_MALFORMED_MEX, seqNum, &clientAddress, sizeof(clientAddress));
			close(threadSocket);
		}
	}*/
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
		currentRequest->sizeMessageReceived = recvfrom(serverSocket,&currentRequest->loginMessage,SIZE_MESSAGE_LOGIN,0,(struct sockaddr*)&currentRequest->clientAddress ,&sizeClientAddress);
		if(currentRequest->sizeMessageReceived < 0){
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

