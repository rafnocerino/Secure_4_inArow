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
#include <cstdint>
#include <math.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../dh.h"
#include "../check_message.h"
#include "../send_message.h"
#include "../digital_signature.h"

#include "users_datastructure.h"
#include "challenges_datastructure.h"
using namespace std;

#define SERVER_PORT 7799
#define MAX_REQUEST 50
#define SLEEP 20

static const char serverCertificateFilePath[] = "../Certificates/Server_cert.pem";
static const char serverUsername[] = "server";

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

vector<int> intializeIndexesAvailableTID(){
	vector<int> result;
	for(int i=0;i<MAX_REQUEST;i++)
		result.push_back(i);
	return result;
}

int serialize_PEM_Pub_Key_From_File(string username,unsigned char** pubkeyBuffer){
	string pathFile = "../public keys/" + username + "_public.pem"; 
	
	FILE *f = fopen(pathFile.c_str(),"rb");
	
	if(f == NULL){
		return -1;
	}
	
	EVP_PKEY* pubkey = PEM_read_PUBKEY(f,NULL,NULL,NULL);
	
	if(pubkey == NULL){
		return -1;
	}
	
	fclose(f);
	 
	BIO* mbio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(mbio,pubkey);
	int ret = BIO_get_mem_data(mbio,pubkeyBuffer);
	return ret;
}

bool receive_ACK(int socket,uint8_t expSeqNum, sockaddr_in* clientAddress,int clientAddressLen,unsigned char* key){
	uint8_t seqNum = expSeqNum;
	uint8_t opcode = OPCODE_ACK;
	unsigned char* buffer = (unsigned char*)malloc(BUF_SIZE);
	socklen_t addressLen = sizeof(clientAddress);
	memset(buffer,0,BUF_SIZE);
	int sizeMessageReceived = recvfrom(socket,buffer,SIZE_MESSAGE_ACK, 0, (struct sockaddr*)clientAddress,&addressLen);
	printf("---> %d.\n",sizeMessageReceived);
	if(sizeMessageReceived < SIZE_MESSAGE_ACK){
		perror("There was an error during the reception of the ACK ! \n");
		memset(buffer, 0, BUF_SIZE);
		send_malformedMsg(socket,buffer,OPCODE_MALFORMED_MEX, seqNum,clientAddress, sizeof(clientAddress),key);
		close(socket);
		return false;
	}
	if(!check_ack(socket,buffer,sizeMessageReceived,OPCODE_ACK,seqNum,key)){
		printf("Errore: messaggio malformato all'interno della recive ACK.\n");
		send_malformedMsg(socket,buffer,OPCODE_MALFORMED_MEX, seqNum,clientAddress, sizeof(clientAddress),key);
	}
	return true;	
}

bool send_AvailableUserListTotal(int socket, unsigned char* buffer, uint8_t& seqNum, sockaddr_in* clientAddress, int clientAddressLen,unsigned char* key){
	string result = "";
	vector<string> availableUserList = availableUserListUserDataStructure();
	for(int i=0 ; i < availableUserList.size(); i++){
		result += availableUserList.at(i); 
		if(i < availableUserList.size() - 1)
			result += ";"; 
	}
	printf("LISTA DI UTENTI ATTUALMENTE IN ATTESA DI UNA SFIDA: %s.\n",result.c_str());
	int resultLength = result.length();
	int chunkPos = 0;
	const char *result_c = result.c_str();
	char *chunk; 
	while(resultLength >= 0){
		
		memset(buffer, 0, BUF_SIZE);
		uint8_t chunkSize = resultLength > 255 ? 255 : resultLength;
		chunk = new char[chunkSize];

		resultLength = resultLength - 255;
		memcpy(chunk,result_c + chunkPos,chunkSize);
		chunkPos += chunkSize;

		
		seqNum = seqNum + 1;

		send_AvailableUserListChunk(socket,buffer,seqNum,chunkSize,chunkSize == 255 ? false : true,chunk,clientAddress, sizeof(clientAddress),key);
		
		if(!receive_ACK(socket,seqNum,clientAddress,sizeof(clientAddress),key)){
			return false;
		}

	}

	return true;
}

bool privateKeyExist(string fileName){
	string filePath = "./private keys/" + fileName + "_prv.pem";
	FILE *tofind;
	if ((tofind = fopen(filePath.c_str(), "r")))
    {
        fclose(tofind);
        return true;
    }
    return false;
}

unsigned char* readFileBytes(const char *name)  {  
    FILE *fl = fopen(name, "rb");  
    fseek(fl, 0, SEEK_END);  
    long len = ftell(fl);  
    unsigned char* ret = (unsigned char*)malloc(len);  
    fseek(fl, 0, SEEK_SET);  
    fread(ret, 1, len, fl);  
    fclose(fl);  
	return ret;  
}  

unsigned char* readFileBytes(const char *name,int &sizeFile){  
    FILE *fl = fopen(name, "rb");  
    fseek(fl, 0, SEEK_END);  
    sizeFile = ftell(fl);  
    unsigned char* ret = (unsigned char*)malloc(sizeFile);  
    fseek(fl, 0, SEEK_SET);  
    fread(ret, 1, sizeFile, fl);  
    fclose(fl);  
    return ret;  
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
	uint8_t seqNum = 0;	
	//Inizializzazione in maniera casuale del sequence number per i messaggi inviati dal server	utilizzando OpenSSL
	RAND_poll();
    RAND_bytes((unsigned char*)&seqNum,SIZE_SEQNUMBER);
	char* username;
	username = (char *)malloc(255);
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
		if(check_login(threadSocket,loginMessage,sizeMessageReceived,username)){
			printf("Il messaggio di login ricevuto e' corretto.\n");
			printf("USERNAME. RICEVUTO: %s.\n",username);
			memset(sendBuffer, 0, BUF_SIZE);
			
			// Controllo che l'utente abbia un file contente la chiave pubblica associato:
			if(privateKeyExist && addNewUserDataStructure(username,clientAddress)){
				
				// Leggo il file del certificato: 
				int certificateSize = 0;
				unsigned char* certificate = readFileBytes(serverCertificateFilePath,certificateSize);
				printf("DEBUG: certificate size=%d\n",certificateSize);
				
				//Generazione dei byte randomici da firmare:
				unsigned char* random_data = (unsigned char*)malloc(SIZE_RANDOM_DATA);
				RAND_poll();
				RAND_bytes(random_data,SIZE_RANDOM_DATA);
				
				// Invio il signature message:
				send_signature_message(threadSocket,sendBuffer,random_data,(char*)serverUsername,certificateSize,&clientAddress,sizeof(clientAddress),true);
				
				//Mi metto in attesa per dare tempo al client di elaborare correttamente il primo messaggio:
				sleep(1);
				
				//Invio del messaggio contente il certificato:
				send_certificate_message(threadSocket,certificate,certificateSize,&clientAddress,clientAddressLen);
				
				free(certificate);
				
				//Mi metto in attesa del messaggio firmato da parte del client:
				memset(sendBuffer,0,BUF_SIZE);
				struct timeval time;
				time.tv_sec = WAIT_TIME_LOGIN;
				time.tv_usec = 0;
				
				setsockopt(threadSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));
				//La prossima recive from avrà un timer:
				int recived = recvfrom(threadSocket,sendBuffer, SIZE_MESSAGE_SIGNATURE_MESSAGE , 0, (struct sockaddr*)&clientAddress, &clientAddressLen);
				
				printf("DEBUG: size signature message = %d.\n",SIZE_MESSAGE_SIGNATURE_MESSAGE);
				printf("DEBUG: recived = %d.\n",recived);
				
				if(recived == SIZE_MESSAGE_SIGNATURE_MESSAGE){
					
					//Controllo la firma del messaggio:
					if(verifySignMsg(username,sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,NULL)){
						
						//Controllo della struttura del messaggio firmato:
						if(check_signature_message_server(sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,random_data)){
							
							printf("Il messaggio ricevuto indietro e' correttamente firmato.\n");
							
							//Mi metto in attesa del messaggio del client
							recived = recvfrom(threadSocket,sendBuffer, SIZE_MESSAGE_SIGNATURE_MESSAGE , 0, (struct sockaddr*)&clientAddress, &clientAddressLen);
							
							if(recived == 0){
								printf("Message with random data from the client not arrived.\n");
								pthread_exit(NULL);
							}
							
							//Controllo la firma del secondo messaggio arrivato
							if(!verifySignMsg(username,sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,NULL)){
								printf("The signature of the client message with random is not correct.\n");
								pthread_exit(NULL);
							}
							
							unsigned char* extractedRandomData = (unsigned char*)malloc(SIZE_RANDOM_DATA);
							memset(extractedRandomData,0,SIZE_RANDOM_DATA);
							
							
							if(!check_signatureMessageClient(sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,extractedRandomData)){
								printf("The structure of the signature of the client message with random is not correct.\n");
								pthread_exit(NULL);	
							}
							
							send_signature_message(threadSocket,sendBuffer,extractedRandomData,(char*)serverUsername,certificateSize,&clientAddress,sizeof(clientAddress),true);
				
							
							// Allocazione del buffer per la memorizzazione della chiave di sessione
							unsigned char* sessionKey = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
							unsigned int sessionKeyLen = 0;
							
							//Chiamata della funzione per derivare il segreto condiviso con Diffie-Hellman:
							sharedSecretCreationDH(threadSocket,&clientAddress,true,username,NULL,sessionKey,sessionKeyLen,random_data,extractedRandomData);

							printf("DEBUG: ottenuta una chiave di sessione di lunghezza %d.\n",sessionKeyLen);
							
							BIO_dump_fp (stdout, (const char*)sessionKey ,sessionKeyLen); 
							
							addKeyFromUsername(sessionKey,username);	
							
							//Invio della Available User List:
							if(send_AvailableUserListTotal(threadSocket, sendBuffer, seqNum, &clientAddress, sizeof(clientAddress),sessionKey)){
							
				//send_loginOK(threadSocket,sendBuffer,OPCODE_LOGIN_OK,seqNum,&clientAddress, sizeof(clientAddress));
	
				//if(receive_ACK(threadSocket,seqNum,&clientAddress,sizeof(clientAddress))){
						uint8_t statusCode = STATUS_IDLE;
						bool exitORerror = false;
						unsigned char* ip = (unsigned char*)malloc(SIZE_IP_ADDRESS);
						unsigned char* key =  (unsigned char*)malloc(SIZE_PUBLIC_KEY);
						uint8_t seqNum2;

						while(!exitORerror){

							printf("Sono risalito.\n");
							memset(sendBuffer, 0, BUF_SIZE);
							sizeMessageReceived = recvfrom(threadSocket,sendBuffer, SIZE_MESSAGE_UPDATE_STATUS, 0, (struct sockaddr*)&clientAddress, &clientAddressLen); 
							seqNum = seqNum + 1;
							printf("Porta da cui ricevo il messaggio -> %s\n",inet_ntoa(clientAddress.sin_addr));
							if(statusCode == STATUS_CHALLENGING){

								//Nel caso in cui l'utente si mette in sfida possiamo:
								//a- Mandare un messaggio di update status
								//b- Mandare un messaggio di exit
								//c- Mandare un messaggio di sfida		

								//Nel caso di una sfida va fatto spazio per l'username dell'utente sfidato					
								char* usernameSfidato = (char*)malloc(sizeMessageReceived - (SIZE_OPCODE + SIZE_SEQNUMBER + SIZE_CHALLENGE_NUMBER + SIZE_LEN + 1));								
								if(check_updateStatus(threadSocket,sendBuffer,sizeMessageReceived,seqNum,statusCode,username,sessionKey)){
									//Se arriva un update status cambio lo stato dell'utente nella struttura dati
									setStatusUserDataStructure(statusCode,username);
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);		
								}else if(check_challengeRequest(threadSocket,sendBuffer,sizeMessageReceived,OPCODE_CHALLENGE_REQUEST,seqNum,username,challengeId,seqNum,usernameSfidato,sessionKey)){
									//Se arriva il messaggio di challenge request occorre:
									//1-Inviare il relativo ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
									//2-Creare una nuova entry della struttura dati
									challengeId = addNewChallengeDataStructure(username,usernameSfidato);
									if(challengeId == -1){
										//Nel caso in cui viene restituito -1 significa che l'utente sfidato non stava aspettando 
										//una challenge perciò occorre inviare un messaggio di challenge unavailable
										printf("Errore: challengeId pari a -1.\n");
										memset(sendBuffer, 0, BUF_SIZE);
										seqNum = seqNum + 1;	
										send_challengeUnavailable(threadSocket,sendBuffer,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
										//Aspetto l'ACK relativo al messaggio
										if(!receive_ACK(threadSocket,seqNum,&clientAddress,sizeof(clientAddress),sessionKey)){
											exitORerror = true;
										}else{
											//Invio la available user list
											if(!send_AvailableUserListTotal(threadSocket, sendBuffer, seqNum, &clientAddress, sizeof(clientAddress),sessionKey)){
												printf("Errore nell'invio della lista degli utenti disponibili.\n");												
												exitORerror = true;
											}
										}
									}else{
										//Invio del messaggio di sfida all'altro utente
										struct sockaddr_in utenteSfidatoAddress;
										memset(&utenteSfidatoAddress,0,sizeof(utenteSfidatoAddress));
										if(getIPUserDataStructure(usernameSfidato,&utenteSfidatoAddress)){
												
											send_challengeRequest(threadSocket,&utenteSfidatoAddress,sizeof(utenteSfidatoAddress),sendBuffer, username,usernameSfidato,seqNum,challengeId,getKeyFromUsername(usernameSfidato));
											
																							
										if(receive_ACK(threadSocket,seqNum,&utenteSfidatoAddress,sizeof(utenteSfidatoAddress),getKeyFromUsername(usernameSfidato))){
											/*//Estrazione del nuovo sequence number
											seqNum = seqNum + 1;
											//Creo il thread per la gestione del timer:
											pthread_t tid;	
											struct timer* currentTimer = (struct timer*)malloc(sizeof(struct timer));
											currentTimer->challengeId = challengeId;
											currentTimer->socket = threadSocket;
											currentTimer->buffer = sendBuffer;
											currentTimer->clientAddress = clientAddress;
											currentTimer->exitORerror = &exitORerror;
											currentTimer->seqNum = seqNum;
												if(pthread_create(&tid,NULL,timer_thread,(void*)currentTimer) != 0 ){
													printf("ERRORE: e' stato riscontrato un errore nella fase di creazione di un thread.\n");
												}*/	
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
						           send_malformedMsg(threadSocket,sendBuffer,OPCODE_MALFORMED_MEX,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
								}

							}else if(statusCode == STATUS_WAITING){
								//Nel caso in cui l'utente e' in waiting può inviare:
								//a-Un messaggio di challenge accepted
								//b-Un messaggio di challenge refused
								//c-Un messaggio di update status
								
								
								if(check_challengeAccepted(threadSocket,sendBuffer,sizeMessageReceived,seqNum,&challengeId,sessionKey)){
									//Nel caso in cui viene ricevuta la challenge accepted:
									//Va inviato il relativo ACK:
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
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
											if(getIPUserDataStructure(getChallengesDataStructure().at(challengeIndex).username1,&sfidante_addr)){
												printf("IP SFIDANTE: %s\n",inet_ntoa(sfidante_addr.sin_addr));													
												seqNum = seqNum + 1;
												unsigned char* temp_pubkey;
												int ret = serialize_PEM_Pub_Key_From_File(username,&temp_pubkey);
												printf("DEBUG: ret_serialize = %d\n",ret);
												if(ret == SIZE_PUBLIC_KEY){ 	 
												send_challengeStart(threadSocket,sendBuffer,inet_ntoa(clientAddress.sin_addr),temp_pubkey,seqNum,&sfidante_addr,sizeof(sfidante_addr),getKeyFromUsername(getChallengesDataStructure().at(challengeIndex).username1));
												// Aspettiamo di ricevere l'ACK
												if(receive_ACK(threadSocket,seqNum,&sfidante_addr,sizeof(sfidante_addr),getKeyFromUsername(getChallengesDataStructure().at(challengeIndex).username1))){
													printf("1.\n");
													// Una volta ricevuto l'ACK posso inviare la challenge start al secondo utente
													int ret = serialize_PEM_Pub_Key_From_File(getChallengesDataStructure().at(challengeIndex).username1,&temp_pubkey);
													if(ret ==  SIZE_PUBLIC_KEY){
send_challengeStart(threadSocket,sendBuffer,inet_ntoa(sfidante_addr.sin_addr),temp_pubkey,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
													//Aspettiamo di ricevere l'ACK													
													if(receive_ACK(threadSocket,seqNum,&sfidante_addr,sizeof(sfidante_addr),sessionKey)){
														printf("Correttamente inviate le challenge start.\n");
													}else{
														printf("Errore nella ricezione dell'ACK.\n");
														exitORerror = true;
													}
												}else{
													printf("Errore: serializzazione della chiave pubblica dell'utente 2 non riuscita.\n");
													exitORerror = true;
												}
												}else{
													printf("Errore nella ricezione dell'ACK.\n");
													exitORerror = true;
												}
											}else{
												printf("Errore: serializzazione della chiave pubblica dell'utente 2 non riuscita.\n");
											}
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
  send_challengeUnavailable(threadSocket,sendBuffer,seqNum,&clientAddress,sizeof(clientAddressLen),sessionKey);
										//Attendo il relativo ACK
										receive_ACK(threadSocket,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
									}

								}else if(check_challengeRefused(threadSocket,sendBuffer,sizeMessageReceived,seqNum,&challengeId,sessionKey)){
									
									//Se la challenge e' stata rifiutata prima devo informare lo sfidante
									int challengeIndex = searchChallengeDataStructureFromChallengeNumber(challengeId); 
									if(challengeIndex == -1){
										printf("Errore: impossibile trovare la challenge.\n");
									}else{
										struct sockaddr_in sfidante_addr;
										if(getIPUserDataStructure(getChallengesDataStructure().at(challengeIndex).username1,&sfidante_addr)){
											send_challengeRefused(threadSocket,sendBuffer,seqNum,challengeId,&sfidante_addr,sizeof(sfidante_addr),getKeyFromUsername(getChallengesDataStructure().at(challengeIndex).username1));
											//Attendo l'ACK
											if(receive_ACK(threadSocket,seqNum,&sfidante_addr,sizeof(sfidante_addr),getKeyFromUsername(getChallengesDataStructure().at(challengeIndex).username1))){
												printf("Challenge refused inoltrata correttamente.\n");
												//Mando l'ACK al mio utente 
												send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
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
								}else if(check_updateStatus(threadSocket,sendBuffer,sizeMessageReceived,seqNum,statusCode,username,sessionKey)){
									//Se arriva un update status cambio lo stato dell'utente nella struttura dati
									setStatusUserDataStructure(statusCode,username);
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,clientAddressLen,sessionKey);
									printf("Ricevuto un messaggio di update status nuovo stato %u.\n",statusCode);
								/*}else if(check_exit(threadSocket,sendBuffer,sizeMessageReceived,seqNum,username)){
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress));
									exitORerror = true;*/
								}else{
									printf("Errore: arrivato un messaggio di un tipo non riconosciuto.\n");
									send_malformedMsg(threadSocket,sendBuffer,OPCODE_MALFORMED_MEX,seqNum,&clientAddress,clientAddressLen,sessionKey);
								}

							}else if(statusCode == STATUS_IDLE){
								//Nel caso l'utente e' in idle può solo inviare un messaggio di Update Status
								if(check_updateStatus(threadSocket,sendBuffer,sizeMessageReceived,seqNum,statusCode,username,sessionKey)){
									//Se arriva un update status cambio lo stato dell'utente nella struttura dati
									setStatusUserDataStructure(statusCode,username);
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,clientAddressLen,sessionKey);
									//printf("Porta a cui invio l'ack di update status -> %s\n",inet_ntoa(clientAddress.sin_addr));
									printf("Ricevuto un messaggio di update status nuovo stato %u.\n",statusCode);
								}else if(check_exit(threadSocket,sendBuffer,sizeMessageReceived,seqNum,username,sessionKey)){
									//Invio il corrispondente ACK
									send_ACK(threadSocket,sendBuffer,OPCODE_ACK,seqNum,&clientAddress,sizeof(clientAddress),sessionKey);
									exitORerror = true;	
								}else{
									printf("Errore nella ricezione dell'update status (STATUS == IDLE) .\n");
									exitORerror = true;
								send_malformedMsg(threadSocket,sendBuffer,OPCODE_MALFORMED_MEX,seqNum,&clientAddress,clientAddressLen,sessionKey);
								}
								//La EXIT può essere fatta solo quando si è in IDLE
							}
					}
					//Se si esce dal ciclo in ogni caso va rimosso l'utente dalla struttura dati
					removeUserDataStructure(username);
				}else{
					printf("Errore: impossibile inviare la available user list.\n");
				}
				}else{
					printf("Errore: il signature message ha un formato scorretto.\n");
				}
					
					}else{
							printf("Errore: il controllo sulla firma del messaggio e' scorretto.\n");
					}
				}else{
					printf("Errore: impossibile riceve il messaggio firmato dal client in risposta.\n");
				}	
		}else{
			printf("Errore: l'utente richiesto non e' uno degli utenti registrati o non e' stato possibile andarlo ad aggiungere alla struttura dati.\n");
		}
		
	}else{
		printf("Errore: il messaggio di login ricevuto ha un formato errato\n");
	}
	close(threadSocket);
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
}

int main(){
	indexesAvailableTID = intializeIndexesAvailableTID();
	sem_init(&indexesSem,0,MAX_REQUEST);

	int serverSocket;
	struct sockaddr_in serverAddress;
	memset(&serverAddress,0,sizeof(serverAddress));
	serverSocket = socket(AF_INET,SOCK_DGRAM,0); //[]
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = SERVER_PORT; //[]
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

