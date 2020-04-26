//Codice per la creazione di un server multithreading per la gestione di richieste TCP/IP in parallelo
#include <stdio.h> 
#include <stdlib.h> //[01]
#include <sys/socket.h> //[02]
#include <netinet/in.h> //[03] 
#include <string.h>
#include <arpa/inet.h> //[04]
#include <pthread.h> //[05]
#include <unistd.h> 

#define MAX_REQUEST 50
#define MAX_LENGHT_MEX 2000

char client_message[MAX_LENGHT_MEX];
char buffer[MAX_LENGHT_MEX];
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; //[06]

/*
Ogni socket è definito da una socket pair ovvero IP_locale:porta_locale, IP_remoto:porta_remota.
Sequenza di operazioni per gestire un socket:

1.    creazione del socket;

2.    assegnazione dell'indirizzo;

3.    connessione o attesa di connessione;

4.    invio o ricezione dei dati;

5.    chiusura del socket.

*/

void * socketThread(void *arg){

	int newSocket = *((int *)arg);
	recv(newSocket , client_message , MAX_LENGHT_MEX , 0); //[07]
	pthread_mutex_lock(&lock); //[08]
	char *message = (char*) malloc(sizeof(client_message)+20);
	strcpy(message,"Hello Client : ");
	strcat(message,client_message);
	strcat(message,"\n");
	strcpy(buffer,message);
	free(message);
	pthread_mutex_unlock(&lock);
	sleep(1);
	send(newSocket,buffer,13,0); //[09]
	printf("Exit socketThread \n");
	close(newSocket);
	pthread_exit(NULL);
}

int main(){
	int serverSocket, newSocket;
	struct sockaddr_in serverAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size;
	serverSocket = socket(PF_INET, SOCK_STREAM, 0); //[10]
	// Configure settings of the server address struct
	// Address family = Internet 
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(7799); //[11]
 	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //[12]
	//Set all bits of the padding field to 0 
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	bind(serverSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)); //[13]
	if(listen(serverSocket,MAX_REQUEST)==0) //[14]
		printf("Listening\n");
	else
		printf("Error in the listen\n");
	pthread_t tid[60]; //[15]
    int i = 0;
    while(1){
        addr_size = sizeof serverStorage;
        newSocket = accept(serverSocket, (struct sockaddr *) &serverStorage, &addr_size); //[16]
        if( pthread_create(&tid[i], NULL, socketThread, &newSocket) != 0 ) //[17]
           printf("Failed to create thread\n");
		i = i + 1;
        if( i >= MAX_REQUEST)
        {
          i = 0;
          while(i < MAX_REQUEST){
          	pthread_join(tid[i++],NULL); //[18]
          }
          i = 0;
        }
    }
  return 0;
}

/*------------------------------------------------------COMMENTI------------------------------------------------------------------------------
[01] stdlib serve per l'allocazione dello heap (malloc)
[02] sys/socket definisce alcune strutture dati per la gestione dei socket:
- socklen_t
- sockaddr_storage
I metodi:
- int socket(int domain, int type, int protocol)
- int bind(int socket, const struct sockaddr *address, socklen_t address_len)
- int listen(int socket, int backlog)
- int accept(int sd, struct sockaddr *ind, socklen_t *indlen)
- int recv(int sd, void *buf, int lun, int opzioni)
- int send(int sd, void *buf, int lun, int opzioni)
[03] sockaddr_in(struttura per indirizzo e porta)
[04] definisce il seguente metodo:
-in_addr_t inet_addr(const char *cp);
[05] definsice la seguente struttura dati:
- pthread_mutex_t
definisce il seguenti metodi:
- int pthread_create(pthread_t *thread,pthread_attr_t *attr,void *(*start_routine)(void *), void * arg)
- int pthread_join(pthread_t th, void **thread_return)
- int pthread_mutex_lock(pthread_mutex_t *mutex)
[06] PTHREAD_MUTEX_INITIALIZER è la MACRO definita per quanto riguarda l'inizializzazione della variabile lock
[07] La recv riceve dati dal socket newSocket e l'inserisce all'interno della struttura dati client_message e indica la lunghezza dei dati che si vogliono ricevere
[08] Il lock serve in quanto buffer e client_message sono risorse condivise tra tutti i thread e perciò devono essere bloccate
[09] In modo analogo alla recv la send invia i dati contenuti nel buffer attraverso il socket specificato come primo parametro. La lunghezza dei dati da inviare è poi specificata come terzo parametro mentre il quarto è ancora una volta lasciato a 0
[10] Il metodo socket crea un socket in particolare PF_INET serve a specificare che si utilizzano indirizzi IPv4, SOCK_STREAM che si utilizza TCP possiamo trascurare il terzo parametro 
[11] htons assicura che i numeri vengono memorizzati in memoria secondo il byte order della rete che prevede che i byte più significativi vengano messi prima quindi assicura che i numeri siano memorizzati come lo sarebbero in una macchina big endian. 
[12] Il metodo inet_addr ha il compito di tradurre un indirizzo IPv4 in dotted notation da una stringa a un numero che può essere utilizzato dalla rete 127.0.0.1 è l'indirizzo localhost
[13] Il metodo bind serve ad assegnare un indirizzo locale ad un socket (quindi la prima metà di un socket pair) e serve quindi a specificare su quale IP:porta il server si metterà in ascolto. Il client invece non deve andare a invocare la bind in quanto sarà il kernel ad assegnargli la porta mentre l'IP sarà quello dell'interfaccia di rete utilizzata
[14] In un server TCP occorre indicare che il programma si deve mettere in attesa di ricevere delle connessioni da parte dei client listen fa questo e inoltre la dimensione della coda di richieste pendenti (richieste arrivate mentre se ne stava servendo un'altra). Questa funzione ritorna 0 in caso di successo
[15] Struttura dati che serve a memorizzare i pthread_id
[16] Il metodo accept accetta una connessione sul serverSocket mentre gli altri due parametri sono l'indirizzo del client che ha stabilito tale connessione e la lunghezza di tale indirizzo. L'effetto di tale metodo è la creazione di un nuovo socket con le stesse caratteristiche del serverSocket che viene restituito da tale metodo. L'effettivo scambio di dati avviene su tale nuovo socket mentre il socket serverSocket si rimette in ascolto per eventuali nuove connessioni 
[17] Il metodo pthread_create si occupa della creazione di un thread per la gestione di ciascuna connessione in particolare tid[i] sarà la variabile che conterrà l'id del nuovo thread, il secondo parametro è impostato a NULL in quanto non ci sono attributi da associare al thread, il terzo è il puntatore al metodo che il nuovo thread andrà ad eseguire mentre il quarto sono gli argomenti da passare a tale metodo. Il metodo ritorna 0 in caso di successo altrimenti un codice di errore
[18] Nel caso in cui vi siano più di connessioni di quelle permesse il server non accetta più connessioni ma tramite la pthread_join si mette in attesa che tutti i thread terminino la loro esecuzione
*/
