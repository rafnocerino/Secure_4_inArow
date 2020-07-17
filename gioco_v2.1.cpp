//LIST OF WHAT NEEDS TO BE DONE
/*
 WHEN A PLAYER MOVE
 - CREATE THE MSG
 - SEND THE MSG
 - WAIT FOR ACK/MALFORMED [NOT IMPLEMNTED]
 WHEN A PLAYER WAITS
 - WAIT THE MSG
 - ANAYLZE MALFORMED
 - SEND ACK/MALFORMED



*/


#include <iostream>
#include <limits>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "send_message.h"
#include "check_message.h"
#include "digital_signature.h"
#include "dh.h"
#include "gcm.h"

#include "protocol_constant.h"
#include "gioco_v2.1.h"
#define MAX_BUFFER_SIZE 512
#define MOVE_SIZE 34
#define OPCODE_MOVE 30
using namespace std;

void receive_ACK2(int socket,unsigned char* buffer,int addr_size,struct sockaddr_in* sv_addr,int& received){
    socklen_t size = addr_size;
    int pos = 0;
    memset(buffer, 0, BUF_SIZE);
    received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr, &size);
    if (received < SIZE_MESSAGE_ACK) {
        perror("There was an error during the reception of the ACK ! \n");
        close(socket);
        exit(-1);
    }

}

/* To many parameters */ 
/*void send_ACK(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;
    int ret;
    op_code = OPCODE_ACK;
    memset(buffer, 0, MAX_BUFFER_SIZE);
    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);
    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);
    ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the ACK \n");
        exit(-1);
    }
}*/

int check_move(unsigned char* buffer, int messageLength, uint8_t* expectedSeqNum, unsigned char* key,bool first_move){
	uint8_t actualOpcode;
	uint8_t seqNumMex;
	int playerMoveColumn;
	bool check; 
	unsigned char* plaintext=(unsigned char*)malloc(BUF_SIZE);
	memset(plaintext,0,BUF_SIZE);

	cout<<"Messaggio cifrato ricevuto"<<endl;

	BIO_dump_fp(stdout,(const char*)buffer,messageLength);
	
	check=gcm_decrypt(key,buffer,messageLength,plaintext);
	if(!check){
		cout<<"Errore decoding the msg"<<endl;
		//send_malformedMsg(socket,buffer,OPCODE_MALFORMED_MEX,++expectedSeqNum, )
		return -1;
	}
	memcpy(&actualOpcode, plaintext, SIZE_OPCODE);
	memcpy(&seqNumMex, plaintext + SIZE_OPCODE, SIZE_SEQNUMBER);
	cout<<"Questo e' l expected seq nume"<<endl;	
	cout<<*expectedSeqNum<<endl;
	if((!first_move) && (seqNumMex != *expectedSeqNum)){
		cout<<"Error: sequence number obtained not correct"<<endl;
		//malformed 
		return -1;
	}	
	if(actualOpcode==OPCODE_MALFORMED_MEX){
		cout<<"Error: The adversary has recived a malformed msg"<<endl;		
		//ack?		
		return -1;
	}

	if(actualOpcode!= OPCODE_MOVE){
		cout<<"Error: expected OPCODE_MOVE"<<endl;
		//malformed?
		return -1; 
	}
	if(first_move)
		*expectedSeqNum=seqNumMex;

	//ritorna l indice della colonna
	memcpy(&playerMoveColumn,plaintext+SIZE_OPCODE+SIZE_SEQNUMBER,sizeof(playerMoveColumn));
	return playerMoveColumn;
}

void wait_ACK(int sd, sockaddr_in* sock, uint8_t sq_numb)
{
	struct timeval tv;
	int ret;
	socklen_t len=sizeof(*sock);
	unsigned char* buffer=(unsigned char*)malloc(1024); //
	memset(buffer,0,1024);	
	tv.tv_sec = 120; //after 120 sec u
	tv.tv_usec= 0 ;
	
	cout<<"Waiting for ACK ..."<<endl;
	if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
		perror("Error");
		exit(-1);
	}
	ret=recvfrom(sd,buffer,sizeof(buffer),0,(struct sockaddr*)sock,&len);
	//check if ACK or Malformed MSG
	cout<<"ACK recived!!!"<<endl;
	
}


void send_Move(int sd, sockaddr_in* sock, uint8_t seq_numb, int playerMoveColumn, unsigned char* key)
{
	int pos=0;
	int ret;
	unsigned char buffer[BUF_SIZE]; //
	memset(buffer,0,BUF_SIZE);
	uint8_t op_code=OPCODE_MOVE;
	
	//memset(buffer, 0, MOVE_SIZE);
	memcpy(buffer, &op_code, sizeof(op_code));
    	pos += sizeof(op_code);
	memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    	pos += sizeof(seq_numb);
	memcpy(buffer + pos, &playerMoveColumn, sizeof(playerMoveColumn));
	pos+=sizeof(playerMoveColumn);
	
	struct cipher_txt c;

	gcm_encrypt(buffer,pos,key,&c);
		
	cout<<"Messaggio cifrato "<<endl;
	BIO_dump_fp(stdout,(const char*)c.all,c.all_len);
	cout<<"Dimensioni"<<endl;	
	cout<<MOVE_SIZE<<endl;
	cout<<c.all_len<<endl;
	ret= sendto(sd, c.all, c.all_len, 0, (struct sockaddr*)sock, sizeof(*sock) );
	if (ret < pos) {
        	perror("There was an error during the sending of the ACK \n");
        	exit(-1);
    }
}


/**
	The initiateGame function initite the game by insertin in each matrix element the
		symbol *
*/
void initiateGame(char gameMatrix[6][7])
{
	int playerId;
	for(int i=0;i<6;i++)
	{
		for(int j=0;j<7;j++)
		{
			gameMatrix[i][j]='*';
		}
	}
	cout << "******************************"<<endl;
	cout << "*** Welcome to 4 in a row ***" <<endl;
	cout << "******************************"<<endl;
	//cout<<"Which player are you?"<<endl;
	//cin>>playerId;
	//return playerId;
}

/**
	The printGame function is used to print the matrix
*/
void printGame(char gameMatrix[6][7])
{
	cout<<"1	2	3	4	5	6	7"<<endl;
	for(int i=0;i<6;i++)
	{
		for(int j=0;j<7;j++)
		{
			cout<<gameMatrix[i][j]<<"	";
		}
		cout<<" "<<endl;
	}
}

/**
	The insertColumnValue function reads the move 
*/
int insertColumnValue()
{
			int playerMoveColumn=0;
			int checkInput=0;
			cout<<"Select a column number:"<<endl;
			if(cin>>checkInput){
				playerMoveColumn=checkInput;
				cout<<playerMoveColumn<<endl;
				playerMoveColumn--;				
			}
			else
			{
				//if the cin fails the input value is not a char
				cout<<"Only numbers are allowed try again"<<endl;
				checkInput=0;
				playerMoveColumn=-1;
				cin.clear();
		    	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}
			return playerMoveColumn;
}

/**
	the waitColumnValue listen from the adversary move
*/
int waitColumnValue(int sd, sockaddr_in* adversary_socket, uint8_t* seq_numb_expected, unsigned char* key,bool first_move)
{
	        socklen_t len=sizeof(*adversary_socket);
		unsigned char receive_buffer[BUF_SIZE];
		memset(receive_buffer,0,BUF_SIZE);		
		//unsigned char send_buffer[MAX_BUFFER_SIZE];
		unsigned char* send_buffer=(unsigned char*)malloc(BUF_SIZE);		
		if(!send_buffer){
			perror("Malloc failed");
			exit(-1);
		}		
		memset(send_buffer,0,BUF_SIZE);
		int playerMoveColumn=0,ret;
		uint8_t seq_numb_recived;
		cout<<"Waiting adversary move..."<<endl;
		// must be implemented a inactive politic
		ret=recvfrom(sd,receive_buffer,MOVE_SIZE,0,(struct sockaddr*)adversary_socket,&len);
		//void check_move(int socket, unsigned char* buffer, int messageLength, uint8_t expectedSeqNum, unsigned char* key){
		//decrypts and checks malformed
		cout<<"Sono neella wait ho ricevuto un pacchetto adesso controllo"<<endl;
		playerMoveColumn=check_move(receive_buffer, MOVE_SIZE ,seq_numb_expected,key,first_move);
		if(playerMoveColumn<0){	
			send_malformedMsg(sd,receive_buffer,OPCODE_MALFORMED_MEX,++(*seq_numb_expected),adversary_socket,len,key );
			exit(-1);		
		}


		
		//memcpy(&seq_numb_recived,receive_buffer+1,sizeof(seq_numb_recived));
		//cout<<"Msg received, seq number: "<<seq_numb_recived<<endl;
		//printf("%u\n",seq_numb_recived);
					
		cout<<"Move sent: "<<playerMoveColumn<<endl;
		
		cout<<"Sending ack"<<endl;
		send_ACK(sd,send_buffer,OPCODE_ACK,*seq_numb_expected, adversary_socket, len, key );
		cout<<"Ack sent"<<endl;		
	
		return playerMoveColumn;
}

/** 
	The chekMove function
		- check for buffer overflows
		- Find the fist available row where to insert our symbol
*/
int checkMove(char gameMatrix[6][7], int move)
{
	if((move<7) && (move>=0))
	{
		for(int j=6;j>=0;j--)
		{
			if(gameMatrix[j][move]=='*')
				return j;
		}
	}
	cout<<"Invalid move try again"<<endl;
	return -1;
}

/**
	The checkWinner function checks if the player has winned thanks to his last move
		bool checkWinner(char gameMatrix[6][7],int moveRow, int moveColumn,char simbol)
*/
bool checkWinner(char gameMatrix[6][7],int moveRow, int moveColumn,char simbol)
{
	int counterConsecutive=0;
	int startRow;
	int endRow;
	int startColumn;
	int endColumn;

	int index;
		//check vertical win
		//we have to check only below the actual move
	endRow=(moveRow+3 > 5? 5 : moveRow+3);
	
	for(int i=moveRow;i<=endRow;i++)
	{
		if(gameMatrix[i][moveColumn]==simbol)
		{
			counterConsecutive++;
			if(counterConsecutive==4)
				return true;
		}
		else
			counterConsecutive=0;
	}

		//check orizontal win
	startColumn=(moveColumn-3>=0 ? 0 : moveColumn-3 );

	endColumn=(moveColumn+3>6 ? 6 : moveColumn+3 );

	counterConsecutive=0;
	for(int j=startColumn;j<=endColumn;j++)
	{
		if(gameMatrix[moveRow][j]==simbol)
		{
			counterConsecutive++;
			if(counterConsecutive==4)
				return true;
		}
		else
			counterConsecutive=0;
	}

	counterConsecutive=0;

		//check diagonal win
	int counterConsecutiveSD=0;
	for(int i=1;i<8;i++)
	{
		index=i-4;
		if(moveRow-index>=0 && moveRow-index<=5 )
			{
				//first diagonal
				if(moveColumn-index>=0 && moveColumn-index<=6)
				{
					if(gameMatrix[moveRow-index][moveColumn-index]==simbol)
					{
						counterConsecutive++;
						if(counterConsecutive==4)
							return true;
					}
					else
					{
						counterConsecutive=0;
					}
				}
				
				//second diagonal
				if(moveColumn+index>=0 && moveColumn+index<=6)
				{
					if(gameMatrix[moveRow-index][moveColumn+index]==simbol)
					{
						counterConsecutiveSD++;
						if(counterConsecutiveSD==4)
							return true;
					}
					else
					{
						counterConsecutiveSD=0;
					}
				}
			}
	}
	return false;
}



/**
this function is the function that read the player move and checks:
	- The input is an integer 
	- The input is an integer between  and the number of columns in the matrix 
*/
bool playerMove(char gameMatrix[6][7],int playerId, int myPlayerId, int sd, sockaddr_in* adversary_socket, uint8_t* mvNumb, unsigned char* key,bool first_move)
{
	char integer_column[4]; //this is the buffer need to send the msg TO CHANGE
	uint8_t* sq_num=mvNumb;
	char simbol=(playerId==0?'X':'O');
	bool winner=false;
	int playerMoveColumn=0;
	int rowMove=-1;
	unsigned char buffer[BUF_SIZE];
	int received;

	do
	{
		playerMoveColumn=0;
		if(playerId==myPlayerId)
			playerMoveColumn=insertColumnValue();
		else
			playerMoveColumn=waitColumnValue(sd, adversary_socket, sq_num, key,first_move);							
		//check if move is allowed
		rowMove=checkMove(gameMatrix,playerMoveColumn);
	}while(rowMove<0);
	
	gameMatrix[rowMove][playerMoveColumn]=simbol;
	winner = checkWinner(gameMatrix,rowMove,playerMoveColumn,simbol);
	// if my move send it to the adversary
	if(playerId==myPlayerId)
	{
		send_Move(sd, adversary_socket, *sq_num, playerMoveColumn, key);
		receive_ACK2(sd,buffer,sizeof(*adversary_socket),adversary_socket,received);  
            	int check = check_ack(sd, buffer, received, OPCODE_ACK, *sq_num,key);
            	if (!check) {
            	    cout<<"The ACK received after sending challenge accepted is altered, the app will be closed!"<<endl;
            	    send_malformedMsg(sd, buffer, OPCODE_MALFORMED_MEX, ++(*sq_num), adversary_socket, sizeof(*adversary_socket),key);
            	   // send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

                	close(sd);	
                	exit(-1);
            	}
		//wait_ACK(sd, adversary_socket, *sq_num);
		//msg structure
		//insert content
		//memcpy(integer_column, &playerMoveColumn,sizeof(playerMoveColumn));	
		//ret=sendto(sd,integer_column,sizeof(integer_column),0,(struct sockaddr*)adversary_socket,sizeof(*adversary_socket));

		//wait for ack or malformed msg 
	}
	if(winner)
	{
		//ack msg from the sender
		cout<<"THERE IS A WINNER!!!"<<endl;
		cout<<"The winner is  player "<<playerId<<endl;
	}
	return winner;
}

int gameStart(unsigned char* IpAddr,int playerI,EVP_PKEY* pubkey_adv,char* username){
	
	if(pubkey_adv==NULL){
		cout<<"CHIAVE VUOTA"<<endl;
	}
	/* UDP Socket data structure */
	int sd, new_sd, ret, check_bind;
	struct sockaddr_in adversary_socket; //where to send/recive data
	/* ************************* */
	int myPlayerId=playerI;
	int playerId=0;
	int indexMove;
	uint8_t moveNumber=0;
	bool winner=false;
	char  gameMatrix[6][7];
	char ad_soc_num[10];
	bool first_move=true;
        initiateGame(gameMatrix);

	//cout<<"********************************************************************************"<<endl;
	//printf("MoveNumber prima %u",moveNumber);
	//RAND_poll();
	//RAND_bytes((unsigned char*)&moveNumber,sizeof(moveNumber));
	//printf("MoveNumber dopo %u",moveNumber);
	/********************************** SOCKET CREATION **************************************/
	sd=socket(AF_INET, SOCK_DGRAM, 0);
	memset(&adversary_socket, 0, sizeof(adversary_socket));
	adversary_socket.sin_family=AF_INET;
	//the socket number used for this service is 2020
	adversary_socket.sin_port=2020;
	inet_pton(AF_INET,(char*)IpAddr,&adversary_socket.sin_addr);  
	if(myPlayerId==1){
		//second player must have an open socket to listen
		//adversary_socket.sin_addr.s_addr=IpAddr; 
		check_bind=bind(sd, (struct sockaddr*)&adversary_socket, sizeof(adversary_socket));
		if(check_bind<0)
		{
			perror("Errore binding the socket");
			exit(0);
		}
	}	
	//else{
	//	inet_pton(AF_INET,(char*)IpAddr,&adversary_socket.sin_addr);  
	//}
	/****************************************************************************************/
	
	/* ******************************** AUTHENTICATION **************************************/
	cout<<"Starting authentication"<<endl;
	unsigned char* sendBuffer;
	sendBuffer=(unsigned char*)malloc(BUF_SIZE);
	if(!sendBuffer){
		perror("Error malloc");
		exit(0);
	}	
	memset(sendBuffer,0,BUF_SIZE);		
	unsigned char* random_data=(unsigned char*)malloc(SIZE_RANDOM_DATA);	
	if(!random_data){
		perror("Error malloc");
		exit(0);
	}
	unsigned char* signature= (unsigned char*)malloc(SIZE_SIGNATURE);
	if(!signature){
		perror("Error malloc");
		exit(0);
	}


	if(myPlayerId==0){
		sleep(1);
		RAND_poll();
		RAND_bytes(random_data,SIZE_RANDOM_DATA);
		cout<<"Ready to send data to be authenticated"<<endl;
		send_signature_message(sd,sendBuffer,random_data,username,0,&adversary_socket,sizeof(adversary_socket),0);
		cout<<"Sent"<<endl;

		//memset(random_data,0,SIZE_RANDOM_DATA);
		memset(sendBuffer,0,BUF_SIZE);		
		struct timeval time;
		time.tv_sec=WAIT_TIME_LOGIN;
		time.tv_usec=0;
		
		setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));
		socklen_t len=sizeof(adversary_socket);
		cout<<"Waiting to receive authenticated Data"<<endl;
		int recived= recvfrom(sd,sendBuffer, SIZE_MESSAGE_SIGNATURE_MESSAGE, 0 , (struct sockaddr*)&adversary_socket, &len);
		cout<<"RECIVED "<<recived<<" CONST "<<SIZE_MESSAGE_SIGNATURE_MESSAGE<<endl;		
			
		if(recived==SIZE_MESSAGE_SIGNATURE_MESSAGE){
			//check msg signature
			if(pubkey_adv==NULL)
				cout<<"CHIAVE VUOTA"<<endl;
			
			if(!check_signature_message_server(sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,random_data)){
				cout<<"The signature is INCORRECT"<<endl;			
				exit(-1);			
			}
			if(verifySignMsg(username,sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,pubkey_adv)){
				cout<<"The adversary signed the msg"<<endl;
			}		
			else{
				cout<<"ERROR AUTHENTICATION"<<endl;
				exit(-1); 
			}
		}
		memset(sendBuffer,0,BUF_SIZE);
		memset(random_data,0,SIZE_RANDOM_DATA);
		//Wait adversary for data to authenticate
		setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));
		cout<<"Waiting for data to authenticate"<<endl;
		recived= recvfrom(sd,sendBuffer, SIZE_MESSAGE_SIGNATURE_MESSAGE, 0 , (struct sockaddr*)&adversary_socket, &len);

		int check=check_signatureMessageClient(sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,random_data,signature);
		if(!check)
		{
			close(sd);
			exit(-1);
		}

		// ********************************************* 		
		if(recived==SIZE_MESSAGE_SIGNATURE_MESSAGE){
			//check msg signature
			if(pubkey_adv==NULL)
				cout<<"CHIAVE VUOTA"<<endl;
			
			if(!check_signature_message_server(sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,random_data)){
				cout<<"The signature is INCORRECT"<<endl;			
				exit(-1);			
			}
			if(verifySignMsg(username,sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,pubkey_adv)){
				cout<<"The adversary signed the msg"<<endl;
			}		
			else{
				cout<<"ERROR AUTHENTICATION"<<endl;
				exit(-1); 
			}
		}	
		//*********************************	
		cout<<"Ready to sign data authenticated"<<endl;
		//authenticate and send info
		//sendAndSignMsg(sd,username, random_data, SIZE_RANDOM_DATA, &adversary_socket,sizeof(adversary_socket),0);
		send_signature_message(sd,sendBuffer,random_data,username,0,&adversary_socket,sizeof(adversary_socket),0);	
		cout<<"Data authenticated sent"<<endl;	
	}
	else{
		//recive the signed random number and authenticate it
		memset(sendBuffer,0,BUF_SIZE);
		memset(random_data,0,SIZE_RANDOM_DATA);
		struct timeval time;
		time.tv_sec=WAIT_TIME_LOGIN;
		time.tv_usec=0;

		setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));
		socklen_t len=sizeof(adversary_socket);
		cout<<"Waiting for data to authenticate"<<endl;
		int recived= recvfrom(sd,sendBuffer, SIZE_MESSAGE_SIGNATURE_MESSAGE, 0 , (struct sockaddr*)&adversary_socket, &len);
		cout<<"Data to authenticate recived"<<endl;
		cout<<recived<<endl;
		if(recived==SIZE_MESSAGE_SIGNATURE_MESSAGE){
			//check msg signature
			//BIO_dump_ftp();
			if(pubkey_adv==NULL)
				cout<<"CHIAVE VUOTA"<<endl;
			if(verifySignMsg(username,sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,pubkey_adv)){
				cout<<"The adversary signed the msg"<<endl;
			}		
			else{
				cout<<"ERROR AUTHENTICATION"<<endl;
				exit(-1); 
			}
		}
		int check=check_signatureMessageClient(sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,random_data,signature);
		if(!check)
		{
			close(sd);
			exit(-1);
		}
		
		memset(sendBuffer,0,BUF_SIZE);
		cout<<"Data authenticated ready to send"<<endl;
		send_signature_message(sd,sendBuffer,random_data,username,0,&adversary_socket,sizeof(adversary_socket),0);
		cout<<"Authenticated data sent"<<endl;		
		
		memset(random_data,0,SIZE_RANDOM_DATA);
		memset(sendBuffer,0,BUF_SIZE);
		RAND_poll();
		RAND_bytes(random_data,SIZE_RANDOM_DATA);
		cout<<"Ready to send data to be authenticaed"<<endl;
		send_signature_message(sd,sendBuffer,random_data,username,0,&adversary_socket,sizeof(adversary_socket),0);
		cout<<"Sent"<<endl;
		//Wait adversary for data to authenticate
		setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO,&time,sizeof(time));

		cout<<"Waiting to recieve authenticaed data"<<endl;
		recived= recvfrom(sd,sendBuffer, SIZE_MESSAGE_SIGNATURE_MESSAGE, 0 , (struct sockaddr*)&adversary_socket, &len);
		cout<<"RECIVED"<<endl;		
		if(recived==SIZE_MESSAGE_SIGNATURE_MESSAGE){
			//check msg signature
			//BIO_dump_ftp();
			if(pubkey_adv==NULL)
				cout<<"CHIAVE VUOTA"<<endl;
			if(verifySignMsg(username,sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,pubkey_adv)){
				cout<<"The adversary signed the message"<<endl;
			}		
			else{
				cout<<"ERROR AUTHENTICATION"<<endl;
				exit(-1); 
			}
		}

		check=check_signature_message_server(sendBuffer,SIZE_MESSAGE_SIGNATURE_MESSAGE,random_data);		
		if(!check)
		{
			close(sd);
			exit(-1);
		}
		cout<<"ADVRESARY AUTHENTICATED"<<endl;
		
	}
	

	/* *****************************  END AUTHENTICATION ********************************************************/

	/* ************************************ SHARED SECRET DH ****************************************************/
	cout<<"DIFFIE HELLMAN START"<<endl;	
	unsigned char* shared_secret=(unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
	if(!shared_secret){
		perror("memset failed");
		exit(-1);
	}
	unsigned int shared_secretLen;	
	bool first=(myPlayerId==0?true:false);	
     	
	//void sharedSecretCreationDH(int sd, struct sockaddr_in* opposite_addr, bool first,char* username,EVP_PKEY* oppositeKey,unsigned char* sharedSecret,unsigned int& sharedSecretLen)
	sharedSecretCreationDH(sd,&adversary_socket,first,username,pubkey_adv,shared_secret, shared_secretLen,username);
	cout<<"Session key:"<<endl;
	BIO_dump_fp(stdout,(const char*)shared_secret,shared_secretLen);
	/* ************************************ END SHARED DH *********************************************/
	if(first){	
		cout<<"********************************************************************************"<<endl;
		printf("MoveNumber prima %u",moveNumber);
		RAND_poll();
		RAND_bytes((unsigned char*)&moveNumber,sizeof(moveNumber));
		printf("MoveNumber dopo %u",moveNumber);	
	}
	cout<<""<<endl;
	printGame(gameMatrix);
	do
	{
		winner=playerMove(gameMatrix,playerId,myPlayerId,sd,&adversary_socket,&moveNumber, shared_secret,first_move);
		first_move=false;		
		moveNumber++;
		printGame(gameMatrix);
		playerId++;
		playerId=playerId%2;
	}while(!winner); 
	cout<<"The game ended"<<endl;
	close(sd);
	return 0;
}

