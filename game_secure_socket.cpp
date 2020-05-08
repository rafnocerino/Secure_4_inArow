#include <iostream>
#include <limits>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
//#include <protocol_constant.h>
#include <stdlib.h>
#include <unistd.h>
using namespace std;
/**
	The initiateGame function initite the game by insertin in each matrix element the
		symbol *
*/
int initiateGame(char gameMatrix[6][7])
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
	cout<<"Which player are you?"<<endl;
	cin>>playerId;
	return playerId;
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
int waitColumnValue(int sd, sockaddr_in* adversary_socket)
{
	    socklen_t len=sizeof(*adversary_socket);
		char integer_column[4];
		int playerMoveColumn=0,ret;
		cout<<"Waiting adversary move..."<<endl;
		// must be implemented a inactive politic
		ret=recvfrom(sd,integer_column,sizeof(integer_column),0,(struct sockaddr*)adversary_socket,&len);
		memcpy(&playerMoveColumn,integer_column,sizeof(playerMoveColumn));			
		cout<<playerMoveColumn<<endl;	
		//check malforme
		//send ack or malformed
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
bool playerMove(char gameMatrix[6][7],int playerId, int myPlayerId, int sd, sockaddr_in* adversary_socket, int mvNumb)
{
	char integer_column[4];
	
	char simbol=(playerId==0?'X':'O');
	bool winner=false;
	int playerMoveColumn=0;
	int rowMove=-1;
	int ret;

	
	do
	{
		playerMoveColumn=0;
		if(playerId==myPlayerId)
			playerMoveColumn=insertColumnValue();
		else
			playerMoveColumn=waitColumnValue(sd, adversary_socket);							
		//check if move is allowed
		rowMove=checkMove(gameMatrix,playerMoveColumn);
	}while(rowMove<0);
	
	gameMatrix[rowMove][playerMoveColumn]=simbol;
	winner = checkWinner(gameMatrix,rowMove,playerMoveColumn,simbol);
	// if my move send it to the adversary
	if(playerId==myPlayerId)
	{
		//msg structure
		//insert content
		memcpy(integer_column, &playerMoveColumn,sizeof(playerMoveColumn));	
		ret=sendto(sd,integer_column,sizeof(integer_column),0,(struct sockaddr*)adversary_socket,sizeof(*adversary_socket));

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

int gameStart()
{
	/* UDP Socket data structure */
	int sd, new_sd, ret, check_bind;
	struct sockaddr_in adversary_socket; //where to send/recive data
	/* ************************* */
	int myPlayerId=0;
	int indexMove;
	int moveNumber=0;
	int playerId=0; //this must be filled by the protocol
	bool winner=false;
	char  gameMatrix[6][7];
	char ad_soc_num[10];
	
	myPlayerId=initiateGame(gameMatrix);
	
	/********************************** SOCKET CREATION **************************************/
	sd=socket(AF_INET, SOCK_DGRAM, 0);
	memset(&adversary_socket, 0, sizeof(adversary_socket));
	adversary_socket.sin_family=AF_INET;
	//the socket number used for this service is 2020
	adversary_socket.sin_port=htons(atol("2020"));
	
	if(myPlayerId==1){
		//second player must have an open socket to listen
		adversary_socket.sin_addr.s_addr=INADDR_ANY; 
		check_bind=bind(sd, (struct sockaddr*)&adversary_socket, sizeof(adversary_socket));
		if(check_bind<0)
		{
			perror("Errore binding the socket");
			exit(0);
		}
	}	
	else{
		inet_pton(AF_INET,"127.0.0.1",&adversary_socket.sin_addr);  
	}
	/****************************************************************************************/
	
	cout<<""<<endl;
	printGame(gameMatrix);
	do
	{
		winner=playerMove(gameMatrix,playerId,myPlayerId,sd,&adversary_socket,moveNumber);
		moveNumber++;
		printGame(gameMatrix);
		playerId++;
		playerId=playerId%2;
	}while(!winner); 
	cout<<"The game ended"<<endl;
	return 0;
}

int main()
{
	gameStart();
}
