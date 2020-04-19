#include <iostream>
using namespace std;

void initiateGame(char gameMatrix[6][7])
{
	for(int i=0;i<6;i++)
	{
		for(int j=0;j<7;j++)
		{
			gameMatrix[i][j]='*';
		}
	}
}

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

bool playerMove(char gameMatrix[6][7],int playerId)
{
	char simbol=(playerId==0?'X':'O');
	bool winner=false;
	int playerMoveColumn=0;
	int rowMove=0;
	do
	{
		cout<<"Select a column number:"<<endl;
		cin>>playerMoveColumn;
		playerMoveColumn--;
		rowMove=checkMove(gameMatrix,playerMoveColumn);
	}while(rowMove<0);
	gameMatrix[rowMove][playerMoveColumn]=simbol;
	winner = checkWinner(gameMatrix,rowMove,playerMoveColumn,simbol);
	if(winner)
	{
		//ack msg from the sender
		cout<<"THERE IS A WINNER!!!"<<endl;
		cout<<"The winner is  player "<<playerId<<endl;
	}
	return winner;
}


int main()
{
	int indexMove;
	int playerId=0;
	bool winner=false;
	char  gameMatrix[6][7];
	initiateGame(gameMatrix);
	cout << "Welcome to the game" <<endl;
	printGame(gameMatrix);
	do
	{
		winner=playerMove(gameMatrix,playerId);
		printGame(gameMatrix);
		playerId++;
		playerId=playerId%2;
	}while(!winner); 
	cout<<"The game ended"<<endl;
	return 0;
}
