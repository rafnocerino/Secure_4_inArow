#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include "protocol_constant.h"
#include "check_message.h"
#include "send_message.h"
#include "gioco_v2.1.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;


uint8_t seq_numb;

#define BUF_SIZE 512

//valutare la possibilità di fare funzione receive_ACK()---> riduce di molto la ridondanza

void receive_ACK(int socket,unsigned char* buffer,int addr_size,struct sockaddr_in* sv_addr,int& received){
	printf("Entrato.\n");
    socklen_t size = addr_size;
    int pos = 0;
    memset(buffer, 0, BUF_SIZE);
    received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr, &size);
	printf("Ricevuto.\n");
    if (received < SIZE_MESSAGE_ACK) {
        perror("There was an error during the reception of the ACK ! \n");
        close(socket);
        exit(-1);
    }

}

void login(int sock,struct sockaddr_in& serverAddress,const char* user){
	unsigned char *buf;
	buf = (unsigned char*)malloc(SIZE_MESSAGE_LOGIN);
	int memcpyPos = 0;
	uint8_t opcode = OPCODE_LOGIN;	
	seq_numb = 0;
	uint8_t stringDim = strlen(user) + 1;
	memcpy(buf , &opcode, SIZE_OPCODE);
	memcpyPos += SIZE_OPCODE;
	memcpy(buf + memcpyPos,&seq_numb,SIZE_SEQNUMBER);	
	memcpyPos += SIZE_SEQNUMBER;
	memcpy(buf + memcpyPos,&stringDim,SIZE_LEN);
	memcpyPos += SIZE_LEN;
	memcpy(buf + memcpyPos,user,strlen(user)+1);
	memcpyPos += strlen(user) + 1;
    char ip_addr[] = "127.0.0.1";
    uint16_t port = 7799;
    struct sockaddr_in sv_addr;
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = port;
    inet_pton(AF_INET, ip_addr, &sv_addr.sin_addr);
	printf("Messaggio inviato:\n");
 	BIO_dump_fp (stdout, (const char *)buf, memcpyPos);
	sendto(sock, buf, memcpyPos, 0, (struct sockaddr*)&sv_addr, sizeof(struct sockaddr_in));
	//Ricezione dell'ACK
	free(buf);
	socklen_t size = sizeof(struct sockaddr_in);
	buf = (unsigned char*)malloc(SIZE_MESSAGE_ACK);
	int received = recvfrom(sock, buf, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)&serverAddress,&size);
	printf("Messaggio ricevuto:\n");
 	BIO_dump_fp (stdout, (const char *)buf, received);
}

void exit(int socket,sockaddr_in* sv_addr_priv, int addr_size,char* user){
    bool check;
    int received;
    unsigned char buffer[BUF_SIZE];

    send_exit(socket,buffer,user,++seq_numb,sv_addr_priv,addr_size);

    receive_ACK(socket,buffer,addr_size,sv_addr_priv,received); 
	printf("ACK ricevuto!\n");   
    check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
    if (!check) {
        cout<<"ACK received after exit msg is altered, the app will be closed!"<<endl;
        // received an altered msg-->send malformed msg
        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
        close(socket);
        exit(-1);
    }

    close(socket);
    exit(-1);


}

void wait(int socket, sockaddr_in* sv_addr_main, sockaddr_in* sv_addr_priv, sockaddr_in* sv_addr_challenge, int addr_size, const char* user) {
    unsigned char buffer[BUF_SIZE];
    int received, ret;
    socklen_t size;
    uint8_t op_code;
    uint8_t status_code;
    uint8_t rcv_opcode, rcv_seq_numb;
    int pos = 0;
    struct timeval time;
    char challenging_user[255];
    char chg_cmd[6];
    unsigned char adv_ip[SIZE_IP_ADDRESS];
    unsigned char adv_pubkey[257];
    int challenge_id;
    bool check;
    uint8_t user_len;

    time.tv_sec = 180;  // attualmente scelto cosi--->da confermare
    time.tv_usec = 0;

    seq_numb = seq_numb + 1;  // attualmente scelto cosi-->futuro randomizzato
    user_len = strlen(user)+1;
	
	printf("USER: %s.\n",user);
	printf("USER.LEN: %u.\n",user_len);

    // sent the update status used to notify the server that the client will wait challenge requests
    send_UpdateStatus(socket, buffer, user, user_len, OPCODE_UPDATE_STATUS, seq_numb, STATUS_WAITING, sv_addr_priv, addr_size);

    // now i wait the ack from the server

    receive_ACK(socket,buffer,addr_size,sv_addr_priv,received); 
	printf("ACK ricevuto!\n");   
    check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
    if (!check) {
        cout<<"ACK received after first UpdateStatus is altered, the app will be closed!"<<endl;
        // received an altered msg-->send malformed msg
        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
        close(socket);
        exit(-1);
    }

    // if i'm here means that the msg is not malformed
    cout << "Player waits for a challenge reception ! " << endl;

    memset(buffer, 0, BUF_SIZE);
    size = addr_size;
    pos = 0;

    // call the recvfrom in order to wait a challenge request, if a challenge request is not recevide after x seconds the client leaves the wait mode
    
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time)); // set timer on socket
    received = recvfrom(socket, buffer, SIZE_MESSAGE_CHALLENGE_REQUEST, 0, (struct sockaddr*)sv_addr_challenge, &size);

    if (received <= 0) {  // timeout elapsed

        cout << "No challenge received in 5 minutes, the user will be redirected to the main menu! " << endl;
        pos = 0;

        //reset timer 
        time.tv_sec = 0;  
        time.tv_usec = 0;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));

        // the client has to leave the wait mode but before has to notify the server that it is no more available for receive challenges
        // so it sends on its "associated port" of the server the update status (idle) msg

        send_UpdateStatus(socket, buffer, user, user_len, OPCODE_UPDATE_STATUS, ++seq_numb, STATUS_IDLE, sv_addr_priv, addr_size);

        receive_ACK(socket,buffer,addr_size,sv_addr_priv,received);  

        check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
        if (!check) {
            cout<<"ACK received after the updateStatus before idle is altered, app will be closed !"<<endl;
            // received an altered msg-->send malformed msg
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
            close(socket);
            exit(-1);
        }

        return;  // the user comes back to the main menu

    } else {
        // i have received a challenge request

        check = check_challengeRequest(socket, buffer, received, OPCODE_CHALLENGE_REQUEST, 0, challenging_user, challenge_id, rcv_seq_numb, NULL);
        if (!check) {
            cout<<"The challenge request msg received is altered, the app will be closed!"<<endl;
            // received an altered msg-->send malformed msg
            // in this case we have to send 2 malformed msg in order to notify our "associate thread" and the "challenging thread"
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, rcv_seq_numb, sv_addr_priv, addr_size);
            //send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

            close(socket);
            exit(-1);
        }

        // if i'm here means that the structure of the challenge request received is ok!
        // ACK must be sent

        send_ACK(socket, buffer, OPCODE_ACK, rcv_seq_numb, sv_addr_challenge, addr_size);

        cout << "Challenge request received from: " << challenging_user << " ! \n";
        cout << "Write ACCEPT to play otherwise write REFUSE \n";
        cin >> chg_cmd;

        while (strcmp(chg_cmd, "ACCEPT") != 0 && strcmp(chg_cmd, "REFUSE") != 0) {
            cout << "Wrong command inserted, please retry!" << endl;
            cin >> chg_cmd;
        }

        //reset timer 
        time.tv_sec = 0;  
        time.tv_usec = 0;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));

        if (strcmp(chg_cmd, "ACCEPT") == 0) {
            // we have accepted the challenge request
            //send_challengeAccepted(socket, buffer, OPCODE_CHALLENGE_ACCEPTED, ++rcv_seq_numb, sv_addr_challenge, addr_size, challenge_id);
            send_challengeAccepted(socket, buffer, OPCODE_CHALLENGE_ACCEPTED, ++seq_numb, sv_addr_priv, addr_size, challenge_id);

            receive_ACK(socket,buffer,addr_size,sv_addr_priv,received);  
            check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
            if (!check) {
                cout<<"The ACK received after sending challenge accepted is altered, the app will be closed!"<<endl;
                send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
               // send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

                close(socket);
                exit(-1);
            }
            // now i have to wait for a challenge start or for a challenge unavailable
            memset(buffer, 0, BUF_SIZE);
            size = addr_size;
            pos = 0;

            received = recvfrom(socket, buffer, SIZE_MESSAGE_CHALLENGE_START, 0, (struct sockaddr*)sv_addr_priv, &size);

            // i have to distinguish if the received msg is challenge_start or a challenge_unavailable or also a malformed msg
            memcpy(&rcv_opcode, buffer, SIZE_OPCODE);

            if(rcv_opcode != OPCODE_MALFORMED_MEX && rcv_opcode != OPCODE_CHALLENGE_UNAVAILABLE && rcv_opcode != OPCODE_CHALLENGE_START){
                
                cout<<"received an altered response after challenge accept msg, app will be closed !"<<endl;
                send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
                //send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);
                close(socket);
                exit(-1);
            }

            if(rcv_opcode == OPCODE_MALFORMED_MEX){

                cout<<"Received a malformed msg, the app will beclosed !"<<endl;
                close(socket);
                exit(-1);

            }

            if (rcv_opcode == OPCODE_CHALLENGE_UNAVAILABLE) {

                cout<<"The challenging user is no more available, now you will be redirected to main menu!"<<endl;
                check = check_challengeUnavailable(socket, buffer, received, ++seq_numb);
                if (!check) {
                    cout<<"The challenge unavailable msg received is altered, the app will be closed!"<<endl;
                    send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
                    //send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

                    close(socket);
                    exit(-1);
                }

                send_ACK(socket, buffer, OPCODE_ACK, seq_numb, sv_addr_priv, addr_size);
            }
            if (rcv_opcode == OPCODE_CHALLENGE_START) {
                cout<<"The challenging user is available, the match can start!"<<endl;
                check = check_challengeStart(socket, buffer, received, ++seq_numb, adv_ip, adv_pubkey);
                if (!check) {
                    cout<<"The challenge start msg is altered, the app will be closed!"<<endl;
                    send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
                    //send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

                    close(socket);
                    exit(-1);
                }

                send_ACK(socket, buffer, OPCODE_ACK, seq_numb, sv_addr_priv, addr_size);
                // here we will insert a function call in order to start the game
		gameStart(adv_ip,1);            
		}
        }

        // we have refused the challenge --> we send a challenge refused msg
        if (strcmp((char*)chg_cmd, "REFUSE") == 0){

            send_challengeRefused(socket, buffer, ++seq_numb, challenge_id, sv_addr_priv, addr_size);

            receive_ACK(socket,buffer,addr_size,sv_addr_priv,received);  

            check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
            if (!check) {
                cout<<"The ACK received for challenge refused msg is altered, the app will be closed!"<<endl;
                // in this case the malformed msg is sent only " to my personal thread" since the other thread is no more listening
                send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);

                close(socket);
                exit(-1);
            }
        }
           
        // before leaving the wait mode i have to notify to my "associated" thread that i'm returning in idle mode

        size = addr_size;
        send_UpdateStatus(socket, buffer, user, user_len, OPCODE_UPDATE_STATUS, ++seq_numb, STATUS_IDLE, sv_addr_priv, addr_size);

        // now i wait the ack from the server
        receive_ACK(socket,buffer,addr_size,sv_addr_priv,received);  

        check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
        if (!check) {
            cout<<"The ACK received after last UpdateStatus before main menu is altered, the app will be closed!"<<endl;
            // received an altered msg-->send malformed msg
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
            close(socket);
            exit(-1);
        }
        
        cout<<"Now you will be redirected to the main menu!"<<endl;
    }
}

void challenge(int socket, sockaddr_in* sv_addr_main, sockaddr_in* sv_addr_priv,sockaddr_in* sv_addr_challenge,int addr_size,const char* user,char* available_users,int& avail_len){

    unsigned char buffer[BUF_SIZE];
    int received, ret;
    socklen_t size;
    uint8_t rcv_seq_numb, rcv_opcode;
    int pos = 0;
    struct timeval time;
    char challenged_user[255];
    unsigned char adv_ip[SIZE_IP_ADDRESS];
    unsigned char adv_pubkey[2049];
    int challenge_id;
    bool check;
    uint8_t user_len=strlen(user)+1;

    seq_numb = seq_numb + 1; //scelto a caso

    //the first thing that the client does is to notify the server that he wants to send challenge requests
    size=addr_size;
    send_UpdateStatus(socket,buffer,user,user_len,OPCODE_UPDATE_STATUS,seq_numb,STATUS_CHALLENGING,sv_addr_priv,size);

    // now i wait the ack from the server
    receive_ACK(socket,buffer,addr_size,sv_addr_priv,received);

    check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
    if (!check) {

        cout<<"ACK received after first UpdateStatus is altered!"<<endl;
        // received an altered msg-->send malformed msg
        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
        close(socket);
        exit(-1);
    }

    //now the user has to insert as input the name of the user who wants to challenge
    cout<<"Please insert the name of the challenged user ! \n";
    cin>>challenged_user;

   
    //now i send the challenge request to the inserted user
    send_challengeRequest(socket,sv_addr_priv,addr_size,buffer,user,challenged_user,++seq_numb,0);

    //wait for ACK
    receive_ACK(socket,buffer,addr_size,sv_addr_priv,received);

    check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
    if (!check) {

        cout<<"ACK received after Challenge Request is altered!"<<endl;

        // received an altered msg-->send malformed msg
        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
        close(socket);
        exit(-1);
    }

    // now i can receive several possible responses: CHALLENGE_START,CHALLENGE_REFUSED,CHALLENGE_UNAVAILABLE, CHALLENGE TIMER EXPIRED
    
    
    memset(buffer, 0, BUF_SIZE);
    size = addr_size;
    pos = 0;

    received = recvfrom(socket, buffer, SIZE_MESSAGE_CHALLENGE_START , 0, (struct sockaddr*)sv_addr_challenge, &size);
   
    //now i have to distinguish if i have received CHALLENGE_START, CHALLENGE REFUSED, CHALLENGE_UNAVAILABLE OR TIMER EXPIRED

    memcpy(&rcv_opcode, buffer, SIZE_OPCODE);
    pos+=SIZE_OPCODE;
    memcpy(&rcv_seq_numb,buffer+pos,SIZE_OPCODE);

    if(rcv_opcode != OPCODE_MALFORMED_MEX && rcv_opcode != OPCODE_CHALLENGE_TIMER_EXPIRED && rcv_opcode != OPCODE_CHALLENGE_REFUSED && rcv_opcode !=OPCODE_CHALLENGE_UNAVAILABLE && rcv_opcode != OPCODE_CHALLENGE_START){

        cout<<"After challenge reuqest, received an altered message !"<<endl;

        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, rcv_seq_numb, sv_addr_challenge, addr_size);
        close(socket);
        exit(-1);

    }

    if(rcv_opcode == OPCODE_MALFORMED_MEX){

        cout<<"Received a malformed msg, the application will be closed"<<endl;

        close(socket);
        exit(-1);

    }

    /*if(rcv_opcode == OPCODE_CHALLENGE_TIMER_EXPIRED){
        
        cout<<"The challenge does not receive response in time ! "<<endl;
        
        check = check_challengeTimerExpired(socket,buffer,received,++seq_numb);

        if(!check){
            cout<<"The challenge timer expired msg is altered, the app will be closed !"<<endl;
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, seq_numb, sv_addr_priv, addr_size);
            close(socket);
            exit(-1);
        }

        send_ACK(socket, buffer, OPCODE_ACK,seq_numb, sv_addr_priv, addr_size);
        
    }*/


    if(rcv_opcode == OPCODE_CHALLENGE_REFUSED){
        
        cout<<"Challenge request refused !"<<endl;

        check = check_challengeRefused(socket,buffer,received,rcv_seq_numb,&challenge_id);
        
        if(!check){
            cout<<"The challenge refused msg is altered, the app will be closed !"<<endl;
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, rcv_seq_numb, sv_addr_challenge, addr_size);
            close(socket);
            exit(-1);
        }

        send_ACK(socket, buffer, OPCODE_ACK,rcv_seq_numb, sv_addr_challenge, addr_size);
    }

    if (rcv_opcode == OPCODE_CHALLENGE_UNAVAILABLE) {
        
        cout<<"The challenged user is no more available !"<<endl;

        check = check_challengeUnavailable(socket, buffer, received, ++seq_numb);
        if (!check) {
            cout<<"The challenge unavailable msg is altered, the app will be closed !"<<endl;
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, rcv_seq_numb, sv_addr_challenge, addr_size);
            close(socket);
            exit(-1);
            }

        send_ACK(socket, buffer, OPCODE_ACK,seq_numb, sv_addr_priv, addr_size);

        //now i receive the updated list of available users
        int flag=0;
        int len_list=0;
        int total_len=0;
        char* result = (char*)malloc(255);
        int result_size=0;
        char* temp;
        while(true){

            memset(buffer, 0, BUF_SIZE);
            size = addr_size;
            pos = 0;



            received = recvfrom(socket, buffer, SIZE_MESSAGE_AVAILABLE_USER_LIST , 0, (struct sockaddr*)sv_addr_challenge, &size);
            
			printf("Ricevuto chunk della available user list.\n");

            char list[255];
            check = check_available_userList(socket,buffer,len_list,received,++seq_numb,list,flag);
            
            if (!check) {
            cout<<"The user available list msg is altered, the app will be closed !"<<endl;
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, rcv_seq_numb, sv_addr_challenge, addr_size);
            close(socket);
            exit(-1);
            }

            send_ACK(socket, buffer, OPCODE_ACK,seq_numb, sv_addr_challenge, addr_size);         

            total_len+=len_list;
            temp=(char*)malloc(total_len);
            memcpy(temp,result,result_size);
            memcpy(temp+result_size,list,len_list);

            free(result);
            result = (char*)malloc(total_len);
            memcpy(result,temp,total_len);
            result_size=total_len;

            if(flag==1){
                break;
            }

        }
		printf("Available User List: %s\n",result);
        /*BIO_dump_fp(stdout,(const char*)result,result_size);	
        avail_len=result_size;
		available_users=(char*) malloc(avail_len);
		memcpy(available_users,result,result_size);*/
    }
    
    if (rcv_opcode == OPCODE_CHALLENGE_START) {

        cout<<"Challenge accepted! "<<endl;

        check = check_challengeStart(socket, buffer, received, rcv_seq_numb, adv_ip, adv_pubkey);
        if (!check) {
            cout<<"The challenge start msg is altered, the app will be closed !"<<endl;
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, rcv_seq_numb, sv_addr_challenge, addr_size);
            close(socket);
            exit(-1);
            }

        send_ACK(socket, buffer, OPCODE_ACK,rcv_seq_numb, sv_addr_challenge, addr_size);
        // here we will insert a function call in order to start the game
	gameStart(adv_ip,0);
    }
    

    //if the client reach this point has to return to main menu --> has to notify the server the IDLE status

    size = addr_size;
    send_UpdateStatus(socket, buffer, user, user_len, OPCODE_UPDATE_STATUS, ++seq_numb, STATUS_IDLE, sv_addr_priv, addr_size);

    //wait the ack

    receive_ACK(socket,buffer,addr_size,sv_addr_priv,received);
    
    check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
    if (!check) {
        cout<<"ACK received after last UpdateStatus is altered!"<<endl;
        // received an altered msg-->send malformed msg
        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
        close(socket);
        exit(-1);
    }
}

int main() {
    char cmd[10];
    int sock;
    char ip_addr[] = "127.0.0.1";
    uint16_t port=7799;
    struct sockaddr_in sv_addr_main;
    struct sockaddr_in sv_addr_priv;
    struct sockaddr_in sv_addr_challenge;
    char*  available_users;
    int avail_len;
	char* user = (char*) malloc(255);

	cout << "Inserisci nome utente:" << endl;
	cin >> user;

    

    memset(&sv_addr_main, 0, sizeof(sv_addr_main));
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    sv_addr_main.sin_family = AF_INET;
    sv_addr_main.sin_port = port;

    inet_pton(AF_INET, ip_addr, &sv_addr_main.sin_addr);

    login(sock,sv_addr_priv,user);

    // temp code
    /*unsigned char buffer[BUF_SIZE];
    
    memset(buffer, 0, BUF_SIZE);
    uint8_t opcode = 99;
    memcpy(buffer,&opcode,sizeof(opcode));


    int ret = sendto(sock,&opcode,1,0,(struct sockaddr*)&sv_addr_main,sizeof(sv_addr_main));
    if ( ret < 0){

        perror("Errore nell'invio \n");
		exit(-1);
    }

    socklen_t size ;
    int pos = 0;
    memset(buffer, 0, BUF_SIZE);
    int received = recvfrom(sock, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)&sv_addr_priv, &size);

    // end temp
*/
    while (1) {
        cout << "Inserisci un comando, per aiuto digita !help " << endl;
        cin >> cmd;

        if (strcmp(cmd, "!help") == 0) {
            cout << "The available commands are: " << endl;
            cout << "!help ---> returns the list of all available commands " << endl;
            cout << "!wait ---> the user waits for a challenge request " << endl;
            cout << "!challenge ---> the user wants to send a challenge request to another user !" << endl;
            cout << "!exit---> the user leaves the application !" << endl;

            continue;
        }

        if (strcmp(cmd, "!wait") == 0) {
            wait(sock,&sv_addr_main,&sv_addr_priv,&sv_addr_challenge,sizeof(sv_addr_main),user);

            continue;
        }

        if (strcmp(cmd, "!challenge") == 0) {        
            challenge(sock,&sv_addr_main,&sv_addr_priv,&sv_addr_challenge,sizeof(sv_addr_main),user,available_users,avail_len);

            continue;
        }

        if (strcmp(cmd, "!exit") == 0) {
            exit(sock,&sv_addr_priv,sizeof(sv_addr_priv),user);
            break;
        }

        else {
            cout << "the inserted command is wrong, please try with a new one or !help to see the command list!" << endl;
        }
    }
    return 0;
}
