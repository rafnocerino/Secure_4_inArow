#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
using namespace std;

#define LOGIN_REQ 0
#define LOGIN_OK 1
#define LOGIN_NO 2
#define AVAILABLE_USER_LIST 3
#define CHALLENGE_REQUEST 4
#define CHALLENGE_ACCEPTED 5
#define CHALLENGE_START 6
#define CHALLENGE_TIMER_EXP 7
#define CHALLENGE_REFUSED 8
#define CHALLENGE_UNAVAILABLE 9
#define UPDATE_STATUS 10
#define ACK 11
#define EXIT 12
#define MALFORMED_MSG 13
#define BUF_SIZE 512

void login() {}

bool check_malformation(int socket, int pos, char* buffer, uint8_t rcv_opcode, uint8_t exp_opcode, uint8_t rcv_seq_numb, uint8_t* seq_numb,
                        sockaddr_in* sv_addr) {
    
    if(rcv_opcode==MALFORMED_MSG){
        //this means that the msg that i sent was modified during the forwarding
        close(socket);
        exit(-1);
    }

    if ((rcv_opcode != exp_opcode) || (rcv_seq_numb != *(seq_numb))) {
        // the msg is malformed --> send a malformed msg to the server
        memset(buffer, 0, BUF_SIZE);
        *(seq_numb)++;
        pos = 0;
        int opcode = 13;

        memcpy(buffer, &opcode, sizeof(opcode));
        pos += sizeof(opcode);

        memcpy(buffer + pos, seq_numb, sizeof(seq_numb));
        pos += sizeof(seq_numb);

        int  ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)&sv_addr, sizeof(sv_addr));

        close(socket);
        exit(-1);
    }
}

void wait(int socket, sockaddr_in* sv_addr, char* user) {
    char buffer[BUF_SIZE];
    int size, received, ret;
    uint8_t op_code;
    uint8_t seq_numb;
    uint8_t status_code;
    uint8_t rcv_opcode, rcv_seq_numb;
    int pos = 0;
    struct timeval time;

    time.tv_sec = 300;  // attualmente scelto cosi--->da confermare
    time.tv_usec = 0;

    setsockopt(socket, S0L_SOCKET, S0_RCVTIME0, (const char*)&time, sizeof(time));

    op_code = 10;
    seq_numb = 7;  // attualmente scelto cosi-->futuro randomizzato
    status_code = 2;

    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);
    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);
    strcpy(buffer + pos, user);
    pos += strlen(user) + 1;
    memcpy(buffer + pos, &status_code, sizeof(status_code));
    pos += sizeof(status_code);

    // sended the update status msg ( wait )
    ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)&sv_addr, sizeof(sv_addr));

    if (ret < 0) {
        perror("Errore nell'invio dello status al server \n");
        exit(-1);
    }

    memset(buffer, 0, BUF_SIZE);

    // now i wait the ack from the server
    size = sizeof(sv_addr);
    pos = 0;
    received = recvfrom(socket, buffer, 2, 0, (struct sockaddr*)&sv_addr, &size);

    memcpy(&rcv_opcode, buffer, sizeof(rcv_opcode));
    pos += sizeof(rcv_opcode);

    memcpy(&rcv_seq_numb, buffer + pos, sizeof(rcv_seq_numb));
    pos += 2;

    // now i do the check on the received fields
    /*if( (rcv_opcode != ACK) || (rcv_seq_numb != seq_numb) ){

            //the msg is malformed --> send a malformed msg to the server
            memset(buffer,0,BUF_SIZE);
            seq_numb++;
            pos=0;
            opcode=13;

            memcpy(buffer,&opcode,sizeof(opcode));
            pos+=sizeof(opcode);

            memcpy(buffer+pos,&seq_numb,sizeof(seq_numb));
            pos+=sizeof(seq_numb);

            ret=sendto(socket,buffer,pos,0,(struct sockaddr*)&sv_addr,sizeof(sv_addr));

            close(socket);
            exit(-1);

    }*/

    check_malformation(socket, pos, buffer, rcv_opcode, ACK, rcv_seq_numb, &seq_numb, &sv_addr);

    // if i'm here means that the msg is not malformed

    cout << "Player waits for a challenge reception ! " << endl;

    memset(buffer, 0, BUF_SIZE);
    size = sizeof(sv_addr);
    pos = 0;

    // call the recvfrom in order to wait a challenge request, if a challenge request is not recevide after x seconds the client leaves the wait mode
    received = recvfrom(socket, buffer, 258, 0, (struct sockaddr*)&sv_addr, &size);

    if (received == 0) {  // timeout elapsed

        cout << "No challenge received in 5 minutes, the user will be redirected to the main menu! " << endl;
        pos = 0;

        // the client has to leave the wait mode but before has to notify the server that it is no more available for receive challenges

        op_code = 10;
        seq_numb++;  // attualmente scelto cosi-->futuro randomizzato
        status_code = 0;

        memcpy(buffer, &op_code, sizeof(op_code));
        pos += sizeof(op_code);
        memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
        pos += sizeof(seq_numb);
        strcpy(buffer + pos, user);
        pos += strlen(user) + 1;
        memcpy(buffer + pos, &status_code, sizeof(status_code));
        pos += sizeof(status_code);

        ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)&sv_addr, sizeof(sv_addr));  // the status of the user is now idle-->main menu

        // dubbio sulla porta del ricevitore/ server ascolta?

        if (ret < 0) {
            perror("Errore nell'invio dello status al server \n");
            exit(-1);
        }

        return;  // the user comes back to the main menu

    } else {  
        // i have received a challenge request
        
    
    }
}

void challenge() {}

int main() {
    char cmd[10];
    int sock;
    char ip_addr[] = "127.0.0.1";
    uint16_t port;
    struct sockaddr_in sv_addr;

    memset(&sv_addr, 0, sizeof(sv_addr));
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_port = htons(port);

    inet_pton(AF_INET, ip_addr, &sv_addr.sin_addr);

    login();

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
            wait();

            continue;
        }

        if (strcmp(cmd, "!challenge") == 0) {
            challenge();

            continue;
        }

        if (strcmp(cmd, "!exit") == 0) {
            break;
        }

        else {
            cout << "the inserted command is wrong, please try with a new one or !help to see the command list!" << endl;
        }
    }
    return 0;
}
