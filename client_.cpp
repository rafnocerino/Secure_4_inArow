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

#include "check_message.h"
#include "send_message.h"
#include "protocol_constant.h"
using namespace std;

#define BUF_SIZE 512

void login() {}
/*void send_malformedMsg(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;
    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);

    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);

    int ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)&sv_addr, addr_size);
    if (ret < SIZE_MESSAGE_MALFORMED_MEX) {
        perror("There was an error during the sending of the malformed msg ! \n");
        exit(-1);
    }

    close(socket);
    exit(-1);
}
void send_ACK(int socket, unsigned char* buffer, uint8_t op_code, uint8_t seq_numb, sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;
    int ret;

    op_code = OPCODE_ACK;
    memset(buffer, 0, BUF_SIZE);
    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);
    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);

    ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the ACK \n");
        exit(-1);
    }
}

void send_UpdateStatus(int socket, unsigned char* buffer, char* username, uint8_t user_size, uint8_t op_code, uint8_t seq_numb, uint8_t status_code,
                       sockaddr_in* sv_addr, int addr_size) {
    int pos = 0;

    memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);
    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);
    memcpy(buffer + pos, &status_code, sizeof(status_code));
    pos += sizeof(status_code);
    memcpy(buffer + pos, &user_size, sizeof(user_size));
    pos += sizeof(user_size);
    strcpy((char*)buffer + pos, username);
    pos += strlen(username) + 1;

    int ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);
    if (ret < pos) {
        perror("There was an error during the sending of the ACK \n");
        exit(-1);
    }
}
*/
/*
bool check_malformation(int socket,unsigned char* buffer, uint8_t rcv_opcode, uint8_t exp_opcode, uint8_t rcv_seq_numb, uint8_t* seq_numb,
                        sockaddr_in* sv_addr,int addr_size) {

    int pos=0;

    if(rcv_opcode==OPCODE_MALFORMED_MEX){
        //this means that the msg that i sent was modified during the forwarding
        close(socket);
        exit(-1);
    }

    if ((rcv_opcode != exp_opcode) || (rcv_seq_numb != *(seq_numb))) {
        // the msg is malformed --> send a malformed msg to the server
        memset(buffer, 0, BUF_SIZE);
        *(seq_numb)++;
        int opcode = 13;

        memcpy(buffer, &opcode, sizeof(opcode));
        pos += sizeof(opcode);

        memcpy(buffer + pos, seq_numb, sizeof(seq_numb));
        pos += sizeof(seq_numb);

        int  ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)&sv_addr,addr_size);

        close(socket);
        exit(-1);
    }
}
*/
void wait(int socket, sockaddr_in* sv_addr, int addr_size, char* user) {
    unsigned char buffer[BUF_SIZE];
    int size, received, ret;
    uint8_t op_code;
    uint8_t seq_numb;
    uint8_t status_code;
    uint8_t rcv_opcode, rcv_seq_numb;
    int pos = 0;
    struct timeval time;
    unsigned char challenging_user[255];
    unsigned char chg_cmd[6];
    int challenge_id;
    bool check;

    time.tv_sec = 300;  // attualmente scelto cosi--->da confermare
    time.tv_usec = 0;

    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));

    op_code = 10;
    seq_numb = 7;  // attualmente scelto cosi-->futuro randomizzato
    status_code = 2;
    uint8_t len = strlen(user);

    /*memcpy(buffer, &op_code, sizeof(op_code));
    pos += sizeof(op_code);
    memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
    pos += sizeof(seq_numb);
    memcpy(buffer + pos, &status_code, sizeof(status_code));
    pos += sizeof(status_code);
    memcpy(buffer+pos,&len,sizeof(len));
    pos+=sizeof(len);
    strcpy((char*)buffer + pos, user);
    pos += strlen(user) + 1;


    // sended the update status msg ( wait )
    ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr,addr_size);*/

    send_UpdateStatus(socket, buffer, user, len, OPCODE_UPDATE_STATUS, seq_numb, STATUS_WAITING, sv_addr, addr_size);

    /* if (ret < 0) {
         perror("Errore nell'invio dello status al server \n");
         exit(-1);
     }*/

    memset(buffer, 0, BUF_SIZE);

    // now i wait the ack from the server
    size = sizeof(sv_addr);
    pos = 0;
    received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr, &size);

    if (received < SIZE_MESSAGE_ACK) {
        perror("There was an error during the reception of the ACK ! \n");
        exit(-1);
    }

    check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
    if (!check) {
        // received an altered msg-->send malformed msg
        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr, addr_size);
    }

    // if i'm here means that the msg is not malformed

    cout << "Player waits for a challenge reception ! " << endl;

    memset(buffer, 0, BUF_SIZE);
    size = sizeof(sv_addr);
    pos = 0;

    // call the recvfrom in order to wait a challenge request, if a challenge request is not recevide after x seconds the client leaves the wait mode
    received = recvfrom(socket, buffer, 258, 0, (struct sockaddr*)sv_addr, &size);

    if (received == 0) {  // timeout elapsed

        cout << "No challenge received in 5 minutes, the user will be redirected to the main menu! " << endl;
        pos = 0;

        // the client has to leave the wait mode but before has to notify the server that it is no more available for receive challenges

        // send login msg or send update status

        op_code = 10;
        seq_numb++;  // attualmente scelto cosi-->futuro randomizzato
        status_code = 0;

        memcpy(buffer, &op_code, sizeof(op_code));
        pos += sizeof(op_code);
        memcpy(buffer + pos, &seq_numb, sizeof(seq_numb));
        pos += sizeof(seq_numb);
        strcpy((char*)buffer + pos, user);
        pos += strlen(user) + 1;
        memcpy(buffer + pos, &status_code, sizeof(status_code));
        pos += sizeof(status_code);

        // in realtà la struttura sock_addr al quale inviare il messaggio di LOGIN potrbbe essere quella iniziale

        ret = sendto(socket, buffer, pos, 0, (struct sockaddr*)sv_addr, addr_size);  // the status of the user is now idle-->main menu

        // dubbio sulla porta del ricevitore/ server ascolta?

        if (ret < 0) {
            perror("Errore nell'invio dello status al server \n");
            exit(-1);
        }

        return;  // the user comes back to the main menu

    } else {
        // i have received a challenge request

        check = check_challengeRequest(socket, buffer, received, OPCODE_CHALLENGE_REQUEST, 0, challenging_user, challenge_id, rcv_seq_numb);
        if (!check) {
            // received an altered msg-->send malformed msg
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr, addr_size);
        }

        // if i'm here means that the structure of the challenge request received is ok!
        // ACK must be sent

        send_ACK(socket, buffer, OPCODE_ACK, ++rcv_seq_numb, sv_addr, addr_size);


        cout << "Challenge request received from: " << challenging_user << " ! \n";
        cout << "Write ACCEPT to play othervise write REFUSE \n";
        cin >> chg_cmd;
        while (strcmp((char*)chg_cmd, "ACCEPT") != 0 && strcmp((char*)chg_cmd, "REFUSE") != 0) {
            cout << "Wrong command inserted, please retry!" << endl;
            cin >> chg_cmd;
        }
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
