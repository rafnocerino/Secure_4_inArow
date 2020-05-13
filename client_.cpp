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
#include "protocol_constant.h"
#include "send_message.h"
using namespace std;

#define BUF_SIZE 512

//valutare la possibilità di fare funzione receive_ACK()---> riduce di molto la ridondanza

void login() {}

void wait(int socket, sockaddr_in* sv_addr_main, sockaddr_in* sv_addr_priv, sockaddr_in* sv_addr_challenge, int addr_size, char* user) {
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
    unsigned char adv_ip[SIZE_IP_ADDRESS];
    unsigned char adv_pubkey[2049];
    int challenge_id;
    bool check;
    uint8_t user_len;

    time.tv_sec = 300;  // attualmente scelto cosi--->da confermare
    time.tv_usec = 0;

    op_code = 10;
    seq_numb = 7;  // attualmente scelto cosi-->futuro randomizzato
    status_code = 2;
    user_len = strlen(user);

    // sent the update status used to notify the server that the client will wait challenge requests
    send_UpdateStatus(socket, buffer, user, user_len, OPCODE_UPDATE_STATUS, seq_numb, STATUS_WAITING, sv_addr_priv, addr_size);

    // now i wait the ack from the server
    size = addr_size;
    pos = 0;
    memset(buffer, 0, BUF_SIZE);
    received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr_priv, &size);

    if (received < SIZE_MESSAGE_ACK) {
        perror("There was an error during the reception of the ACK ! \n");
        exit(-1);
    }

    check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
    if (!check) {
        // received an altered msg-->send malformed msg
        send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
        close(socket);
        exit(-1);
    }

    // if i'm here means that the msg is not malformed

    cout << "Player waits for a challenge reception ! " << endl;

    memset(buffer, 0, BUF_SIZE);
    size = addr_size;
    pos = 0;

    // call the recvfrom in order to wait a challenge request, if a challenge request is not recevide after x seconds the client leaves the wait mode
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));
    // please remember to reset the timer once used
    received = recvfrom(socket, buffer, 258, 0, (struct sockaddr*)sv_addr_challenge, &size);

    if (received == 0) {  // timeout elapsed

        cout << "No challenge received in 5 minutes, the user will be redirected to the main menu! " << endl;
        pos = 0;

        // the client has to leave the wait mode but before has to notify the server that it is no more available for receive challenges
        // so it sends on its "associated port" of the server the update status (idle) msg

        send_UpdateStatus(socket, buffer, user, user_len, OPCODE_UPDATE_STATUS, ++seq_numb, STATUS_IDLE, sv_addr_priv, addr_size);

        size = addr_size;
        pos = 0;
        memset(buffer, 0, BUF_SIZE);
        received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr_priv, &size);

        if (received < SIZE_MESSAGE_ACK) {
            perror("There was an error during the reception of the ACK ! \n");
            exit(-1);
        }

        check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
        if (!check) {
            // received an altered msg-->send malformed msg
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
            close(socket);
            exit(-1);
        }

        return;  // the user comes back to the main menu

    } else {
        // i have received a challenge request

        check = check_challengeRequest(socket, buffer, received, OPCODE_CHALLENGE_REQUEST, 0, challenging_user, challenge_id, rcv_seq_numb);
        if (!check) {
            // received an altered msg-->send malformed msg
            // in this case we have to send 2 malformed msg in order to notify our "associate thread" and the "challenging thread"
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
            send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

            close(socket);
            exit(-1);
        }

        // if i'm here means that the structure of the challenge request received is ok!
        // ACK must be sent

        send_ACK(socket, buffer, OPCODE_ACK, rcv_seq_numb, sv_addr_challenge, addr_size);

        cout << "Challenge request received from: " << challenging_user << " ! \n";
        cout << "Write ACCEPT to play othervise write REFUSE \n";
        cin >> chg_cmd;

        while (strcmp((char*)chg_cmd, "ACCEPT") != 0 && strcmp((char*)chg_cmd, "REFUSE") != 0) {
            cout << "Wrong command inserted, please retry!" << endl;
            cin >> chg_cmd;
        }

        if (strcmp((char*)chg_cmd, "ACCEPT") == 0) {
            // we have accepted the challenge request
            send_challengeAccepted(socket, buffer, OPCODE_CHALLENGE_ACCEPTED, ++rcv_seq_numb, sv_addr_challenge, addr_size, challenge_id);

            memset(buffer, 0, BUF_SIZE);
            size = addr_size;
            pos = 0;
            // receive the ack
            received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr_challenge, &size);

            if (received < SIZE_MESSAGE_ACK) {
                perror("There was an error during the reception of the ACK ! \n");
                exit(-1);
            }
            check = check_ack(socket, buffer, received, OPCODE_ACK, rcv_seq_numb);
            if (!check) {
                send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
                send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

                close(socket);
                exit(-1);
            }
            // now i have to wait for a challenge start or for a challenge unavailable
            memset(buffer, 0, BUF_SIZE);
            size = addr_size;
            pos = 0;

            received = recvfrom(socket, buffer, SIZE_MESSAGE_CHALLENGE_START, 0, (struct sockaddr*)sv_addr_challenge, &size);

            // i have to distinguish if the received msg is challenge_start or a challenge_unavailable
            memcpy(&rcv_opcode, buffer, SIZE_OPCODE);

            if(rcv_opcode == OPCODE_MALFORMED_MEX){

                close(socket);
                exit(-1);

            }

            if (rcv_opcode == OPCODE_CHALLENGE_UNAVAILABLE) {
                check = check_challenge_Unavailable(socket, buffer, received, ++rcv_seq_numb);
                if (!check) {
                    send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
                    send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

                    close(socket);
                    exit(-1);
                }

                send_ACK(socket, buffer, OPCODE_ACK, rcv_seq_numb, sv_addr_challenge, addr_size);
            }
            if (rcv_opcode == OPCODE_CHALLENGE_START) {
                check = check_challengeStart(socket, buffer, received, ++rcv_seq_numb, adv_ip, adv_pubkey);
                if (!check) {
                    send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
                    send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++rcv_seq_numb, sv_addr_challenge, addr_size);

                    close(socket);
                    exit(-1);
                }

                send_ACK(socket, buffer, OPCODE_ACK, rcv_seq_numb, sv_addr_challenge, addr_size);
                // here we will insert a function call in order to start the game
            }
        }

        // we have refused the challenge --> we send a challenge refused msg
        if (strcmp((char*)chg_cmd, "REFUSE") == 0) {
            send_challengeRefused(socket, buffer, ++rcv_seq_numb, challenge_id, sv_addr_challenge, addr_size);

            memset(buffer, 0, BUF_SIZE);
            size = addr_size;
            pos = 0;
            // receive the ack
            received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr_challenge, &size);

            if (received < SIZE_MESSAGE_ACK) {
                perror("There was an error during the reception of the ACK ! \n");
                exit(-1);
            }
            check = check_ack(socket, buffer, received, OPCODE_ACK, rcv_seq_numb);
            if (!check) {
                // in this case the malformed msg is sent only " to my personal thread" since the other thread is no more listening
                send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);

                close(socket);
                exit(-1);
            }

            // before leaving the wait mode i have to notify to my "associated" thread that i'm returning in idle mode

            size = addr_size;
            send_UpdateStatus(socket, buffer, user, user_len, OPCODE_UPDATE_STATUS, ++seq_numb, STATUS_IDLE, sv_addr_priv, addr_size);

            // now i wait the ack from the server
            size = addr_size;
            pos = 0;
            memset(buffer, 0, BUF_SIZE);
            received = recvfrom(socket, buffer, SIZE_MESSAGE_ACK, 0, (struct sockaddr*)sv_addr_priv, &size);

            if (received < SIZE_MESSAGE_ACK) {
                perror("There was an error during the reception of the ACK ! \n");
                exit(-1);
            }

            check = check_ack(socket, buffer, received, OPCODE_ACK, seq_numb);
            if (!check) {
                // received an altered msg-->send malformed msg
                send_malformedMsg(socket, buffer, OPCODE_MALFORMED_MEX, ++seq_numb, sv_addr_priv, addr_size);
                close(socket);
                exit(-1);
            }
        }
    }
}

void challenge() {}

int main() {
    char cmd[10];
    int sock;
    char ip_addr[] = "127.0.0.1";
    uint16_t port;
    struct sockaddr_in sv_addr_main;
    struct sockaddr_in sv_addr_priv;

    memset(&sv_addr_main, 0, sizeof(sv_addr_main));
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    sv_addr_main.sin_family = AF_INET;
    sv_addr_main.sin_port = htons(port);

    inet_pton(AF_INET, ip_addr, &sv_addr_main.sin_addr);

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
