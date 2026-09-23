#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>

//ola amig

#define MAX_CMD 11
#define MAX_UID 7
#define MAX_PASSWORD 9
#define MAX_BUFFER 64
#define MAX_IP 30
#define DSIP "193.136.138.142"
#define DSPORT "59000"

sig_atomic_t keep_running = 1;

typedef struct {
    int fd;
    struct sockaddr_in addr;
    socklen_t addrlen;
} connection;

typedef struct {
    char uid[MAX_UID];
    char password[MAX_PASSWORD];
} user;

char* get_id(user *x) {
    return x->uid;
}
char* get_password(user *x) {
    return x->password;
}
void set_id(user *x, const char *id) {
    strcpy(x->uid, id);
}
void set_password(user *x, const char *password) {
    strcpy(x->password, password);
}

void sigint_handler(int sig){
    (void) sig;
    keep_running = 0;
}

int verify_port(int port) {
    if (port < 1 || port > 65535) {
        printf("invalid port\n");
        return 0;
    }
    return 1;
}

int verify_uid(const char *UID) {
    if (strlen(UID) != 6) {
        printf("invalid uid\n");
        return 0;
    }
    for (int i = 0; i < 6; i++) {
        if (!isdigit(UID[i])) {
            printf("invalid uid\n");
            return 0;
        }
    }
    return 1;
}
int verify_password(const char *password) {
    if (strlen(password) != 8) {
        printf("invalid password\n");
        return 0;
    }
    for (int i = 0; i < 8; i++) {
        if (!isalnum(password[i])) {
            printf("invalid password\n");
            return 0;
        }
    }
    return 1;
}

void server_connect (connection *conn, struct addrinfo **res, const char *ip, const char *port) {
    struct addrinfo hints;

    conn->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn->fd ==-1) exit(1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(ip, port, &hints, res) != 0) exit(1);
}

int handle_login(connection conn, struct addrinfo *res, user temp_user, int peerport, int *is_logged_in) {
    char buffer[MAX_BUFFER];
    ssize_t n;

    if (!verify_uid(get_id(&temp_user)) || !verify_password(get_password(&temp_user))) return 1;

    snprintf(buffer, sizeof(buffer), "LIN %s %s %d\n", get_id(&temp_user), get_password(&temp_user), peerport);
    if (sendto(conn.fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen) == -1) exit(1);

    conn.addrlen = sizeof(conn.addr);
    n = recvfrom(conn.fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&conn.addr, &conn.addrlen);
    if (n == -1) exit(1);
    buffer[n] = '\0';

    char response[4];

    sscanf(buffer, "%*s %s", response);

    if (strcmp(response, "OK") == 0) {
        *is_logged_in = 1;
        printf("successful login\n");
    } else if (strcmp(response, "NOK") == 0) {
        printf("incorrect login attempt\n");
    } else if (strcmp(response, "REG") == 0) {
        *is_logged_in = 1;
        printf("new user registered\n");
    }
    return 0;
}

int handle_logout(connection conn, struct addrinfo *res, user logged_user, int peerport, int *is_logged_in) {
    char buffer[MAX_BUFFER];
    ssize_t n;

    snprintf(buffer, sizeof(buffer), "LOU %s %s\n", get_id(&logged_user), get_password(&logged_user));
    if(sendto(conn.fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen) == -1) exit(1);

    conn.addrlen = sizeof(conn.addr);
    n = recvfrom(conn.fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&conn.addr, &conn.addrlen);
    if(n == -1) exit(1);
    buffer[n] = '\0';

    char response[4];
    sscanf(buffer, "%*s %s", response);

    if(strcmp(response, "OK") == 0){
        *is_logged_in = 0;
        printf("successful logout\n");
    } else if(strcmp(response, "NLG") == 0){
        printf("user not logged in\n");
    } else if(strcmp(response, "UNR") == 0){
        printf("unknown user\n");
    } else if(strcmp(response, "WRP") == 0){
        printf("unsuccessful logout\n");
    }
    return 0; 
}

int handle_unregister(connection conn, struct addrinfo *res, user logged_user, int peerport, int *is_logged_in) {
    char buffer[MAX_BUFFER];
    ssize_t n;

    snprintf(buffer, sizeof(buffer), "UNR %s %s\n", get_id(&logged_user), get_password(&logged_user));
    if(sendto(conn.fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen) == -1) exit(1);

    conn.addrlen = sizeof(conn.addr);
    n = recvfrom(conn.fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&conn.addr, &conn.addrlen);
    if(n == -1) exit(1);
    buffer[n] = '\0';

    char response[4];
    sscanf(buffer, "%*s %s", response);

    if(strcmp(response, "OK") == 0){
        *is_logged_in = 0;
        printf("successful unregister\n");
    } else if(strcmp(response, "NOK") == 0){
        printf("incorrect unregister attempt\n");
    } else if(strcmp(response, "UNR") == 0){
        printf("unknown user\n");
    } else if(strcmp(response, "WRP") == 0){
        printf("unsuccessful unregister\n");
    }
    return 0; 
}

void read_command(connection conn, struct addrinfo *res, int peerport){
    char command[MAX_CMD];
    user temp_user;
    user logged_user;
    char extra[2];
    char buffer[MAX_BUFFER];
    int args;
    int is_logged_in = 0;

    while(keep_running){
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            if(!keep_running) break;
            break;
        }

        args = sscanf(buffer, "%s %s %s %s", command, get_id(&temp_user), get_password(&temp_user), extra);
        if (args >= 1) {
            if (args == 3 && strcmp(command, "login") == 0){
                if(is_logged_in) {
                    printf("already logged in\n");
                    continue;
                } handle_login(conn, res, temp_user, peerport, &is_logged_in);
                if(is_logged_in){
                    set_id(&logged_user, get_id(&temp_user));
                    set_password(&logged_user, get_password(&temp_user));
                }
            } else if (args == 1 && strcmp(command, "exit") == 0){
                if(is_logged_in){
                    printf("need to logout first\n");
                    continue;
                } break;
            } else if (args == 1 && strcmp(command, "logout") == 0){
                if (!is_logged_in) {
                    printf("user not logged in\n");
                    continue;
                } handle_logout(conn, res, logged_user, peerport, &is_logged_in);
            } else if (args == 1 && strcmp(command, "unregister") == 0){
                if (!is_logged_in) {
                    printf("user not logged in/registered\n");
                    continue;
                } handle_unregister(conn, res, logged_user, peerport, &is_logged_in);
            } else {
            printf("Invalid command or arguments\n");
            }
        }
    }
}

int get_flags(int argc,char *argv[], int *peerport, char *ip, char *port){
    int opt;

    while ((opt = getopt(argc, argv, "m:n:p:")) != -1) {
        switch (opt) {
            case 'm':
                *peerport = atoi(optarg);
                break;
            case 'n':
                strcpy(ip, optarg);
                break;
            case 'p':
                strcpy(port, optarg);
                if (!verify_port(atoi(port))) {
                    printf("invalid dsport.\n");
                    return 1;
                }
                break;
            default:
                printf("invalid arguments\n");
                return 1;
        }
    }

    if (!verify_port(*peerport)) {
        printf("invalid peerport.\n");
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]){
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    signal(SIGPIPE, SIG_IGN);

    int peerport = 0;
    char ip[MAX_IP] = DSIP; 
    char port[6] = DSPORT;
    
    if (get_flags(argc, argv, &peerport, ip, port) != 0){
        return 1;
    }

    connection conn;
    struct addrinfo *res;

    server_connect(&conn, &res, ip, port);
    
    read_command(conn, res, peerport);
    
    freeaddrinfo(res);
    close(conn.fd);
    return 0;
}