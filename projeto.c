#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <sys/stat.h>

#define MAX_CMD 11
#define MAX_UID 7
#define MAX_PASSWORD 9
#define MAX_BUFFER 128
#define LIST_BUFFER 2048
#define MAX_IP 30
#define MAX_FILENAME 24
#define MAX_LABEL 20
#define MAX_TIME 16
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

typedef struct {
    char uid[16];
    long fsize;
    char label[MAX_LABEL];
    char pub_time[MAX_TIME];
    char availability[4];
} PeerInfo;

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

int verify_filename(const char *filename){
    if(strlen(filename) >= 24){
        printf("invalid filename\n");
        return 0;
    }

    const char *dot = strrchr(filename, '.');
    if(dot == NULL || dot == filename){
        printf("invalid filename\n");
            return 0;
    }

    for(const char *p = filename; p < dot; p++){
        if(!isalnum(*p) && *p != '-' && *p != '_'){
            printf("invalid filename\n");
            return 0;
        }
    }

    if(strlen(dot + 1) != 3){
        printf("invalid filename\n");
        return 0;
    }

    for(int i = 1; i <= 3; i++){
        if(!isalnum(dot[i])){
            printf("invalid filename\n");
            return 0;
        }
    }
    return 1;
}

int verify_label(const char *label){
    if(strlen(label) > 20 || strlen(label) < 1){
        printf("invalid label\n");
        return 0;
    }

    for(const char *l = label; *l != '\0'; l++){
        if(!isalnum(*l) && *l != '-' && *l != '_'){
            printf("invalid label\n");
            return 0;
        }
    }
    return 1;
}

void server_connect_UDP(connection *conn, struct addrinfo **res, const char *ip, const char *port) {
    struct addrinfo hints;
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0; 

    conn->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn->fd ==-1) exit(1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(ip, port, &hints, res) != 0) exit(1);

    if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
    }
}

int server_connect_TCP(const char *ip, const char *port){
    int fd, errcode;
    struct addrinfo hints, *res;
    ssize_t n;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) exit(1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    errcode = getaddrinfo(ip, port, &hints, &res);
    if(errcode != 0) exit(1);

    n = connect(fd, res->ai_addr, res->ai_addrlen);
    if(n == -1) {
        freeaddrinfo(res);
        exit(1);
    }
    freeaddrinfo(res);
    return fd;
}

int handle_login(connection conn, struct addrinfo *res, user temp_user, int peerport, int *is_logged_in) {
    char buffer[MAX_BUFFER];
    ssize_t n;

    if (!verify_uid(get_id(&temp_user)) || !verify_password(get_password(&temp_user))) return 1;

    snprintf(buffer, sizeof(buffer), "LIN %s %s %d\n", get_id(&temp_user), get_password(&temp_user), peerport);
    if (sendto(conn.fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen) == -1) exit(1);

    conn.addrlen = sizeof(conn.addr);
    n = recvfrom(conn.fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&conn.addr, &conn.addrlen);
    if (n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("didn't receive a server response. try again\n");
            return 1;
        } else {
            exit(1);
        }
    }

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
    if (n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("timeout waiting for server response\n");
            return 1;
        } else {
            exit(1);
        }
    }
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
    if(n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("timeout waiting for server response\n");
            return 1;
        } else {
            exit(1);
        }
    }
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

int publish_resource(connection conn, struct addrinfo *res, user logged_user, int peerport, const char *filename, const char *label){
    char buffer[MAX_BUFFER];
    ssize_t n;
    struct stat file_stat;

    if (!verify_filename(filename) || !verify_label(label)) return 1;

    if(stat(filename, &file_stat) == -1){
        printf("file does not exist in the local directory\n");
        return 0;
    }

    long f_size = file_stat.st_size;
    snprintf(buffer, sizeof(buffer), "PUB %s %s %s %ld %s\n", get_id(&logged_user), get_password(&logged_user), filename, f_size, label);
    if (sendto(conn.fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen) == -1) exit(1);

    conn.addrlen = sizeof(conn.addr);
    n = recvfrom(conn.fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&conn.addr, &conn.addrlen);
    if(n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("timeout waiting for server response\n");
            return 1;
        } else {
            exit(1);
        }
    }
    buffer[n] = '\0';

    char response[4];
    sscanf(buffer, "%*s %s", response);

    if(strcmp(response, "OK") == 0){
        printf("successful publication\n");
    } else if(strcmp(response, "NLG") == 0){
        printf("user not logged in\n");
    } else if(strcmp(response, "UNR") == 0){
        printf("unknown user\n");
    } else if(strcmp(response, "WRP") == 0){
        printf("wrong password\n");
    } else if(strcmp(response, "NOK") == 0){               //basta colocar wrong password? nao sei
        printf("unsuccessful publish\n");
    }
    return 0; 
}

int remove_resource(connection conn, struct addrinfo *res, user logged_user, int peerport, const char *filename){
    char buffer[MAX_BUFFER];
    ssize_t n;
    struct stat file_stat;

    if (!verify_filename(filename)) return 1;

    snprintf(buffer, sizeof(buffer), "REM %s %s %s\n", get_id(&logged_user), get_password(&logged_user), filename);
    if (sendto(conn.fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen) == -1) exit(1);

    conn.addrlen = sizeof(conn.addr);
    n = recvfrom(conn.fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&conn.addr, &conn.addrlen);
    if(n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("timeout waiting for server response\n");
            return 1;
        } else {
            exit(1);
        }
    }
    buffer[n] = '\0';

    char response[4];
    sscanf(buffer, "%*s %s", response);

    if(strcmp(response, "OK") == 0){
        printf("successful removal\n");
    } else if(strcmp(response, "NLG") == 0){
        printf("user not logged in\n");
    } else if(strcmp(response, "UNR") == 0){
        printf("unknown user\n");
    } else if(strcmp(response, "WRP") == 0){
        printf("wrong password\n");
    } else if(strcmp(response, "NOK") == 0){                                
        printf("resource not found\n");                      //no enunciado diz que essa é a mensagem mas devia ser tipo "nao foi publicado por este user" de acordo com outra parte do enunciado
    }
    return 0; 
}

int list_files(connection conn, struct addrinfo *res, user logged_user, int peerport){
    char buffer[LIST_BUFFER];
    ssize_t n;

    snprintf(buffer, sizeof(buffer), "LST\n");

    if (sendto(conn.fd, buffer, strlen(buffer), 0, res->ai_addr, res->ai_addrlen) == -1) exit(1);

    conn.addrlen = sizeof(conn.addr);
    n = recvfrom(conn.fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&conn.addr, &conn.addrlen);
    if(n == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("timeout waiting for server response\n");
            return 1;
        } else {
            exit(1);
        }
    }
    buffer[n] = '\0';

    char response[4];
    sscanf(buffer, "%*s %s", response);
    if (strcmp(response, "NOK") == 0) {
        printf("no published resources\n");
    }
    else if (strcmp(response, "OK") == 0) {
        char *ptr = buffer + 6;
        char filename[MAX_FILENAME];
        int count = 0;
        printf("List of published resources:\n");
        
        int bytes_read;
        while (sscanf(ptr, "%s %n", filename, &bytes_read) == 1) {
            count++;
            printf("%d %s\n", count, filename);
            ptr += bytes_read;
        }

        printf("-----------------------------\n");
    }

    return 0;
}

int handle_versions(int tcp_fd, user logged_user, const char *filename){
    char buffer[MAX_BUFFER];
    char message[MAX_BUFFER];        
    int bytes_read = 0;
    char c;
    int n;

    if(!verify_filename(filename)){
        close(tcp_fd);
        return 1;
    }

    snprintf(message, sizeof(buffer), "VRS %s\n", filename);
    write(tcp_fd, message, strlen(message));

    while(bytes_read < MAX_BUFFER -1){
        n = read(tcp_fd, &c, 1);

        if (n == -1) return 1;
        if (n == 0) break;

        buffer[bytes_read++] = c;
        if ( c == '\n'){
            break;
        }
    }

    buffer[bytes_read] = '\0';
    int chars_read = 0;
    int offset = 0;

    char response[4];
    sscanf(buffer, "%*s %s %n", response, &chars_read);
    offset += chars_read;
    char *ptr = buffer + offset;

    if(strcmp(response, "OK") == 0){
        printf("List of peers available:\n");
        PeerInfo peer;
        int count = 0;
        while(sscanf(ptr, "%s %ld %s %s %s%n", peer.uid, &peer.fsize, peer.label, peer.pub_time, peer.availability, &chars_read) == 5){
            count++;
            printf("%d.-----------------------------\n", count);
            printf("Peer UID: %s\n", peer.uid);
            printf("File Size: %ld bytes\n", peer.fsize);
            printf("Label: %s\n", peer.label);
            int year, month, day, hour, min, sec;
            sscanf(peer.pub_time, "%4d%2d%2d-%2d%2d%2d", &year, &month, &day, &hour, &min, &sec);
            printf("Publication Time: %04d-%02d-%02d %02d:%02d:%02d\n", year, month, day, hour, min, sec);
            if (strcmp(peer.availability, "AVL") == 0) {
                printf("Availability: Available\n");
            } else {
                printf("Availability: Not Available\n");
            }
            ptr += chars_read;
        }
        printf("-----------------------------\n");
    } else if (strcmp(response, "NOK") == 0){
        printf("no peer available for such resource\n"); 
    } else if(strcmp(response, "ERR") == 0){
        printf("error");
    }
    return 0; 
}

void read_command(connection conn, struct addrinfo *res, int peerport, const char *ip, const char *port){
    char command[MAX_CMD];
    user temp_user;
    user logged_user;
    char extra[2];
    char buffer[MAX_BUFFER];
    int args;
    int is_logged_in = 0;
    char filename[MAX_FILENAME];
    char label[MAX_LABEL];
    int tcp_fd;

    while(keep_running){
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            if(!keep_running) break;
            break;
        }

        //args = sscanf(buffer, "%s %s %s %s", command, get_id(&temp_user), get_password(&temp_user), extra);
        args = sscanf(buffer, "%s", command);
        if (args == 1) {
            if (strcmp(command, "login") == 0 && sscanf(buffer, "%s %s %s %s", command, get_id(&temp_user), get_password(&temp_user), extra) == 3){
                if(is_logged_in) {
                    printf("already logged in\n");
                    continue;
                } handle_login(conn, res, temp_user, peerport, &is_logged_in);
                if(is_logged_in){
                    set_id(&logged_user, get_id(&temp_user));
                    set_password(&logged_user, get_password(&temp_user));
                }
            } else if (strcmp(command, "exit") == 0){
                if(is_logged_in){
                    printf("need to logout first\n");
                    continue;
                } break;
            } else if (strcmp(command, "logout") == 0){
                if (!is_logged_in) {
                    printf("user not logged in\n");
                    continue;
                } handle_logout(conn, res, logged_user, peerport, &is_logged_in);
            } else if (strcmp(command, "unregister") == 0){
                if (!is_logged_in) {
                    printf("user not logged in/registered\n");
                    continue;
                } handle_unregister(conn, res, logged_user, peerport, &is_logged_in);
            } else if (strcmp(command, "publish") == 0 && sscanf(buffer, "%s %s %s %s", command, filename, label, extra) == 3){
                if (!is_logged_in) {
                    printf("user not logged in\n");
                    continue;
                } publish_resource(conn, res, logged_user, peerport, filename, label);
            } else if (strcmp(command, "remove") == 0 && sscanf(buffer, "%s %s %s", command, filename, extra) == 2){
                if (!is_logged_in) {
                    printf("user not logged in\n");
                    continue;
                } remove_resource(conn, res, logged_user, peerport, filename);
            } else if (strcmp(command, "list") == 0) {
                list_files(conn, res, logged_user, peerport);
            } else if (strcmp(command, "versions") == 0 && sscanf(buffer, "%s %s %s", command, filename, extra) == 2) {
                tcp_fd = server_connect_TCP(ip, port);
                handle_versions(tcp_fd, logged_user, filename);
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

    server_connect_UDP(&conn, &res, ip, port);

    read_command(conn, res, peerport, ip, port);
    
    freeaddrinfo(res);
    close(conn.fd);
    return 0;
}