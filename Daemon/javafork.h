/*System V IPC keys*/
#define SHAREMEMKEY 1
#define SHAREMEMSEM 2

/*Non-argument default values*/
#define PORT 5193
#define IPADDRESS "127.0.0.1"
#define QUEUE 6



struct tcpforkhdr{
    //In this way, there are not issues related to ENDIANNESS or padding
    //but we are wasting bytes for the type field...
    uint32_t type;    /*Data alignment: 4-byte aligned. For Java, we must send the integer using BIG ENDIAN*/
    uint32_t length;  /*Data alignment: 4-byte aligned. For Java, we must send the integer using BIG ENDIAN*/

    //We use fixed width integer types from C99.
};



/****************************************************************************************/
/* This method is used by pthread_create                                                */
/*                                                                                      */
/* INPUT PARAMETER: socket file descriptor                                              */
/* RETURNS: void                                                                        */
/****************************************************************************************/
void *serverThread (void *arg);



/****************************************************************************************/
/* This method is used by pthread_create                                                */
/*                                                                                      */
/* INPUT PARAMETER: socket file descriptor                                              */
/* INPUT PARAMETER:                                                                     */
/* INPUT PARAMETER:                                                                     */
/* RETURNS: void                                                                        */
/****************************************************************************************/
int daemonize(const char *pname, int facility, int option);



/****************************************************************************************/
/* This method is used by pthread_create                                                */
/*                                                                                      */
/* INPUT PARAMETER: socket file descriptor                                              */
/* RETURNS: int                                                                         */
/****************************************************************************************/
int main_daemon (char *address, int port, int queue);



/****************************************************************************************/
/* This method is used by pthread_create                                                */
/*                                                                                      */
/* INPUT PARAMETER: socket file descriptor                                              */
/* RETURNS: void                                                                        */
/****************************************************************************************/
int fork_system(int socket, char *command, int *returnst);



/****************************************************************************************/
/* This method is used by pthread_create                                                */
/*                                                                                      */
/* INPUT PARAMETER: socket file descriptor                                              */
/* RETURNS: void                                                                        */
/****************************************************************************************/
int pre_fork_system(int socket, char *command);



/****************************************************************************************/
/* This method is used by pthread_create                                                */
/*                                                                                      */
/* INPUT PARAMETER: socket file descriptor                                              */
/* RETURNS: void                                                                        */
/****************************************************************************************/
void sigint_handler();



int required_sock_options (int socket);



int receive_from_socket (int socket, char *data, int len, long timeout, long utimeout);



int readable_timeout (int fd, long timeout, long utimeout);



int readable (int socket, char *data, int len, int flags);
