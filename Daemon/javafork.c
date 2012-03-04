#define _GNU_SOURCE

/*
 * Be aware: this program uses GNU extensions (the TEMP_FAILURE_RETRY macro)
 * I am writing (non-)portable code because I am running out of time
 * TODO: my portable macro with the same funcionality
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <strings.h>
#include <pthread.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <endian.h>
#include "javafork.h"



pid_t daemonPID;        /*Stores the daemon server PID*/
int sockfd = -1;        /*Stores the daemon server TCP socket.*/




static int closeSafely(int fd) 
{
    /*If we always initialize file descriptor variables with value -1*/
    /*this method should work like a charm*/
    return (fd == -1) ? 0 : TEMP_FAILURE_RETRY(close(fd));
}



int main (int argc, char *argv[]) 
{
	int c;                      /*Getopt parameter*/
	/*Default values*/
	char *avalue = IPADDRESS;   /*Address: numeric value or hostname*/
	int pvalue = PORT;          /*TCP port*/
	int qvalue = QUEUE;         /*TCP listen queue*/
    struct sigaction sa;        /*sig actions values*/

    /*This process is intended to be used as a daemon, it sould be launched by the INIT process, because of that*/
	/*we are not forking it (INIT needs it)*/
	if (daemonize(argv[0], LOG_SYSLOG, LOG_PID) < 0)
		return 1;

	/*Changing session.*/	
	setsid();

	
	opterr = 0;
	while ((c = getopt (argc, argv, "a:p:q:")) != -1) {
		switch (c) {
		case 'a':
			avalue = optarg;
			break;
		case 'p':
			pvalue = atoi(optarg);
			if ((pvalue > 65535) || (pvalue <= 0)) {
				syslog (LOG_ERR, "Port value %d out of range", pvalue);
				return 1;
			}
			break;
		case 'q':
			qvalue = atoi(optarg);
			break;
		case '?':
			if ((optopt == 'a') || (optopt == 'p') || (optopt == 'q'))
				syslog (LOG_ERR, "Option -%c requires an argument.", optopt);
			else if (isprint (optopt))
				syslog (LOG_ERR, "Invalid option '-%c'.", optopt);
			else
				syslog (LOG_ERR, "Unknown option character '\\x%x'.", optopt);
			return 1;
		default:
			abort ();
		}
	}

	/*This program does not admit options*/
	if (optind < argc) {
		syslog (LOG_ERR,"This program does not admit options just argument elements with their values.");
		return 1;
	}
	

    /*
     * From man sigaction(2):
     * A child created via fork(2) inherits a copy of its parent's signal dispositions.
     * During an execve(2), the dispositions of handled signals are reset to the default; the
     * dispositions of ignored signals are left unchanged.
     * I want to ignore SIGCHLD without causing any issue to child processes.
     */
    memset (&sa, 0, sizeof(sa));
    /*SIG_DFL: by default SIGCHLD is ignored.*/
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        syslog (LOG_ERR, "SIGCHLD signal handler failed: %m");
        return 1;
    }


    /*INIT process sending SIGINT? Should I catch that signal?*/
    daemonPID = getpid();
    memset (&sa, 0, sizeof(sa));
    sa.sa_handler = &sigint_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        syslog (LOG_ERR, "SIGINT signal handler failed: %m");
        return 1;
    }

	
	if (main_daemon (avalue, pvalue, qvalue) < 0)
		return 1;
	
	return 0;
}



int main_daemon (char *address, int port, int queue)
{
	struct protoent *protocol;          /*Network protocol*/
	struct sockaddr_in addr_server;	    /*struct with the server socket address*/
	struct sockaddr_in  addr_client;    /*struct with the client socket address*/
	int sockclient = -1;                /*File descriptor for the accepted socket*/
	pthread_t idThread;                 /*Thread identifier number*/
	socklen_t clilen;
	int optval;
	int returnValue = 0;                /*The return value from this function, OK by default*/
	
	
	/*Retrieve protocol number from /etc/protocols file */
	protocol=getprotobyname("tcp");
	if (protocol == NULL) {
		syslog(LOG_ERR, "cannot map \"tcp\" to protocol number: %m");
		goto err;
	}
	
	bzero((char*) &addr_server, sizeof(addr_server));
	addr_server.sin_family = AF_INET;
	if (inet_pton(AF_INET, address, &addr_server.sin_addr.s_addr) <= 0) {
		syslog (LOG_ERR, "error inet_pton: %m");
		goto err;
	}
	
	addr_server.sin_port = htons(port);
	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, protocol->p_proto)) < 0) {
		syslog (LOG_ERR, "socket creation failed: %m");
		goto err; 
	}


	/*We want to avoid issues while trying to bind a socket in TIME_WAIT state*/
	optval = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		syslog (LOG_ERR, "setsockopt failed: %m");
		goto err;
	}
	
	if (bind(sockfd, (struct sockaddr *) &addr_server, sizeof(addr_server)) < 0) {
		syslog (LOG_ERR, "socket bind failed: %m");
		goto err;
	}
	
	if (listen (sockfd, queue) < 0 ) {
		syslog (LOG_ERR, "socket listen failed: %m");
		goto err;
	}	
	
	for(;;) {
		clilen =  sizeof(addr_client);
		if ((sockclient = TEMP_FAILURE_RETRY(accept (sockfd, (struct sockaddr *) &addr_client, &clilen))) < 0) {
			syslog (LOG_ERR, "socket accept failed: %m");
			goto err;
		}

		if (pthread_create (&idThread, NULL, serverThread, (void *)sockclient) != 0 ) {
			syslog (LOG_ERR, "thread creation failed: %m");
		}
	}

end:
    closeSafely (sockfd);
    return returnValue;
err:
	/*When there is an error.*/
	returnValue = -1;	
	goto end;
}



int daemonize(const char *pname, int facility, int option)
{
	int fd = -1;    /*Temporaly store for the /dev/tty and /dev/null file descriptors*/
	
	if ((fd = TEMP_FAILURE_RETRY(open( "/dev/tty", O_RDWR, 0))) == -1) {
        /*We already have no tty control*/
        closeSafely(fd);
        return 0;
	}
	
	/*Sending messages to log*/
	openlog(pname, option, facility);

	/*To get a controlling tty*/
	if (ioctl(fd, TIOCNOTTY, (caddr_t)0) <0 ) {
		syslog (LOG_ERR, "Getting tty failed: %m");
		return -1;
	}

	if (closeSafely(fd) < 0) {
		syslog (LOG_ERR, "Closing tty failed: %m");
		return -1;
	}
	
	if ((fd = TEMP_FAILURE_RETRY(open( "/dev/null", O_RDWR, 0))) == -1) {
		closeSafely(fd);
		return -1;
	}

	if (TEMP_FAILURE_RETRY(dup2(fd,0)) < 0 || 
        TEMP_FAILURE_RETRY(dup2(fd,1)) < 0 ||
        TEMP_FAILURE_RETRY(dup2(fd,2)) < 0) {
	    closeSafely(fd);
        return -1;
    }

    closeSafely(fd);	

    return 0;
}



void *serverThread (void * arg)
{
	int socket = -1;                /*Open socket by the Java client*/
	long timeout, utimeout;         /*Timeout for reading data from client: secs and usecs*/
                                    /*respectively*/
    uint32_t commandLength = 0;     /*Store the command length*/
    char *command = NULL;           /*The command sent by the client, to be executed by this process*/
	char buffer[sizeof(uint32_t)];  /*This buffer is intended to store the data received from the client*/
	
	socket = (int) arg;
	
	pthread_detach(pthread_self());


    if (required_sock_options (socket) < 0)
        goto err;
	
	
            /****************************************************************************************/
            /*   Just over 1 TCP connection                                                         */
            /*   COMMAND_LENGTH: Java integer 4 bytes, BIG-ENDIAN (the same as network order)       */
            /*   COMMAND: locale character set encoding                                             */
            /*   RESULTS: locale character set encoding                                             */
            /*                                                                                      */
            /*          JAVA CLIENT: ------------ COMMAND_LENGTH -------> :SERVER                   */
            /*          JAVA CLIENT: -------------- COMMAND ------------> :SERVER                   */
            /*          JAVA CLIENT: <-------------- RESULTS ------------ :SERVER                   */
            /*          JAVA CLIENT: <---------- CLOSE CONNECTION ------- :SERVER                   */
            /*                                                                                      */
            /****************************************************************************************/

    /*Wait max 2 seconds for data coming from client, otherwise exits with error.*/
    timeout = 2;
    utimeout = 0;


    /*1. COMMAND LENGTH*/
    /*First of all we receive the command size as a Java integer (4 bytes primitive type)*/
    bzero(buffer, sizeof(buffer));

    if (receive_from_socket (socket, buffer, sizeof(uint32_t), timeout, utimeout) < 0)
        goto err;

    /*Retrieve integer (4 bytes) from buffer*/
    memcpy (&commandLength, buffer, sizeof(uint32_t));
    /*Java sends the primitive integer using big-endian order (it is the same as network order)*/
    commandLength = be32toh (commandLength);


    /*2. COMMAND*/
    /*Reserving commandLength + 1 because of the string end character*/
    if ((command = (char *) malloc(commandLength + 1)) == NULL) {
        syslog (LOG_ERR, "command malloc failed: %m");
        goto err;
    }

    bzero(command, ((commandLength) + 1));

    /*Wait max 2 seconds for data coming from client, otherwise exits with error.*/
    if (receive_from_socket (socket, command, commandLength, timeout, utimeout) < 0)
        goto err;


    /*3. RESULTS*/	
    pre_fork_system(socket, command);


    /*4. CLOSE CONNECTION AND FINISH*/

err:
    free(command);
    closeSafely(socket);

    pthread_exit(0);
}



int required_sock_options (int socket)
{
    int optval, flags;

    /*We want non blocking sockets.*/
    /*See the discussion of spurious readiness notifications under the BUGS section of select(2) */
    if ((flags = TEMP_FAILURE_RETRY(fcntl(socket,F_GETFL,0))) < 0) {
        syslog (LOG_ERR, "read socket status flags failed: %m");
        return -1;
    }

    if (TEMP_FAILURE_RETRY(fcntl(socket, F_SETFL, O_NONBLOCK|flags)) < 0){
        syslog (LOG_ERR, "set socket status flags failed: %m");
        return -1;
    }

    /*Portable programs should not rely on inheritance or noninheritance of file status flags and */
    /*always explicitly set all required flags*/
    optval = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        syslog (LOG_ERR, "setsockopt SO_REUSEADDR failed: %m");
        return -1;
    }

    /*Enable keepalive for this socket*/
    optval = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        syslog (LOG_ERR, "setsockopt SO_KEEPALIVE failed: %m");
        return -1;
    }

    /*
     *TODO: keepalive is not enough to find out if the connection is broken
     *      apparently it just works while the handshake phase. See:
     *      http://stackoverflow.com/questions/4345415/socket-detect-connection-is-lost
     *      I have to implement an echo/ping messages protocol (application layer)
     */

    return 0;
}



int readable_timeout (int fd, long timeout, long utimeout)
{
    struct timeval ptime;   /*Timeout, secs and usecs*/
    fd_set fd_read;         /*Values for select function.*/
    int ret;                /*Store return value from select.*/

    ptime.tv_sec = timeout;
    ptime.tv_usec = utimeout;
    FD_ZERO(&fd_read);
    FD_SET(fd, &fd_read);
  
    ret = TEMP_FAILURE_RETRY(select(fd+1, &fd_read, NULL, NULL, &ptime)); 
    
    if (ret == 0) {
        syslog(LOG_INFO, "receiving timeout error");
        return -1;
    } else if (ret == -1) {
        syslog(LOG_ERR, "receiving error: %m");
        return -1;
    }

    return ret;
}



int readable (int socket, char *data, int len, int flags) 
{
    int received;   /*Stores received data from socket*/

    received = TEMP_FAILURE_RETRY(recv(socket, data, len, flags));

    if (received < 0) {
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            syslog (LOG_ERR, "read TCP socket failed: %m");
            return -1;
        } else {
            /*see spurious readiness man select(2) BUGS section*/
            received = 0;
            syslog (LOG_INFO, "read TCP socket spurious readiness");
        }
    } else if (received == 0) {
        /*if received is 0, client closed connection but we wanted to receive more data, */
        /*this is an error */
        syslog (LOG_ERR, "expected more data, closed connection from client");
        return -1;
    }

    return received;
}



int receive_from_socket (int socket, char *data, int len, long timeout, long utimeout)
{
    int nData, iPos;	/*Control variables.*/

    nData = iPos = 0;
    do {
        if (readable_timeout(socket, timeout, utimeout) < 0)
            return -1;
        
        if ((nData = readable (socket, &data[iPos], len, 0)) < 0)
            return -1;

        len -= nData;
        iPos += nData;
    } while (len > 0);

    return 0;
}



int pre_fork_system(int socket, char *command)
{
    /*Required variables in order to share memory between processes*/
    key_t keyvalue;
    int idreturnstatus = -1;
    /*Store the return status from the process launched using system or execve*/
    /*Using shared memory between the child and parent process*/
    int *returnstatus = NULL;
	
    int returnValue = -1;       /*Return value from this function can be caught by upper*/
                                /*layers, NOK by default*/

    // TODO: stop using shared memory. There must be another way to do this. 
    // See OpenJDK Fork Process, it uses a file descriptor.
		
    /*
     * Allocate shared memory for the return status code from the process which is 
     * going to be launched by the system function. We want to share the returnstatus 
     * variable between this process and the child that is going to be created in the 
     * fork_system method.
     * The goal is to store in this variable the return status code received from the 
     * process launched with the system method by the child process, then the parent 
     * process can retrieve that return status code and send it by TCP to the Java client.
     * There are not concurrency issues because the parent process will just try to read 
     * this variable when the child process is dead, taking in that moment its last value 
     * and sending it to the Java client.
     */

    /*the /bin/ls must exist otherwise this does not work... */
    keyvalue=ftok("/bin/ls", SHAREMEMKEY); 
    if (keyvalue == -1) {
        syslog (LOG_ERR, "ftok failed: %m");
        goto end;
    }

    /*Attach shared memory*/
    if ((idreturnstatus=shmget(keyvalue,sizeof(int), 0660 | IPC_CREAT)) < 0) {
        syslog (LOG_ERR, "shmget failed: %m");
        goto end_release_mem;
    }

    returnstatus = (int *)shmat(idreturnstatus, (void *)0, 0);
    if ((*returnstatus)== -1) {
        syslog (LOG_ERR, "shmat failed: %m");
        goto end_release_mem;
    } 

    /*After allocating and attaching shared memory we reach this code if everything went OK.*/

    returnValue = fork_system(socket, command, returnstatus);


end_release_mem:
    if (returnstatus != NULL) {
        /*detach memory*/
        if (shmdt ((int *)returnstatus) < 0)
            syslog (LOG_ERR, "returnstatus shared variable shmdt failed: %m");
    }

    /*Mark the segment to be destroyed.*/
    if (shmctl (idreturnstatus, IPC_RMID, (struct shmid_ds *)NULL) < 0 )
        syslog (LOG_ERR, "returnstatus shared variable shmctl failed: %m");
end:
    return returnValue;
}



int fork_system(int socket, char *command, int *returnstatus) 
{
    int pid;                /*Child or parent PID.*/
    int out[2], err[2];     /*Store pipes file descriptors. Write ends attached to the stdout*/
                            /*and stderr streams.*/
    u_char buf[2000];       /*Read data buffer. allignment(int) * 500.*/
    struct pollfd polls[2]; /*pipes attached to the stdout and stderr streams.*/
    int n;                  /*characters number from stdout and stderr*/
    struct tcpforkhdr *header = (struct tcpforkhdr *)buf;
    int childreturnstatus;
    int returnValue = 0;    /*return value from this function can be caught by upper layers,*/
                            /*OK by default*/


    /*Value by default*/
    (*returnstatus) = 0;

	
    out[0] = out[1] = err[0] = err[1]  = -1;


    /*Creating pipes, they will be attached to the stderr and stdout streams*/	
    if (pipe(out) < 0 || pipe(err) < 0) {
        syslog (LOG_ERR, "pipe failed: %m");
        goto err;
    }

    if ((pid=fork()) == -1) {
        syslog (LOG_ERR, "fork failed: %m");
        goto err;
    }

    if (pid == 0) {
        /*Child process*/
        /*It has to launch another one using system or execve*/
        if ((TEMP_FAILURE_RETRY(dup2(out[1], 1)) < 0) || (TEMP_FAILURE_RETRY(dup2(err[1], 2)) < 0)) {	
            syslog (LOG_ERR, "child dup2 failed: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/	
            exit(-1);
        }


        /*TODO: I should use execve with setlocale and the environment instead of system.*/
        /*During execution of the command, SIGCHLD will be blocked, and SIGINT and SIGQUIT*/
        /* will be ignored. From man system(3)*/
        *returnstatus=system(command);
        if (WIFEXITED(returnstatus) == 1)
            (*returnstatus) = WEXITSTATUS(*returnstatus);
        else
            (*returnstatus) = -1;
        /*Going to zombie state, hopefully waitpid will catch it*/
        exit(0);
    }
    else {
        /*Parent process*/
        /*It sends data to the Java client using a TCP connection.*/
        polls[0].fd=out[0];
        polls[1].fd=err[0];
        polls[0].events = polls[1].events = POLLIN;

        for (;;) {
            if(poll(polls, 2, 100)) {
                if(polls[0].revents && POLLIN) {
                    bzero(buf,2000);
                    n=TEMP_FAILURE_RETRY(read(out[0], &buf[sizeof(struct tcpforkhdr)], 2000-sizeof(struct tcpforkhdr)));
                    //To network order, indeed it is the order used by Java (BIG ENDIAN). Anyway I am 
                    //swapping the bytes because it is required if you want to write portable code and 
                    //ENDIANNESS indepedent.
                    header->type = htonl(1);
                    header->length = htonl(n);
                    //PACKING THE STRUCT OR SERIALIZING? 
                    //serializing-> sends the struct one data member at time (using for example writev?) I send
                    //one field of my struct at time.
                    //packing-> Compilers often do some amount of padding and alignment, so unless you define 
                    //alignment explicitly (maybe using a #pragma pack()), that size may be different. 

                    //I think I do not need any of both, because my struct has no padding and it has a defined size
                    //are you sure ur struct is never going to have padding? if it is unaligned? could my struct be unaligned?
                    //does the compiler guarantee alignment?

                    //I do not care about the ENDIANNESS and character set in the payload, I send bytes
                    //and the client application must know what it has to do with them. 
                    //TODO: my own protocol to make the client independent of the ENDIANNESS and character set used
                    //by the machine running this server. See comments in the TCPForkDaemon.java code about this.
                    if (TEMP_FAILURE_RETRY(send(socket, buf, n+sizeof(struct tcpforkhdr), 0)) < 0)
                        syslog (LOG_INFO, "error while sending stdout: %m");
                }
 
                if(polls[1].revents && POLLIN) {
                    bzero(buf,2000);
                    n=TEMP_FAILURE_RETRY(read(err[0], &buf[sizeof(struct tcpforkhdr)], 2000-sizeof(struct tcpforkhdr)));
                    header->type = htonl(2);
                    header->length = htonl(n);
                    if (TEMP_FAILURE_RETRY(send(socket, buf, n+sizeof(struct tcpforkhdr), 0)) < 0)
                        syslog (LOG_INFO, "error while sending stdout: %m");
                }

                if(!(polls[0].revents && POLLIN) && !(polls[1].revents && POLLIN)) {
                    syslog (LOG_ERR, "parent error polling pipes: %m");

                    if (kill(pid, SIGKILL /*should I use SIGTERM and my own handler?*/) < 0) {
                        /*We are not sure if the child process will die. In this case, */
                        /*probably the child process is going to be an orphan and its */
                        /*system process (if there is one) as well*/
                        syslog (LOG_ERR, "error while killing child process: %m");
                        goto err;
                    }

                    if (TEMP_FAILURE_RETRY(waitpid(pid, NULL, 0)) < 0) {
                        /*We are not sure if the child process is dead. In this case, */
                        /*probably the child process is going to be an orphan and its */
                        /*system process (if there is one) as well*/
                        syslog (LOG_ERR, "error while waiting for killed child process: %m");
                    }

                    /*In the Java code, the client will get an error as the return status from the exec method.*/
                    goto err;
                }
            }   
            else {
                /*When timeout*/
                if(TEMP_FAILURE_RETRY(waitpid(pid, &childreturnstatus, WNOHANG))) {
                    //TODO: treating errors in waitpid function
                    /*Child is dead, we can finish the connection*/
                    /*First of all, we check the exit status of our child process*/
                    /*In case of error send an error status to the remote calling process*/
                    if (WIFEXITED(childreturnstatus) != 1)
                        (*returnstatus) = -1;
                    break;
                }
                /*The child process is not dead, keep polling more data from stdout or stderr streams*/
            }
        }
    }
    /*Stuff just done by the parent process. The child process ends with exit*/
    /*Reaching this code when child ends*/
    bzero(buf,2000);
    header->type = htonl(3);
    header->length = htonl((*returnstatus));
    if (TEMP_FAILURE_RETRY(send(socket, buf, sizeof(struct tcpforkhdr), 0)) < 0)
        syslog (LOG_INFO, "error while sending return status: %m");

end:
    closeSafely (out[0]);
    closeSafely (out[1]);
    closeSafely (err[0]);
    closeSafely (err[1]);
    return returnValue;
err:
    returnValue = -1;
	goto end;
}


void sigint_handler(int sig)
{
    if (daemonPID != getpid()) {
        //Do nothing
        return;
    }


    closeSafely (sockfd);
    /*TODO: kill child processes, finish threads and release allocate memory*/
    exit (0);
}
